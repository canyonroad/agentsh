//go:build linux

package postgres

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/policy"
)

// Magic numbers from the Postgres frontend/backend protocol; same values
// pgproto3 uses internally but exposed here for readability.
const (
	sslRequestMagic    uint32 = 80877103
	gssEncRequestMagic uint32 = 80877104
	cancelRequestMagic uint32 = 80877102
	protocol30Magic    uint32 = 196608
)

// dispatchStartup reads startup-class messages and routes to the appropriate
// handler. Loops because SSLRequest is followed by a second startup message.
func (pc *proxyConn) dispatchStartup(ctx context.Context) error {
	for {
		msg, err := pc.backend.ReceiveStartupMessage()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest:
			if err := pc.handleSSLRequest(ctx); err != nil {
				if errors.Is(err, errPassthroughDone) {
					return nil // passthrough byte-pump finished cleanly
				}
				return err
			}
			continue
		case *pgproto3.GSSEncRequest:
			// Default deny per spec §11.1; respond 'N' and loop for the
			// follow-up StartupMessage. Plan 04b₂ may add the opt-in path.
			if _, err := pc.conn.Write([]byte{'N'}); err != nil {
				return fmt.Errorf("write GSS 'N': %w", err)
			}
			continue
		case *pgproto3.CancelRequest:
			return pc.handleCancelRequest(ctx, m)
		case *pgproto3.StartupMessage:
			return pc.handleStartupMessage(ctx, m)
		default:
			return fmt.Errorf("unexpected startup-class message: %T", msg)
		}
	}
}

// handleStartupMessage parses the parameters, evaluates the appropriate
// connection rule (match_kind=replication when the replication parameter is
// truthy; match_kind=connect otherwise), and either synthesizes a deny or
// dials upstream + forwards.
//
// Plan 04b₂: terminate_* allow path dials upstream → Send(StartupMessage)
// → forwardAuth → close at first upstream RFQ. Replication-allowed branches
// to forwardReplicationStartupAndPump (Task 8). Passthrough is handled by
// handleSSLRequest in tls.go (Task 7).
func (pc *proxyConn) handleStartupMessage(ctx context.Context, m *pgproto3.StartupMessage) error {
	pc.state.dbUser = m.Parameters["user"]
	pc.state.database = m.Parameters["database"]
	pc.state.appName = m.Parameters["application_name"]
	if v, ok := m.Parameters["replication"]; ok && v != "" && v != "false" && v != "off" && v != "0" {
		pc.state.replication = true
	}

	var d policy.Decision
	if pc.state.replication {
		d = pc.evaluateReplication(ctx)
	} else {
		d = pc.evaluateConnect(ctx)
	}
	if d.Verb == policy.VerbDeny {
		msg := d.Reason
		if msg == "" {
			if pc.state.replication {
				msg = "AgentSH DB proxy: replication denied by policy"
			} else {
				msg = "AgentSH DB proxy: connection denied by policy"
			}
		}
		return pc.synthesizeError(connectionDenyErrorCode, msg)
	}

	if pc.state.replication {
		return pc.forwardReplicationStartupAndPump(ctx, m) // Task 8
	}
	return pc.dialUpstreamAndForward(ctx, m)
}

// dialUpstreamAndForward dials upstream, forwards the StartupMessage, runs
// forwardAuth until upstream RFQ, then returns nil (caller closes both
// conns). On dial / TLS failure synthesizes UPSTREAM_DIAL_FAIL or
// UPSTREAM_TLS_FAIL to the client. On SCRAM-PLUS detection emits a
// db_handshake_fail event and synthesizes the SCRAM_PLUS_FAIL_CLOSED error
// (the error itself is written by forwardAuth).
func (pc *proxyConn) dialUpstreamAndForward(ctx context.Context, m *pgproto3.StartupMessage) error {
	conn, fe, err := dialUpstream(ctx, pc.svc, pc.srv.cfg)
	if err != nil {
		code := upstreamDialFailEventCode
		errCode := upstreamDialFailErrorCode
		msg := fmt.Sprintf("AgentSH DB proxy: upstream unreachable: %v", err)
		if isTLSError(err) {
			code = upstreamTLSFailEventCode
			errCode = upstreamTLSFailErrorCode
			msg = fmt.Sprintf("AgentSH DB proxy: upstream TLS handshake failed: %v", err)
		}
		pc.emitHandshakeFail(ctx, code)
		return pc.synthesizeError(errCode, msg)
	}
	pc.state.upstream = conn
	pc.state.upstreamFE = fe

	pc.state.upstreamFE.Send(m)
	if err := pc.state.upstreamFE.Flush(); err != nil {
		pc.emitHandshakeFail(ctx, upstreamDialFailEventCode)
		return pc.synthesizeError(upstreamDialFailErrorCode, fmt.Sprintf("AgentSH DB proxy: upstream send StartupMessage: %v", err))
	}

	if err := forwardAuth(ctx, pc); err != nil {
		if errors.Is(err, errScramPlusFailClosed) {
			pc.emitHandshakeFail(ctx, scramPlusEventCode)
			return nil // ErrorResponse already written by forwardAuth
		}
		// Other forwardAuth errors are typically EOF / pipe-closed; return
		// nil so the deferred Close happens but no event is emitted.
		return nil
	}
	return nil
}

// isTLSError is a loose heuristic — "tls:" or "x509:" in the message.
// Used to distinguish TLS-handshake failures from raw TCP dial failures.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "tls:") || strings.Contains(s, "x509:") || strings.Contains(s, "TLS handshake")
}

// forwardReplicationStartupAndPump is the replication-allowed allow path.
// Dials upstream per service.TLSMode, forwards the StartupMessage, emits
// degraded_visibility_warning{reason: replication_passthrough}, then runs
// bytePump until either side closes.
func (pc *proxyConn) forwardReplicationStartupAndPump(ctx context.Context, m *pgproto3.StartupMessage) error {
	conn, fe, err := dialUpstream(ctx, pc.svc, pc.srv.cfg)
	if err != nil {
		code := upstreamDialFailEventCode
		errCode := upstreamDialFailErrorCode
		msg := fmt.Sprintf("AgentSH DB proxy: upstream unreachable: %v", err)
		if isTLSError(err) {
			code = upstreamTLSFailEventCode
			errCode = upstreamTLSFailErrorCode
			msg = fmt.Sprintf("AgentSH DB proxy: upstream TLS handshake failed: %v", err)
		}
		pc.emitHandshakeFail(ctx, code)
		return pc.synthesizeError(errCode, msg)
	}
	pc.state.upstream = conn
	pc.state.upstreamFE = fe
	pc.state.degradedReason = "replication_passthrough"

	pc.state.upstreamFE.Send(m)
	if err := pc.state.upstreamFE.Flush(); err != nil {
		pc.emitHandshakeFail(ctx, upstreamDialFailEventCode)
		return pc.synthesizeError(upstreamDialFailErrorCode, fmt.Sprintf("AgentSH DB proxy: upstream send StartupMessage (replication): %v", err))
	}

	pc.emitDegradedVisibility(ctx, "replication_passthrough", "replication_opt_in")

	if err := bytePump(ctx, pc.conn, pc.state.upstream); err != nil {
		// io.EOF / pipe-closed are normal; surface anything else.
		if !isNormalCloseErr(err) {
			return err
		}
	}
	return nil
}

// handleCancelRequest evaluates match_kind=cancel and either forwards the
// raw 16-byte packet via forwardCancel or silently closes. Plan 04b₂ runs
// un-mapped — Plan 06 will add the mapping table.
func (pc *proxyConn) handleCancelRequest(ctx context.Context, m *pgproto3.CancelRequest) error {
	d := pc.evaluateCancel(ctx)
	pc.logger.Debug("CancelRequest received",
		"service", pc.svc.Name,
		"syn_pid", m.ProcessID,
		"syn_secret", m.SecretKey,
		"verb", d.Verb,
		"rule", d.RuleName)
	if d.Verb == policy.VerbDeny {
		// Silent close per spec §15: cancel has no error response.
		return nil
	}
	// Rebuild the on-wire packet from the parsed CancelRequest because
	// pgproto3's ReceiveStartupMessage consumes the bytes.
	pkt := buildCancelPacketBytes(m.ProcessID, m.SecretKey)
	if err := forwardCancel(ctx, pc.svc, pkt); err != nil {
		pc.logger.Warn("forwardCancel failed", "service", pc.svc.Name, "err", err)
	}
	return nil
}

// buildCancelPacketBytes serializes a CancelRequest payload for un-mapped
// forwarding. Wire layout: 4-byte length + 4-byte magic + 4-byte process ID +
// N-byte secret key (typically 4 bytes for vanilla Postgres; longer for
// CockroachDB extended-secret format).
func buildCancelPacketBytes(pid uint32, secret []byte) []byte {
	total := 4 + 4 + 4 + len(secret) // length, magic, pid, secret
	pkt := make([]byte, total)
	binary.BigEndian.PutUint32(pkt[0:4], uint32(total))
	binary.BigEndian.PutUint32(pkt[4:8], cancelRequestMagic)
	binary.BigEndian.PutUint32(pkt[8:12], pid)
	copy(pkt[12:], secret)
	return pkt
}

// synthesizeError writes one ErrorResponse with the given SQLSTATE+message
// and a final close. Used by deny paths and the not-yet-wired stub.
func (pc *proxyConn) synthesizeError(sqlstate, message string) error {
	resp := &pgproto3.ErrorResponse{
		Severity:            "FATAL",
		SeverityUnlocalized: "FATAL", // wire field 'V' for PG 9.6+ machine-readable parsing
		Code:                sqlstate,
		Message:             message,
	}
	pc.backend.Send(resp)
	if err := pc.backend.Flush(); err != nil {
		return fmt.Errorf("flush ErrorResponse: %w", err)
	}
	// Drain client side cleanly; ignore errors, the conn is about to close.
	_ = pc.conn.SetReadDeadline(timeNow().Add(50 * time.Millisecond))
	_, _ = io.Copy(io.Discard, pc.conn)
	return nil
}

// Error codes Plan 04b synthesizes. Documented here so Plan 04b₂ can
// reuse where relevant.
const (
	// SCRAM-SHA-256-PLUS fail-closed under terminate_* modes. Spec §13.1.
	scramPlusErrorCode = "28000"
	scramPlusMessage   = "AgentSH DB proxy cannot terminate channel-bound SCRAM (SCRAM-SHA-256-PLUS). Disable channel binding upstream or use TLS passthrough; see docs/agentsh-db-access-spec.md §13."
	scramPlusEventCode = "SCRAM_PLUS_FAIL_CLOSED"

	// Connection denied by policy; also used for replication denied in Plan 04b₂.
	connectionDenyErrorCode = "28000"

	// Upstream dial / TLS failures. SQLSTATE 08006 (connection_failure).
	upstreamDialFailErrorCode = "08006"
	upstreamDialFailEventCode = "UPSTREAM_DIAL_FAIL"
	upstreamTLSFailErrorCode  = "08006"
	upstreamTLSFailEventCode  = "UPSTREAM_TLS_FAIL"
)
