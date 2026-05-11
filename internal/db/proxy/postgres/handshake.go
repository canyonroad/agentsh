//go:build linux

package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
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
			// Plan 04b: silently close. Plan 04b₂ evaluates a cancel rule
			// and may forward to upstream un-mapped.
			pc.logger.Debug("CancelRequest received; close silently (Plan 04b)",
				"service", pc.svc.Name, "syn_pid", m.ProcessID, "syn_secret", m.SecretKey)
			return nil
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
	return contains(s, "tls:") || contains(s, "x509:") || contains(s, "TLS handshake")
}

// contains is io-free; the events package uses a similar helper.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
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
	// 0A000 (feature_not_supported) — replication is denied because Plan 04b
	// does not yet route the replication protocol; not an authentication
	// failure (28000), which would mislead operators debugging policy.
	replicationDenyErrorCode     = "0A000"
	replicationDenyMessage       = "AgentSH DB proxy: replication mode is not yet supported; opt-in path lands in Plan 04b₂"
	upstreamNotYetWiredErrorCode = "0A000"
	upstreamNotYetWiredMessage   = "AgentSH DB proxy: upstream wiring not yet shipped (Plan 04b is inbound-only; Plan 04b₂ adds upstream)"
	connectionDenyErrorCode      = "28000"

	// SCRAM-SHA-256-PLUS fail-closed under terminate_* modes. Spec §13.1.
	scramPlusErrorCode = "28000"
	scramPlusMessage   = "AgentSH DB proxy cannot terminate channel-bound SCRAM (SCRAM-SHA-256-PLUS). Disable channel binding upstream or use TLS passthrough; see docs/agentsh-db-access-spec.md §13."
	scramPlusEventCode = "SCRAM_PLUS_FAIL_CLOSED"

	// Upstream dial / TLS failures. SQLSTATE 08006 (connection_failure).
	upstreamDialFailErrorCode = "08006"
	upstreamDialFailEventCode = "UPSTREAM_DIAL_FAIL"
	upstreamTLSFailErrorCode  = "08006"
	upstreamTLSFailEventCode  = "UPSTREAM_TLS_FAIL"
)
