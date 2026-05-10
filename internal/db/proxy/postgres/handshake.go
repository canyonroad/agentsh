//go:build linux

package postgres

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
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

// handleStartupMessage parses the parameters and either denies replication,
// proceeds to connection-rule eval (Task 7), or surfaces the not-yet-wired
// error.
func (pc *proxyConn) handleStartupMessage(ctx context.Context, m *pgproto3.StartupMessage) error {
	pc.state.dbUser = m.Parameters["user"]
	pc.state.database = m.Parameters["database"]
	pc.state.appName = m.Parameters["application_name"]
	if v, ok := m.Parameters["replication"]; ok && v != "" && v != "false" && v != "off" && v != "0" {
		pc.state.replication = true
	}
	if pc.state.replication {
		return pc.synthesizeError(replicationDenyErrorCode, replicationDenyMessage)
	}
	// Task 7 plugs in: connect-rule eval ahead of the not-yet-wired error.
	return pc.synthesizeError(upstreamNotYetWiredErrorCode, upstreamNotYetWiredMessage)
}

// synthesizeError writes one ErrorResponse with the given SQLSTATE+message
// and a final close. Used by deny paths and the not-yet-wired stub.
func (pc *proxyConn) synthesizeError(sqlstate, message string) error {
	resp := &pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     sqlstate,
		Message:  message,
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
	replicationDenyErrorCode     = "28000"
	replicationDenyMessage       = "AgentSH DB proxy: replication mode denied by default; declare an opt-in connection rule (Plan 04b₂)"
	upstreamNotYetWiredErrorCode = "0A000"
	upstreamNotYetWiredMessage   = "AgentSH DB proxy: upstream wiring not yet shipped (Plan 04b is inbound-only; Plan 04b₂ adds upstream)"
	connectionDenyErrorCode      = "28000"
)
