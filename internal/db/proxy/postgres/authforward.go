//go:build linux

package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5/pgproto3"
)

// errScramPlusFailClosed is returned by forwardAuth when the upstream advertises
// SCRAM-SHA-256-PLUS. The caller treats this as a fatal handshake outcome and
// emits a db_handshake_fail event.
var errScramPlusFailClosed = errors.New("postgres.forwardAuth: SCRAM-SHA-256-PLUS detected; fail-closed")

// forwardAuth pumps frames between the client *Backend and the upstream
// *Frontend until the upstream sends ReadyForQuery (or the loop dies).
//
// The upstream→client direction inspects each frame:
//   - *AuthenticationSASL: scan AuthMechanisms for SCRAM-SHA-256-PLUS. If
//     present, write ErrorResponse(28000, SCRAM_PLUS_FAIL_CLOSED) to client,
//     close upstream, and return errScramPlusFailClosed. The caller emits
//     db_handshake_fail.
//   - *BackendKeyData: record PID/SecretKey into connState.upstreamBKD for
//     Plan 06 mapping; forward verbatim to client.
//   - *ReadyForQuery: forward to client, return nil (end-of-auth-loop).
//   - everything else: forward to client.
//
// The client→upstream direction forwards any frame verbatim.
//
// Both directions run as goroutines coordinated via a shared error channel.
// The first error (or RFQ) wins; the loser is cancelled by closing one side.
func forwardAuth(ctx context.Context, pc *proxyConn) error {
	if pc.state.upstreamFE == nil {
		return fmt.Errorf("postgres.forwardAuth: upstreamFE is nil")
	}

	errCh := make(chan error, 2)

	// Upstream → client.
	go func() {
		errCh <- pc.forwardUpstreamToClientUntilRFQ()
	}()

	// Client → upstream.
	go func() {
		errCh <- pc.forwardClientToUpstream()
	}()

	// Wait for the first goroutine to finish. The upstream-side goroutine
	// returning nil means we saw RFQ — clean end. Anything else is fatal.
	select {
	case err := <-errCh:
		// Tear down so the other goroutine can exit.
		pc.closeUpstream()
		_ = pc.conn.Close()
		// Drain the second goroutine's result so it does not leak.
		<-errCh
		if errors.Is(err, errScramPlusFailClosed) {
			return err
		}
		if err == nil {
			return nil
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return nil
		}
		return err
	case <-ctx.Done():
		pc.closeUpstream()
		_ = pc.conn.Close()
		<-errCh
		<-errCh
		return ctx.Err()
	}
}

// forwardUpstreamToClientUntilRFQ runs the upstream→client loop. Returns nil
// when it sees ReadyForQuery; returns errScramPlusFailClosed on SCRAM-PLUS;
// returns the underlying error on any I/O failure.
func (pc *proxyConn) forwardUpstreamToClientUntilRFQ() error {
	for {
		msg, err := pc.state.upstreamFE.Receive()
		if err != nil {
			return fmt.Errorf("upstream recv: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationSASL:
			for _, mech := range m.AuthMechanisms {
				if mech == "SCRAM-SHA-256-PLUS" {
					// Fail-closed before forwarding the frame.
					pc.backend.Send(&pgproto3.ErrorResponse{
						Severity:            "FATAL",
						SeverityUnlocalized: "FATAL",
						Code:                scramPlusErrorCode,
						Message:             scramPlusMessage,
					})
					_ = pc.backend.Flush()
					return errScramPlusFailClosed
				}
			}
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after SASL: %w", err)
			}
		case *pgproto3.BackendKeyData:
			pc.state.upstreamBKD.PID = m.ProcessID
			// Copy SecretKey to decouple from pgproto3's internal buffer
			// (Decode allocates fresh, but be defensive: subsequent frames
			// could reuse the slice in some impls).
			pc.state.upstreamBKD.SecretKey = append(pc.state.upstreamBKD.SecretKey[:0], m.SecretKey...)
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after BKD: %w", err)
			}
		case *pgproto3.ReadyForQuery:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after RFQ: %w", err)
			}
			return nil
		default:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after %T: %w", m, err)
			}
		}
	}
}

// forwardClientToUpstream runs the client→upstream loop. Forwards every
// frame verbatim. Returns when either side closes.
func (pc *proxyConn) forwardClientToUpstream() error {
	for {
		msg, err := pc.backend.Receive()
		if err != nil {
			return fmt.Errorf("client recv: %w", err)
		}
		pc.state.upstreamFE.Send(msg)
		if err := pc.state.upstreamFE.Flush(); err != nil {
			return fmt.Errorf("upstream flush: %w", err)
		}
	}
}
