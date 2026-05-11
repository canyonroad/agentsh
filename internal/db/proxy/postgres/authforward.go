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
// Auth in Postgres is strictly challenge-response: the upstream emits one
// Authentication* frame (or directly AuthenticationOk → BKD → RFQ for
// trust/peer modes), and the client replies with a PasswordMessage / SASL
// Initial Response / SASL Response. We drive this as a single-goroutine
// state machine so that on success we return WITHOUT tearing down either
// conn — the caller (dialUpstreamAndForward) then hands off to
// simpleQueryLoop, which reuses both backend and upstreamFE.
//
// The upstream→client direction inspects each frame:
//   - *AuthenticationSASL: scan AuthMechanisms for SCRAM-SHA-256-PLUS. If
//     present, write ErrorResponse(28000, SCRAM_PLUS_FAIL_CLOSED) to client,
//     close upstream, and return errScramPlusFailClosed. The caller emits
//     db_handshake_fail.
//   - *Authentication{CleartextPassword,MD5Password,GSS,SSPI,SASL,
//     SASLContinue}: forward to client, then block-read one client frame and
//     forward it to upstream. AuthenticationOk/SASLFinal are non-challenge
//     and just pass through.
//   - *BackendKeyData: record PID/SecretKey into connState.upstreamBKD for
//     Plan 06 mapping; forward verbatim to client.
//   - *ReadyForQuery: forward to client, return nil (end-of-auth-loop).
//   - everything else: forward to client.
func forwardAuth(ctx context.Context, pc *proxyConn) error {
	if pc.state.upstreamFE == nil {
		return fmt.Errorf("postgres.forwardAuth: upstreamFE is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		msg, err := pc.state.upstreamFE.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
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
			if err := pc.relayClientFrameToUpstream(); err != nil {
				return err
			}
		case *pgproto3.AuthenticationCleartextPassword,
			*pgproto3.AuthenticationMD5Password,
			*pgproto3.AuthenticationGSS,
			*pgproto3.AuthenticationGSSContinue,
			*pgproto3.AuthenticationSASLContinue:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after %T: %w", m, err)
			}
			if err := pc.relayClientFrameToUpstream(); err != nil {
				return err
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
			pc.state.lastUpstreamRFQ = m.TxStatus
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

// relayClientFrameToUpstream reads one frame from the client and forwards
// it verbatim to upstream. Used after the proxy forwards an authentication
// challenge that the client must answer (PasswordMessage / SASL Response).
func (pc *proxyConn) relayClientFrameToUpstream() error {
	msg, err := pc.backend.Receive()
	if err != nil {
		return fmt.Errorf("client recv: %w", err)
	}
	pc.state.upstreamFE.Send(msg)
	if err := pc.state.upstreamFE.Flush(); err != nil {
		return fmt.Errorf("upstream flush: %w", err)
	}
	return nil
}
