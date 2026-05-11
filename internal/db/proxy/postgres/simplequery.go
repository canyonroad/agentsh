//go:build linux

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"
)

var (
	errInTxTerminate      = errors.New("postgres.simpleQueryLoop: in-tx deny terminated connection")
	errFrameTooLargeClose = errors.New("postgres.simpleQueryLoop: frame budget exceeded; conn closed")
	errUnsupportedFrame   = errors.New("postgres.simpleQueryLoop: unsupported frame type; conn closed")
)

// simpleQueryLoop is the post-handshake driver. It reads client frames one at
// a time, dispatches to handleQuery for 'Q', forwards 'X' (Terminate), and
// rejects any other frame with a synthetic ErrorResponse.
func (pc *proxyConn) simpleQueryLoop(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		msg, err := pc.backend.Receive()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			if err := pc.handleQuery(ctx, m); err != nil {
				return err
			}
		case *pgproto3.Terminate:
			if pc.state.upstreamFE != nil {
				pc.state.upstreamFE.Send(m)
				_ = pc.state.upstreamFE.Flush()
			}
			return nil
		default:
			return pc.handleUnsupportedFrame(ctx, m)
		}
	}
}

// handleUnsupportedFrame synthesizes ErrorResponse for any non-Q/non-X
// post-handshake frame and closes the connection. Distinguishes FunctionCall
// (PG 42501) from generic extended-query frames (0A000).
func (pc *proxyConn) handleUnsupportedFrame(ctx context.Context, msg pgproto3.FrontendMessage) error {
	frameType := fmt.Sprintf("%T", msg)
	if _, isFunc := msg.(*pgproto3.FunctionCall); isFunc {
		pc.emitUnsupportedFrame(ctx, "FUNCTION_CALL_PROTOCOL_DENIED", "FunctionCall")
		_ = pc.synthesizeError(sqlstateInsufficientPrivilege, "FunctionCall sub-protocol denied by AgentSH policy")
		return errUnsupportedFrame
	}
	pc.emitUnsupportedFrame(ctx, "EXTENDED_QUERY_NOT_SUPPORTED", frameType)
	_ = pc.synthesizeError(sqlstateFeatureNotSupported, "Extended Query / COPY / FunctionCall not supported in AgentSH proxy phase 1")
	return errUnsupportedFrame
}

// handleQuery is filled in by Tasks 8 (frame budget), 12 (allow) and 13 (deny).
// Task 8 enforces the frame budget cap; subsequent tasks fill in allow/deny paths.
func (pc *proxyConn) handleQuery(ctx context.Context, q *pgproto3.Query) error {
	if len(q.String) > pc.srv.cfg.MaxQueryBytes {
		pc.emitFrameTooLarge(ctx, len(q.String))
		_ = pc.synthErrorAndRFQ(sqlstateProgramLimitExceeded,
			fmt.Sprintf("statement too large for AgentSH proxy: %d bytes > %d cap",
				len(q.String), pc.srv.cfg.MaxQueryBytes))
		return errFrameTooLargeClose
	}
	// Allow/deny paths filled in by later tasks.
	return pc.synthesizeError("58030", "handleQuery not yet implemented in scaffold")
}
