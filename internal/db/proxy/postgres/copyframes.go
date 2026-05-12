//go:build linux

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

func (pc *proxyConn) runCopyLoop(ctx context.Context, direction effects.BulkOpKind) (upstreamResult, error) {
	switch direction {
	case effects.BulkOpIn:
		return pc.runCopyInLoop(ctx)
	case effects.BulkOpOut:
		return pc.runCopyOutLoop(ctx)
	default:
		return upstreamResult{}, fmt.Errorf("postgres.runCopyLoop: unknown COPY direction %v", direction)
	}
}

func (pc *proxyConn) runCopyInLoop(ctx context.Context) (upstreamResult, error) {
	var r upstreamResult
	if pc.state.smState != nil {
		pc.state.smState.Phase = statemachine.PhaseInCopyIn
	}
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		msg, err := pc.backend.Receive()
		if err != nil {
			return r, fmt.Errorf("copy-in client recv: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.CopyData:
			r.BytesIn += int64(len(m.Data))
			pc.state.upstreamFE.Send(m)
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return r, fmt.Errorf("copy-in upstream flush data: %w", err)
			}
		case *pgproto3.CopyDone:
			pc.state.upstreamFE.Send(m)
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return r, fmt.Errorf("copy-in upstream flush done: %w", err)
			}
			return pc.mergeCopyDrain(ctx, r, timeNow())
		case *pgproto3.CopyFail:
			pc.state.upstreamFE.Send(m)
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return r, fmt.Errorf("copy-in upstream flush fail: %w", err)
			}
			return pc.mergeCopyDrain(ctx, r, timeNow())
		case *pgproto3.Terminate:
			pc.state.upstreamFE.Send(&pgproto3.CopyFail{Message: "client terminated mid-copy"})
			_ = pc.state.upstreamFE.Flush()
			return r, errInTxTerminate
		default:
			return r, fmt.Errorf("copy-in unexpected client frame %T", m)
		}
	}
}

func (pc *proxyConn) runCopyOutLoop(ctx context.Context) (upstreamResult, error) {
	var r upstreamResult
	if pc.state.smState != nil {
		pc.state.smState.Phase = statemachine.PhaseInCopyOut
	}
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		msg, err := pc.state.upstreamFE.Receive()
		if err != nil {
			return r, fmt.Errorf("copy-out upstream recv: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.CopyData:
			r.BytesOut += int64(len(m.Data))
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("copy-out client flush data: %w", err)
			}
		case *pgproto3.CopyDone:
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("copy-out client flush done: %w", err)
			}
			return pc.mergeCopyDrain(ctx, r, timeNow())
		case *pgproto3.ErrorResponse:
			if r.ErrorCode == "" {
				r.ErrorCode = m.Code
			}
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("copy-out client flush error: %w", err)
			}
			return pc.mergeCopyDrain(ctx, r, timeNow())
		default:
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("copy-out client flush %T: %w", m, err)
			}
		}
	}
}

func (pc *proxyConn) mergeCopyDrain(ctx context.Context, r upstreamResult, sentAt time.Time) (upstreamResult, error) {
	drained, err := pc.forwardUpstreamUntilRFQ(ctx, sentAt, 0)
	r.BytesIn += drained.BytesIn
	r.BytesOut += drained.BytesOut
	r.RowsByStmt = append(r.RowsByStmt, drained.RowsByStmt...)
	r.AffectedByStmt = append(r.AffectedByStmt, drained.AffectedByStmt...)
	r.LatencyMs = drained.LatencyMs
	if drained.ErrorCode != "" {
		r.ErrorCode = drained.ErrorCode
	}
	return r, err
}
