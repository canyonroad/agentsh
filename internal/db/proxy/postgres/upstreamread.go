//go:build linux

package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// upstreamResult collects counters and final state from one Q...Z round-trip.
// Per-statement counters live in slices indexed by the order CommandComplete
// frames arrived in. Statements that did not produce a CommandComplete frame
// (mid-batch ErrorResponse aborted them) get null counters at event-build time.
type upstreamResult struct {
	BytesOut       int64
	RowsByStmt     []*int64
	AffectedByStmt []*int64
	LatencyMs      int64
	ErrorCode      string
}

// forwardUpstreamUntilRFQ reads upstream frames one at a time and forwards
// each to the client. Returns when the upstream sends ReadyForQuery, updating
// pc.state.smState.LastUpstreamRFQ.
//
// bytesIn is the inbound 'Q' frame body length; the caller knows it and we
// just pass it through for completeness — the value is currently unused inside
// this function but the spine and event-builder consume it for the per-stmt
// Result struct.
func (pc *proxyConn) forwardUpstreamUntilRFQ(ctx context.Context, sentAt time.Time, bytesIn int) (upstreamResult, error) {
	_ = bytesIn
	var r upstreamResult
	var curRows int64
	curRowsSet := false

	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		msg, err := pc.state.upstreamFE.Receive()
		if err != nil {
			return r, fmt.Errorf("upstream recv: %w", err)
		}

		switch m := msg.(type) {
		case *pgproto3.DataRow:
			curRows++
			curRowsSet = true
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)

		case *pgproto3.CommandComplete:
			rows, aff := parseCommandTag(string(m.CommandTag))
			if curRowsSet && rows == nil {
				v := curRows
				rows = &v
			}
			r.RowsByStmt = append(r.RowsByStmt, rows)
			r.AffectedByStmt = append(r.AffectedByStmt, aff)
			curRows, curRowsSet = 0, false
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)

		case *pgproto3.ErrorResponse:
			if r.ErrorCode == "" {
				r.ErrorCode = m.Code
			}
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)

		case *pgproto3.ReadyForQuery:
			if pc.state.smState != nil {
				prev := pc.state.smState.LastUpstreamRFQ
				pc.state.smState.LastUpstreamRFQ = m.TxStatus
				switch m.TxStatus {
				case 'I':
					pc.state.smState.Phase = statemachine.PhaseIdle
					pc.state.smState.TxStartedAt = time.Time{}
				case 'T':
					pc.state.smState.Phase = statemachine.PhaseInTx
					if prev != 'T' {
						pc.state.smState.TxStartedAt = time.Now()
					}
				case 'E':
					pc.state.smState.Phase = statemachine.PhaseInTxError
				}
				// reset the per-Sync dirty flag on every observed RFQ
				pc.state.smState.UpstreamDirtySinceSync = false
			}
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("flush after RFQ: %w", err)
			}
			r.LatencyMs = time.Since(sentAt).Milliseconds()
			return r, nil

		default:
			// RowDescription / ParameterStatus / NoticeResponse / NotificationResponse /
			// ParameterDescription / etc. — forward verbatim with no counter effect.
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)
		}
	}
}

// estimatedFrameSize approximates encoded frame length for BytesOut accounting.
// pgproto3 v5 Encode returns ([]byte, error); we ignore the error here because
// the only failure mode is message-body-too-large, which cannot be triggered
// by frames we receive from a live upstream.
func estimatedFrameSize(m pgproto3.BackendMessage) int {
	buf, _ := m.Encode(nil)
	return len(buf)
}

// parseCommandTag parses the PostgreSQL CommandComplete tag string. Returns
// (rowsReturned, rowsAffected). At most one is non-nil for any tag, except
// utility tags ("BEGIN", "CREATE TABLE") which return (nil, nil).
//
// Recognized prefixes:
//
//	SELECT <n>       → (n, nil)
//	INSERT <oid> <n> → (nil, n)
//	UPDATE <n>       → (nil, n)
//	DELETE <n>       → (nil, n)
//	MOVE <n>         → (nil, n)
//	FETCH <n>        → (nil, n)
//	COPY <n>         → (nil, n)
func parseCommandTag(tag string) (rows *int64, affected *int64) {
	fields := strings.Fields(tag)
	if len(fields) == 0 {
		return nil, nil
	}
	parseN := func(s string) *int64 {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil
		}
		return &n
	}
	switch fields[0] {
	case "SELECT":
		if len(fields) >= 2 {
			return parseN(fields[1]), nil
		}
	case "INSERT":
		if len(fields) >= 3 {
			return nil, parseN(fields[2])
		}
	case "UPDATE", "DELETE", "MOVE", "FETCH", "COPY":
		if len(fields) >= 2 {
			return nil, parseN(fields[1])
		}
	}
	return nil, nil
}
