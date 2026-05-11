//go:build linux

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
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

	parser := pc.srv.classifierFor(pc.svc.Dialect)
	stmts, _ := parser.Classify(q.String, classify_pg.SessionState{}, classify_pg.Options{})
	rs := pc.srv.policy()
	decisions := make([]policy.Decision, len(stmts))
	anyDeny := false
	for i, s := range stmts {
		decisions[i] = policy.Evaluate(s, rs, policy.ServiceID(pc.svc.Name))
		if decisions[i].Verb == policy.VerbApprove {
			decisions[i] = synthApproveAsDeny(decisions[i])
		}
		if decisions[i].Verb == policy.VerbDeny {
			anyDeny = true
		}
	}

	batchSHA := sha256HexBatch(q.String)

	if !anyDeny {
		sentAt := timeNow()
		pc.state.upstreamFE.Send(q)
		if err := pc.state.upstreamFE.Flush(); err != nil {
			return err
		}
		result, ferr := pc.forwardUpstreamUntilRFQ(ctx, sentAt, len(q.String))
		pc.emitAllowEvents(ctx, stmts, decisions, q.String, batchSHA, result)
		return ferr
	}

	// Deny path filled in by Task 13.
	return pc.synthesizeError(sqlstateInsufficientPrivilege, "deny path not yet implemented")
}

// synthApproveAsDeny rewrites a Decision with Verb=approve into Verb=deny
// with the APPROVE_NOT_YET_SUPPORTED stub marker. Per spec §14.5, approve
// runtime lands in Plan 05; until then we surface a loud failure mode.
func synthApproveAsDeny(d policy.Decision) policy.Decision {
	d.Verb = policy.VerbDeny
	if d.Reason == "" {
		d.Reason = "APPROVE_NOT_YET_SUPPORTED"
	}
	return d
}

func sha256HexBatch(sql string) string {
	sum := sha256.Sum256([]byte(sql))
	return hex.EncodeToString(sum[:])
}

// emitAllowEvents emits one db_statement event per ClassifiedStatement when
// none denied. Per-stmt counters come from result.RowsByStmt /
// AffectedByStmt; bytes_in / bytes_out / latency_ms are attributed per-stmt
// (each event carries the batch values).
func (pc *proxyConn) emitAllowEvents(
	ctx context.Context,
	stmts []effects.ClassifiedStatement,
	decisions []policy.Decision,
	sql string,
	batchSHA string,
	r upstreamResult,
) {
	parser := pc.srv.classifierFor(pc.svc.Dialect)
	for i, s := range stmts {
		var rows, aff *int64
		if i < len(r.RowsByStmt) {
			rows = r.RowsByStmt[i]
			aff = r.AffectedByStmt[i]
		}
		errCode := ""
		if i < len(r.RowsByStmt) {
			// statement got a CommandComplete; attribute upstream error only
			// to the first stmt and the ones that ran past the failure.
			if i == 0 {
				errCode = r.ErrorCode
			}
		} else {
			// stmt never produced a CommandComplete; aborted by prior error.
			errCode = "STATEMENT_ABORTED_BY_PRIOR_ERROR"
		}
		ev := buildStatementEvent(buildArgs{
			Stmt: s, StmtIndex: i, BatchTotal: len(stmts),
			Decision: decisions[i],
			SQL: sql, Tier: pc.state.redactionTier,
			Conn: *pc.state,
			BytesIn: int64(len(sql)),
			BytesOut: r.BytesOut,
			LatencyMs: r.LatencyMs,
			RowsReturned: rows,
			RowsAffected: aff,
			UpstreamErrCode: errCode,
			DenyAction: "none",
			BatchSHA: batchSHA,
			Parser: parser,
		})
		if err := pc.srv.cfg.Sink.EmitStatement(ctx, ev); err != nil {
			pc.logger.Warn("emit statement event failed", "err", err)
		}
	}
}
