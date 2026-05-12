//go:build linux

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

var (
	errInTxTerminate      = errors.New("postgres.simpleQueryLoop: in-tx deny terminated connection")
	errFrameTooLargeClose = errors.New("postgres.simpleQueryLoop: frame budget exceeded; conn closed")
	errUnsupportedFrame   = errors.New("postgres.simpleQueryLoop: unsupported frame type; conn closed")
)

// classifierOptionsFromPolicy materializes a classify_pg.Options from the
// active policy snapshot. Captures the escalation knobs (§7.6) and converts
// the allowlist slice to a map for the walker.
func classifierOptionsFromPolicy(rs *policy.RuleSet) classify_pg.Options {
	if rs == nil {
		return classify_pg.Options{}
	}
	r := rs.Redaction()
	if !r.EscalateUnknownFunctions {
		return classify_pg.Options{}
	}
	allow := make(map[string]struct{}, len(r.SafeFunctionAllowlist))
	for _, n := range r.SafeFunctionAllowlist {
		allow[n] = struct{}{}
	}
	return classify_pg.Options{
		EscalateUnknownFunctions: true,
		SafeFunctionAllowlist:    allow,
	}
}

// simpleQueryLoop is the post-handshake driver. It reads client frames one at
// a time, dispatches to handleQuery for 'Q', forwards 'X' (Terminate) directly,
// routes Plan-05a Extended Query frames (Parse/Bind/Describe/Execute/Sync/
// Flush/Close) through handleExtendedFrame, and rejects any other frame with
// a synthetic ErrorResponse.
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
		case *pgproto3.Parse, *pgproto3.Bind, *pgproto3.Describe, *pgproto3.Execute,
			*pgproto3.Sync, *pgproto3.Flush, *pgproto3.Close:
			if err := pc.handleExtendedFrame(ctx, m); err != nil {
				return err
			}
		default:
			return pc.handleUnsupportedFrame(ctx, m)
		}
	}
}

// handleUnsupportedFrame synthesizes ErrorResponse for any non-Q/non-X
// post-handshake frame and closes the connection. Delegates FunctionCall
// frames to handleFunctionCall (which implements the 04c default-deny stub
// and the Plan-05b opt-in path). Other frames get a generic 0A000 response.
func (pc *proxyConn) handleUnsupportedFrame(ctx context.Context, msg pgproto3.FrontendMessage) error {
	if fc, isFunc := msg.(*pgproto3.FunctionCall); isFunc {
		return pc.handleFunctionCall(ctx, fc)
	}
	frameType := fmt.Sprintf("%T", msg)
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

	rs := pc.srv.policy()
	parser := pc.srv.classifierFor(pc.svc.Dialect)
	opts := classifierOptionsFromPolicy(rs)
	stmts, _ := parser.Classify(q.String, classify_pg.SessionState{}, opts)

	// Pre-pass: handles every Intercept-eligible verb except PREPARE.
	// PREPARE needs decisions, so it's deferred to the post-pass.
	if len(stmts) == 0 || !strings.HasPrefix(stmts[0].RawVerb, "PREPARE") {
		preHandled, preActions := Intercept(stmts, nil, pc.sqlCache, *pc.state.smState, rs)
		if preHandled {
			return pc.executeActions(ctx, q, preActions)
		}
	}

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

	// Post-pass: PREPARE-deny needs decisions to know the denying rule;
	// PREPARE-allow populates the cache from the inner classification.
	// Only invoked for PREPARE verbs; all other verbs were handled (or
	// passed through) in the pre-pass.
	if len(stmts) > 0 && strings.HasPrefix(stmts[0].RawVerb, "PREPARE") {
		postHandled, postActions := Intercept(stmts, decisions, pc.sqlCache, *pc.state.smState, rs)
		if postHandled {
			batchSHA := sha256HexBatch(q.String)
			var postDenyRule policy.StatementRule
			for _, d := range decisions {
				if d.Verb == policy.VerbDeny {
					postDenyRule = lookupStatementRuleByName(rs, d.RuleName)
					break
				}
			}
			pc.emitDenyEvents(ctx, stmts, decisions, q.String, batchSHA, denyActionForState(pc.state.smState, postDenyRule))
			return pc.executeActions(ctx, q, postActions)
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

	// Deny path: route through statemachine.DenyRoute so the §14.3/§14.4
	// fork lives in one place. The first denying decision determines the
	// rule (for DenyModeInTx) and the deny event tags.
	var denyDecision policy.Decision
	for _, d := range decisions {
		if d.Verb == policy.VerbDeny {
			denyDecision = d
			break
		}
	}
	denyRule := lookupStatementRuleByName(rs, denyDecision.RuleName)
	denyAction := "none"
	if pc.state.smState != nil && (pc.state.smState.LastUpstreamRFQ == 'T' || pc.state.smState.LastUpstreamRFQ == 'E') {
		if denyRule.DenyModeInTx == "rollback_then_continue" {
			denyAction = "rollback_injected"
		} else {
			denyAction = "connection_terminated"
		}
	}
	pc.emitDenyEvents(ctx, stmts, decisions, q.String, batchSHA, denyAction)
	rendered, sqlstate := pickDenySynth(decisions)
	actions := statemachine.DenyRoute(*pc.state.smState, denyRule, rendered, sqlstate)
	return pc.executeActions(ctx, q, actions)
}

// denyActionForState returns the deny action string based on the current
// connection state and the matched rule. When the last upstream RFQ indicates
// an active transaction ('T' or 'E'), the action depends on DenyModeInTx:
// "rollback_then_continue" -> "rollback_injected"; anything else ->
// "connection_terminated". Out-of-tx ('I') always returns "none".
func denyActionForState(s *statemachine.ConnState, rule policy.StatementRule) string {
	if s == nil {
		return "none"
	}
	switch s.LastUpstreamRFQ {
	case 'T', 'E':
		if rule.DenyModeInTx == "rollback_then_continue" {
			return "rollback_injected"
		}
		return "connection_terminated"
	}
	return "none"
}

// lookupStatementRuleByName is a 04c-friendly wrapper around
// policy.RuleSet.AllStatementRules() — returns the first rule whose Name
// matches, or the zero StatementRule on miss (which DenyRoute treats as
// terminate-in-tx).
func lookupStatementRuleByName(rs *policy.RuleSet, name string) policy.StatementRule {
	if rs == nil || name == "" {
		return policy.StatementRule{}
	}
	for _, r := range rs.AllStatementRules() {
		if r.Name == name {
			return r
		}
	}
	return policy.StatementRule{}
}

func (pc *proxyConn) emitDenyEvents(
	ctx context.Context,
	stmts []effects.ClassifiedStatement,
	decisions []policy.Decision,
	sql, batchSHA, denyAction string,
) {
	parser := pc.srv.classifierFor(pc.svc.Dialect)
	for i, s := range stmts {
		deniedBySibling := decisions[i].Verb != policy.VerbDeny
		ev := buildStatementEvent(buildArgs{
			Stmt: s, StmtIndex: i, BatchTotal: len(stmts),
			Decision:          decisions[i],
			SQL:               sql, Tier: pc.state.redactionTier,
			Conn:              *pc.state,
			BytesIn:           int64(len(sql)),
			DenyAction:        denyAction,
			IsDeniedBySibling: deniedBySibling,
			BatchSHA:          batchSHA,
			Parser:            parser,
		})
		if err := pc.srv.cfg.Sink.EmitStatement(ctx, ev); err != nil {
			pc.logger.Warn("emit statement event failed", "err", err)
		}
	}
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
