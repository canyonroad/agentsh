//go:build linux

package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

type approvalOutcome struct {
	approved   bool
	denyAction string
	err        error
}

type approvalResult struct {
	approved bool
	err      error
}

func (pc *proxyConn) waitForApproval(ctx context.Context, a statemachine.ActionApproverWait) approvalOutcome {
	approver := pc.srv.cfg.Approver
	if approver == nil {
		approver = policy.NopApprover{}
	}
	timeout := a.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	approveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan approvalResult, 1)
	go func() {
		approved, err := approver.Decide(approveCtx, a.Stmt, timeout)
		resultCh <- approvalResult{approved: approved, err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	startedAt := time.Now()

	select {
	case <-ctx.Done():
		return approvalOutcome{denyAction: "cancelled_during_approval", err: ctx.Err()}
	case res := <-resultCh:
		if res.err != nil || !res.approved {
			if time.Since(startedAt) >= timeout {
				return approvalOutcome{denyAction: "approval_timeout"}
			}
			return approvalOutcome{denyAction: "approval_denied"}
		}
		return approvalOutcome{approved: true, denyAction: "none"}
	case <-timer.C:
		cancel()
		return approvalOutcome{denyAction: "approval_timeout"}
	}
}

func (pc *proxyConn) runApprovalWait(ctx context.Context, origFrame pgproto3.FrontendMessage, a statemachine.ActionApproverWait) error {
	out := pc.waitForApproval(ctx, a)
	if out.err != nil {
		pc.emitApprovalFrameEvent(ctx, origFrame, a, approvalDenyDecision(a.Rule, "cancelled during approval"), out.denyAction)
		return out.err
	}
	if out.approved {
		pc.emitApprovalFrameEvent(ctx, origFrame, a, approvalApproveDecision(a.Rule), "none")
		if parse, ok := origFrame.(*pgproto3.Parse); ok {
			pc.cacheApprovedParse(parse, a.Stmt)
		}
		pc.state.upstreamFE.Send(origFrame)
		return pc.state.upstreamFE.Flush()
	}
	pc.emitApprovalFrameEvent(ctx, origFrame, a, approvalDenyDecision(a.Rule, approvalReason(out.denyAction)), out.denyAction)
	actions := statemachine.DenyRoute(*pc.state.smState, a.Rule, "denied by AgentSH policy: "+approvalReason(out.denyAction), sqlstateInsufficientPrivilege)
	return pc.executeActions(ctx, origFrame, actions)
}

func (pc *proxyConn) runSimpleQueryApproval(
	ctx context.Context,
	q *pgproto3.Query,
	stmts []effects.ClassifiedStatement,
	decisions []policy.Decision,
	approveIndex int,
	batchSHA string,
) error {
	rule := lookupStatementRuleByName(pc.srv.policy(), decisions[approveIndex].RuleName)
	action := statemachine.ActionApproverWait{
		Timeout: approvalTimeout(decisions[approveIndex], rule),
		Stmt:    stmts[approveIndex],
		Rule:    rule,
	}
	out := pc.waitForApproval(ctx, action)
	if out.err != nil {
		denyDecisions := decisionsWithApprovalDeny(decisions, approveIndex, "cancelled during approval")
		pc.emitDenyEvents(ctx, stmts, denyDecisions, q.String, batchSHA, out.denyAction)
		return out.err
	}
	if out.approved {
		sentAt := timeNow()
		pc.state.upstreamFE.Send(q)
		if err := pc.state.upstreamFE.Flush(); err != nil {
			return err
		}
		result, ferr := pc.forwardUpstreamUntilRFQ(ctx, sentAt, len(q.String))
		pc.emitAllowEvents(ctx, stmts, decisions, q.String, batchSHA, result)
		pc.refreshCatalogAfterSuccessfulStatements(ctx, stmts, result)
		return ferr
	}

	denyDecisions := decisionsWithApprovalDeny(decisions, approveIndex, approvalReason(out.denyAction))
	pc.emitDenyEvents(ctx, stmts, denyDecisions, q.String, batchSHA, out.denyAction)
	actions := statemachine.DenyRoute(*pc.state.smState, rule, "denied by AgentSH policy: "+approvalReason(out.denyAction), sqlstateInsufficientPrivilege)
	return pc.executeActions(ctx, q, actions)
}

func approvalTimeout(d policy.Decision, rule policy.StatementRule) time.Duration {
	if rule.Timeout != 0 {
		return rule.Timeout
	}
	if d.Approval != nil && d.Approval.Timeout != 0 {
		return d.Approval.Timeout
	}
	return 60 * time.Second
}

func approvalApproveDecision(rule policy.StatementRule) policy.Decision {
	return policy.Decision{
		Verb:                policy.VerbApprove,
		RuleKind:            policy.RuleKindStatement,
		RuleName:            rule.Name,
		MatchingEffectIndex: 0,
		MatchingEffectGroup: effects.GroupUnknown,
	}
}

func approvalDenyDecision(rule policy.StatementRule, reason string) policy.Decision {
	return policy.Decision{
		Verb:                policy.VerbDeny,
		RuleKind:            policy.RuleKindStatement,
		RuleName:            rule.Name,
		MatchingEffectIndex: 0,
		MatchingEffectGroup: effects.GroupUnknown,
		Reason:              reason,
	}
}

func decisionsWithApprovalDeny(in []policy.Decision, approveIndex int, reason string) []policy.Decision {
	out := append([]policy.Decision(nil), in...)
	if approveIndex >= 0 && approveIndex < len(out) {
		out[approveIndex].Verb = policy.VerbDeny
		out[approveIndex].Reason = reason
	}
	return out
}

func approvalReason(denyAction string) string {
	switch denyAction {
	case "approval_timeout":
		return "approval timeout"
	case "approval_denied":
		return "approval denied"
	case "cancelled_during_approval":
		return "cancelled during approval"
	default:
		return "approval denied"
	}
}

func (pc *proxyConn) emitApprovalFrameEvent(
	ctx context.Context,
	origFrame pgproto3.FrontendMessage,
	a statemachine.ActionApproverWait,
	d policy.Decision,
	denyAction string,
) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	sql := ""
	switch f := origFrame.(type) {
	case *pgproto3.Query:
		sql = f.String
	case *pgproto3.Parse:
		sql = f.Query
	}
	ev := buildStatementEvent(buildArgs{
		Stmt:       a.Stmt,
		StmtIndex:  0,
		BatchTotal: 1,
		Decision:   d,
		SQL:        sql,
		Tier:       pc.state.redactionTier,
		Conn:       *pc.state,
		BytesIn:    int64(len(sql)),
		DenyAction: denyAction,
		BatchSHA:   sha256HexBatch(sql),
		Parser:     pc.srv.classifierFor(pc.svc.Dialect),
	})
	if err := pc.srv.cfg.Sink.EmitStatement(ctx, ev); err != nil {
		pc.logger.Warn("emit approval event failed", "err", err)
	}
}
