//go:build linux

package postgres

import (
	"context"
	"fmt"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/redirect"
)

const sqlstateRedirectRejected = "0A000"

type redirectRuntimePlanner interface {
	PlanRedirect(context.Context, redirectRuntimeInput) (redirectRuntimePlan, error)
}

type redirectRuntimeInput struct {
	SQL      string
	Stmt     effects.ClassifiedStatement
	Decision policy.Decision
	Rule     policy.StatementRule
	Service  policy.ServiceID
}

type redirectRuntimePlan struct {
	RewrittenSQL             string
	RewrittenStatements      []effects.ClassifiedStatement
	OriginalStatementDigest  string
	RewrittenStatementDigest string
	Rule                     string
	SourceRelation           string
	TargetRelation           string
	RuntimeStatus            string
	RejectionReason          string
}

func (pc *proxyConn) activeRedirectPlanner() redirectRuntimePlanner {
	if pc.redirectPlanner != nil {
		return pc.redirectPlanner
	}
	dialect, ok := classify_pg.ParseDialect(pc.svc.Dialect)
	if !ok {
		return plan11RedirectPlanner{}
	}
	return plan11RedirectPlanner{backend: classify_pg.NewRewriteBackend(dialect)}
}

func (pc *proxyConn) planRuntimeRedirect(
	ctx context.Context,
	sql string,
	stmt effects.ClassifiedStatement,
	decision policy.Decision,
) (redirectRuntimePlan, bool) {
	parser := pc.resolvingParser(pc.svc.Dialect)
	rule := lookupStatementRuleByName(pc.srv.policy(), decision.RuleName)
	input := redirectRuntimeInput{
		SQL:      sql,
		Stmt:     stmt,
		Decision: decision,
		Rule:     rule,
		Service:  policy.ServiceID(pc.svc.Name),
	}
	plan, err := pc.activeRedirectPlanner().PlanRedirect(ctx, input)
	if err != nil {
		plan.RejectionReason = err.Error()
		plan.RuntimeStatus = "rejected"
		return plan, false
	}
	if plan.Rule == "" {
		plan.Rule = decision.RuleName
	}
	if plan.RewrittenSQL == "" {
		plan.RejectionReason = "empty_rewritten_statement"
		plan.RuntimeStatus = "rejected"
		return plan, false
	}

	opts := classifierOptionsFromPolicy(pc.srv.policy())
	rewritten, err := parser.Classify(plan.RewrittenSQL, classify_pg.SessionState{}, opts)
	if err != nil || len(rewritten) != 1 {
		plan.RejectionReason = "rewritten_statement_unclassifiable"
		plan.RuntimeStatus = "rejected"
		return plan, false
	}
	if !statementIsReadOnly(rewritten[0]) {
		plan.RejectionReason = "rewritten_statement_not_read_only"
		plan.RuntimeStatus = "rejected"
		return plan, false
	}
	plan.RewrittenStatements = rewritten
	plan.OriginalStatementDigest = statementDigest(parser, sql)
	plan.RewrittenStatementDigest = statementDigest(parser, plan.RewrittenSQL)
	plan.RuntimeStatus = "planned"
	return plan, true
}

func statementIsReadOnly(stmt effects.ClassifiedStatement) bool {
	if len(stmt.Effects) == 0 {
		return false
	}
	for _, eff := range stmt.Effects {
		if eff.Group != effects.GroupRead {
			return false
		}
	}
	return true
}

func redirectEventFromPlan(plan redirectRuntimePlan, status string) redirectEventArgs {
	if status == "" {
		status = plan.RuntimeStatus
	}
	return redirectEventArgs{
		Redirected:               true,
		Rule:                     plan.Rule,
		RewrittenSQL:             plan.RewrittenSQL,
		RewrittenStatementDigest: plan.RewrittenStatementDigest,
		SourceRelation:           plan.SourceRelation,
		TargetRelation:           plan.TargetRelation,
		RuntimeStatus:            status,
		RejectionReason:          plan.RejectionReason,
	}
}

type plan11RedirectPlanner struct {
	backend redirect.SQLBackend
}

func (p plan11RedirectPlanner) PlanRedirect(_ context.Context, input redirectRuntimeInput) (redirectRuntimePlan, error) {
	if p.backend == nil {
		return redirectRuntimePlan{}, fmt.Errorf("unsupported_redirect_dialect")
	}
	action, err := redirectActionFromRuntimeInput(input)
	if err != nil {
		return redirectRuntimePlan{}, err
	}
	plan, err := (redirect.Planner{Backend: p.backend}).Plan(redirect.Input{
		SQL:       input.SQL,
		Statement: input.Stmt,
		Action:    action,
	})
	if err != nil {
		return redirectRuntimePlan{}, err
	}
	return redirectRuntimePlan{
		RewrittenSQL:   plan.RewrittenSQL,
		Rule:           plan.RuleName,
		SourceRelation: plan.SourceRelation,
		TargetRelation: plan.TargetRelation,
	}, nil
}

func redirectActionFromRuntimeInput(input redirectRuntimeInput) (redirect.Action, error) {
	ruleName := input.Decision.RuleName
	if ruleName == "" {
		ruleName = input.Rule.Name
	}
	if input.Decision.Redirect != nil {
		return redirect.Action{
			RuleName:       ruleName,
			SourceRelation: input.Decision.Redirect.SourceRelation,
			TargetRelation: input.Decision.Redirect.TargetRelation,
		}, nil
	}
	if len(input.Rule.Relations) == 1 && input.Rule.Redirect != nil {
		return redirect.Action{
			RuleName:       ruleName,
			SourceRelation: input.Rule.Relations[0],
			TargetRelation: input.Rule.Redirect.Relation,
		}, nil
	}
	return redirect.Action{}, fmt.Errorf("missing_redirect_action")
}
