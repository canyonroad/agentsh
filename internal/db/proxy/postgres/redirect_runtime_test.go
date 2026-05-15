//go:build linux

package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

type fakeRedirectPlanner struct {
	plan  redirectRuntimePlan
	err   error
	calls int
}

func (f *fakeRedirectPlanner) PlanRedirect(context.Context, redirectRuntimeInput) (redirectRuntimePlan, error) {
	f.calls++
	if f.err != nil {
		return redirectRuntimePlan{}, f.err
	}
	return f.plan, nil
}

func TestRedirectRuntime_PlansAndClassifiesRewrittenSQL(t *testing.T) {
	pc, _, _ := newSimpleQueryFixture(t)
	planner := &fakeRedirectPlanner{plan: redirectRuntimePlan{
		RewrittenSQL:   "select id from public.safe_users",
		Rule:           "redirect-users",
		SourceRelation: "public.users",
		TargetRelation: "public.safe_users",
		RuntimeStatus:  "planned",
	}}
	pc.redirectPlanner = planner

	stmt := effects.ClassifiedStatement{
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:   effects.GroupRead,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Schema: "public", Name: "users"}},
		}},
	}
	decision := policy.Decision{Verb: policy.VerbRedirect, RuleName: "redirect-users", RuleKind: policy.RuleKindStatement}

	plan, ok := pc.planRuntimeRedirect(context.Background(), "select id from public.users", stmt, decision)
	if !ok {
		t.Fatalf("planRuntimeRedirect rejected: %+v", plan)
	}
	if planner.calls != 1 {
		t.Fatalf("planner calls = %d, want 1", planner.calls)
	}
	if plan.RewrittenSQL != "select id from public.safe_users" || len(plan.RewrittenStatements) != 1 {
		t.Fatalf("unexpected runtime plan: %+v", plan)
	}
	if plan.RewrittenStatements[0].RawVerb != "SELECT" {
		t.Fatalf("rewritten classification = %+v", plan.RewrittenStatements)
	}
	if plan.RewrittenStatementDigest == "" {
		t.Fatalf("rewritten digest missing")
	}
}

func TestRedirectRuntime_FailsClosedOnPlannerError(t *testing.T) {
	pc, _, _ := newSimpleQueryFixture(t)
	pc.redirectPlanner = &fakeRedirectPlanner{err: errors.New("unsupported_statement")}

	stmt := effects.ClassifiedStatement{RawVerb: "SELECT", Effects: []effects.Effect{{Group: effects.GroupRead}}}
	decision := policy.Decision{Verb: policy.VerbRedirect, RuleName: "redirect-users", RuleKind: policy.RuleKindStatement}

	plan, ok := pc.planRuntimeRedirect(context.Background(), "select 1", stmt, decision)
	if ok {
		t.Fatalf("planRuntimeRedirect unexpectedly succeeded: %+v", plan)
	}
	if plan.RejectionReason == "" {
		t.Fatalf("rejection reason missing: %+v", plan)
	}
}

func TestRedirectRuntime_FailsClosedOnUnsafeReclassification(t *testing.T) {
	pc, _, _ := newSimpleQueryFixture(t)
	pc.redirectPlanner = &fakeRedirectPlanner{plan: redirectRuntimePlan{
		RewrittenSQL:   "delete from public.safe_users",
		Rule:           "redirect-users",
		SourceRelation: "public.users",
		TargetRelation: "public.safe_users",
	}}

	stmt := effects.ClassifiedStatement{RawVerb: "SELECT", Effects: []effects.Effect{{Group: effects.GroupRead}}}
	decision := policy.Decision{Verb: policy.VerbRedirect, RuleName: "redirect-users", RuleKind: policy.RuleKindStatement}

	plan, ok := pc.planRuntimeRedirect(context.Background(), "select 1", stmt, decision)
	if ok {
		t.Fatalf("unsafe rewritten SQL unexpectedly accepted: %+v", plan)
	}
	if plan.RejectionReason != "rewritten_statement_not_read_only" {
		t.Fatalf("RejectionReason = %q", plan.RejectionReason)
	}
}
