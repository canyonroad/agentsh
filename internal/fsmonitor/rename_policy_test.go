package fsmonitor

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestCombinePathDecisionsForRename_DenyWins(t *testing.T) {
	a := policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow, Rule: "a"}
	d := policy.Decision{PolicyDecision: types.DecisionDeny, EffectiveDecision: types.DecisionDeny, Rule: "deny"}

	out := combinePathDecisionsForRename(a, d)
	if out.EffectiveDecision != types.DecisionDeny || out.PolicyDecision != types.DecisionDeny {
		t.Fatalf("expected deny, got %+v", out)
	}
	if out.Rule != "deny" {
		t.Fatalf("expected deny rule, got %q", out.Rule)
	}
}

func TestCombinePathDecisionsForRename_ApproveWinsOverAllow(t *testing.T) {
	a := policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow, Rule: "a"}
	ap := policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionAllow,
		Rule:              "approve",
		Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeShadow},
	}

	out := combinePathDecisionsForRename(a, ap)
	if out.PolicyDecision != types.DecisionApprove || out.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("expected approve/shadow allow, got %+v", out)
	}
	if out.Rule != "approve" {
		t.Fatalf("expected approve rule, got %q", out.Rule)
	}
	if out.Approval == nil || out.Approval.Mode != types.ApprovalModeShadow {
		t.Fatalf("expected approval metadata, got %+v", out.Approval)
	}
}
