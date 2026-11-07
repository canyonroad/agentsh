package fsmonitor

import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

type fakeApprover struct {
	approved bool
	err      error
	calls    int
}

func (f *fakeApprover) RequestApproval(ctx context.Context, req approvals.Request) (approvals.Resolution, error) {
	f.calls++
	return approvals.Resolution{Approved: f.approved}, f.err
}

// TestMaybeApprove_FailsClosedWithoutApprover: a policy "approve" decision must
// not pass when no approver is wired (previously it was silently allowed).
func TestMaybeApprove_FailsClosedWithoutApprover(t *testing.T) {
	n := &node{hooks: &Hooks{SessionID: "s1"}}
	dec := n.maybeApprove(context.Background(), policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
		Rule:              "gate",
		Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeEnforced},
	}, "file", "/workspace/.env", "write")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("effective decision = %q, want deny", dec.EffectiveDecision)
	}
}

func TestMaybeApprove_ResolvesViaApprover(t *testing.T) {
	ap := &fakeApprover{approved: true}
	n := &node{hooks: &Hooks{SessionID: "s1", Approvals: ap}}
	dec := n.maybeApprove(context.Background(), policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
		Rule:              "gate",
		Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeEnforced},
	}, "file", "/workspace/.env", "write")
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("effective decision = %q, want allow", dec.EffectiveDecision)
	}
	if ap.calls != 1 {
		t.Fatalf("approver calls = %d, want 1", ap.calls)
	}
}

func TestMaybeApprove_DeniesOnNegativeResolution(t *testing.T) {
	n := &node{hooks: &Hooks{SessionID: "s1", Approvals: &fakeApprover{err: errors.New("no")}}}
	dec := n.maybeApprove(context.Background(), policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
		Rule:              "gate",
		Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeEnforced},
	}, "file", "/workspace/.env", "write")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("effective decision = %q, want deny", dec.EffectiveDecision)
	}
}

func TestMaybeApprove_LeavesAllowAlone(t *testing.T) {
	n := &node{hooks: &Hooks{SessionID: "s1"}}
	dec := n.maybeApprove(context.Background(), policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
	}, "file", "/workspace/x", "write")
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("effective decision = %q, want allow", dec.EffectiveDecision)
	}
}
