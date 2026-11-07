package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// An "approve" rule with no approvals subsystem configured must deny, not allow:
// nobody can answer, so "approve" previously became a silent allow.
func TestApproveDecisionDeniesWhenApprovalsDisabled(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "t",
		FileRules: []FileRule{{
			Name:       "gate",
			Paths:      []string{"/workspace/.env"},
			Operations: []string{"*"},
			Decision:   "approve",
		}},
	}
	eng, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := eng.CheckFile("/workspace/.env", "write")
	if dec.PolicyDecision != types.DecisionApprove {
		t.Fatalf("policy decision = %q, want approve", dec.PolicyDecision)
	}
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("effective decision = %q, want deny", dec.EffectiveDecision)
	}
}

func TestApproveDecisionStaysApproveWhenApprovalsEnabled(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "t",
		FileRules: []FileRule{{
			Name:       "gate",
			Paths:      []string{"/workspace/.env"},
			Operations: []string{"*"},
			Decision:   "approve",
		}},
	}
	eng, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := eng.CheckFile("/workspace/.env", "write")
	if dec.EffectiveDecision != types.DecisionApprove {
		t.Fatalf("effective decision = %q, want approve", dec.EffectiveDecision)
	}
}
