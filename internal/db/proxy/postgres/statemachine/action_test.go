//go:build linux

package statemachine

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

var _ Action = (*ActionApproverWait)(nil)

func TestActionApproverWait_Fields(t *testing.T) {
	rule := policy.StatementRule{Name: "review-deletes", Decision: "approve"}
	a := &ActionApproverWait{
		Timeout: 60 * time.Second,
		Stmt:    effects.ClassifiedStatement{RawVerb: "DELETE"},
		Rule:    rule,
	}
	if a.Timeout != 60*time.Second {
		t.Errorf("Timeout=%v", a.Timeout)
	}
	if a.Stmt.RawVerb != "DELETE" {
		t.Errorf("Stmt.RawVerb=%q", a.Stmt.RawVerb)
	}
	if a.Rule.Name != "review-deletes" {
		t.Errorf("Rule.Name=%q", a.Rule.Name)
	}
}
