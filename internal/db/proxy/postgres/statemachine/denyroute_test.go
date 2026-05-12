//go:build linux

package statemachine

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/agentsh/agentsh/internal/db/policy"
)

func TestDenyRoute_OutOfTx_NotDirty(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'I', UpstreamDirtySinceSync: false},
		policy.StatementRule{Name: "block-delete", Decision: "deny"},
		"denied: block-delete",
		"42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied: block-delete"},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}

func TestDenyRoute_OutOfTx_Dirty(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'I', UpstreamDirtySinceSync: true},
		policy.StatementRule{Name: "block-delete", Decision: "deny"},
		"denied",
		"42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied"},
		&ActionDrainUntilRFQ{},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}

func TestDenyRoute_InTx_DefaultTerminate(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'T'},
		policy.StatementRule{Name: "block-delete", Decision: "deny"},
		"denied",
		"42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied", Severity: "FATAL"},
		&ActionClose{},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}

func TestDenyRoute_InTx_ExplicitTerminate(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'T'},
		policy.StatementRule{Name: "x", Decision: "deny", DenyModeInTx: "terminate"},
		"x", "42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "x", Severity: "FATAL"},
		&ActionClose{},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff:\n%s", diff)
	}
}

func TestDenyRoute_InTx_RollbackThenContinue(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'T'},
		policy.StatementRule{Name: "soft", Decision: "deny", DenyModeInTx: "rollback_then_continue"},
		"soft",
		"42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "soft"},
		&ActionInjectRollback{},
		&ActionDrainUntilRFQ{},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}

func TestDenyRoute_InTxError_TreatedAsInTx(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'E'},
		policy.StatementRule{Name: "x", Decision: "deny"},
		"x", "42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "x", Severity: "FATAL"},
		&ActionClose{},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}
