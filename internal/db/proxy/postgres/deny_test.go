//go:build linux

package postgres

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/policy"
)

func TestSynthErrorAndRFQ_WritesErrorThenRFQI(t *testing.T) {
	pc, clientFE, _ := newSimpleQueryFixture(t)

	errCh := make(chan error, 1)
	go func() { errCh <- pc.synthErrorAndRFQ("42501", "denied") }()

	m1 := mustReceiveClientFrame(t, clientFE)
	er, ok := m1.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("first frame = %T want ErrorResponse", m1)
	}
	if er.Code != "42501" || er.Message != "denied" || er.Severity != "ERROR" {
		t.Fatalf("ErrorResponse = %+v", er)
	}
	m2 := mustReceiveClientFrame(t, clientFE)
	if rfq, ok := m2.(*pgproto3.ReadyForQuery); !ok || rfq.TxStatus != 'I' {
		t.Fatalf("second frame = %T %+v want RFQ('I')", m2, m2)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("synthErrorAndRFQ: %v", err)
	}
}

func TestSynthErrorOnly_NoTrailingRFQ(t *testing.T) {
	pc, clientFE, _ := newSimpleQueryFixture(t)

	errCh := make(chan error, 1)
	go func() { errCh <- pc.synthErrorOnly("42501", "in-tx") }()

	er := mustReceiveClientFrame(t, clientFE).(*pgproto3.ErrorResponse)
	if er.Code != "42501" || er.Message != "in-tx" {
		t.Fatalf("ErrorResponse = %+v", er)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("synthErrorOnly: %v", err)
	}
}

func TestPickDenySynth_FirstDenyWins(t *testing.T) {
	decisions := []policy.Decision{
		{Verb: policy.VerbAllow},
		{Verb: policy.VerbDeny, RuleKind: policy.RuleKindStatement, RuleName: "no-deletes", Reason: "delete denied"},
		{Verb: policy.VerbDeny, RuleKind: policy.RuleKindStatement, RuleName: "no-truncates"},
	}
	rendered, sqlstate := pickDenySynth(decisions)
	if sqlstate != "42501" {
		t.Fatalf("sqlstate = %q want 42501", sqlstate)
	}
	if !strings.Contains(rendered, "no-deletes") {
		t.Fatalf("rendered = %q does not reference first deny rule", rendered)
	}
}

func TestPickDenySynth_ConnectionRuleUses28000(t *testing.T) {
	decisions := []policy.Decision{
		{Verb: policy.VerbDeny, RuleKind: policy.RuleKindConnection, RuleName: "no-replica"},
	}
	_, sqlstate := pickDenySynth(decisions)
	if sqlstate != "28000" {
		t.Fatalf("sqlstate = %q want 28000", sqlstate)
	}
}

func TestPickDenySynth_ImplicitDenyMessage(t *testing.T) {
	decisions := []policy.Decision{
		{Verb: policy.VerbDeny, RuleKind: policy.RuleKindStatement, RuleName: "", Reason: "no rule covers unsafe_io"},
	}
	rendered, _ := pickDenySynth(decisions)
	if !strings.Contains(rendered, "no rule covers") {
		t.Fatalf("rendered = %q does not include reason text", rendered)
	}
}
