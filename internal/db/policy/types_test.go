package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestDecisionVerbString(t *testing.T) {
	cases := []struct {
		v    DecisionVerb
		want string
	}{
		{VerbAllow, "allow"},
		{VerbAudit, "audit"},
		{VerbRedirect, "redirect"},
		{VerbApprove, "approve"},
		{VerbDeny, "deny"},
	}
	for _, c := range cases {
		if got := c.v.String(); got != c.want {
			t.Errorf("DecisionVerb(%d).String() = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestRuleKindString(t *testing.T) {
	cases := []struct {
		k    RuleKind
		want string
	}{
		{RuleKindStatement, "statement"},
		{RuleKindConnection, "connection"},
		{RuleKindCancel, "cancel"},
	}
	for _, c := range cases {
		if got := c.k.String(); got != c.want {
			t.Errorf("RuleKind(%d).String() = %q, want %q", c.k, got, c.want)
		}
	}
}

func TestRedactionTierString(t *testing.T) {
	cases := []struct {
		r    RedactionTier
		want string
	}{
		{RedactNone, "none"},
		{RedactParametersRedacted, "parameters_redacted"},
		{RedactFull, "full"},
	}
	for _, c := range cases {
		if got := c.r.String(); got != c.want {
			t.Errorf("RedactionTier(%d).String() = %q, want %q", c.r, got, c.want)
		}
	}
}

func TestParseRedactionTier(t *testing.T) {
	cases := []struct {
		in   string
		want RedactionTier
		ok   bool
	}{
		{"none", RedactNone, true},
		{"parameters_redacted", RedactParametersRedacted, true},
		{"full", RedactFull, true},
		{"", 0, false},
		{"REDACTED", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseRedactionTier(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseRedactionTier(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestRuleSet_AllServices(t *testing.T) {
	yaml := `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
  reportsdb:
    family: postgres
    dialect: postgres
    upstream: reports.internal:5432
    tls_mode: passthrough
`
	rp, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := Decode(rp)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := rs.AllServices()
	if len(got) != 2 {
		t.Fatalf("AllServices len = %d, want 2", len(got))
	}
	seen := map[string]bool{}
	for _, s := range got {
		seen[s.Name] = true
	}
	if !seen["appdb"] || !seen["reportsdb"] {
		t.Errorf("AllServices missing expected names: %+v", got)
	}
}

func TestRuleSet_AllServices_Nil(t *testing.T) {
	var rs *RuleSet
	if got := rs.AllServices(); got != nil {
		t.Errorf("nil receiver: got %+v, want nil", got)
	}
}
