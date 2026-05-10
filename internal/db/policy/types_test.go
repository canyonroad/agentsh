package policy

import "testing"

func TestDecisionVerbString(t *testing.T) {
	cases := []struct {
		v    DecisionVerb
		want string
	}{
		{VerbAllow, "allow"},
		{VerbAudit, "audit"},
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
