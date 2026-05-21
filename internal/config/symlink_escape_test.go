package config

import (
	"strings"
	"testing"
)

// TestValidateConfig_RejectsBadSymlinkEscape mirrors the existing
// validator-rejection style (see TestValidateConfig_RejectsBadFailMode):
// an unrecognized policies.symlink_escape value must fail validation at
// load time, not silently default.
func TestValidateConfig_RejectsBadSymlinkEscape(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Policies.SymlinkEscape = "loosey-goosey"

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("invalid policies.symlink_escape must fail validation")
	}
	if !strings.Contains(err.Error(), "symlink_escape") ||
		!strings.Contains(err.Error(), "loosey-goosey") {
		t.Errorf("error should mention symlink_escape and the bad value; got: %v", err)
	}
}

// TestValidateConfig_AcceptsValidSymlinkEscape covers the documented
// values ("" gets normalized to "evaluate" by SymlinkEscapeDeny()).
func TestValidateConfig_AcceptsValidSymlinkEscape(t *testing.T) {
	for _, v := range []string{"", "evaluate", "deny"} {
		cfg := &Config{}
		applyDefaults(cfg)
		cfg.Policies.SymlinkEscape = v
		if err := validateConfig(cfg); err != nil {
			if strings.Contains(err.Error(), "symlink_escape") {
				t.Errorf("valid symlink_escape %q should not be rejected; got: %v", v, err)
			}
		}
	}
}

// TestPoliciesConfig_SymlinkEscapeDeny covers the helper's semantics
// directly. Validator already rejects anything not in {"", "evaluate",
// "deny"}, but the helper is defensive against future schema drift.
func TestPoliciesConfig_SymlinkEscapeDeny(t *testing.T) {
	cases := []struct {
		in   string
		deny bool
	}{
		{"", false},
		{"evaluate", false},
		{"deny", true},
		{"DENY", false}, // case-sensitive on purpose; matches the validator's literal set
		{"anything-else", false},
	}
	for _, c := range cases {
		got := (&PoliciesConfig{SymlinkEscape: c.in}).SymlinkEscapeDeny()
		if got != c.deny {
			t.Errorf("SymlinkEscape=%q: got deny=%v, want %v", c.in, got, c.deny)
		}
	}
}
