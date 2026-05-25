package policy

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// Issue #378: sandbox.seccomp.shellc.opaque controls opaque shell-c handling.
// The hasRestrictiveCommandRule gate is preserved (allow-only policies are
// never tightened); within it the mode picks the outcome.

const opaqueScript = "echo $HOME | head" // opaque: pipe + var

func TestParseShellCOpaqueMode(t *testing.T) {
	cases := map[string]ShellCOpaqueMode{
		"":        ShellCOpaqueEnforce,
		"enforce": ShellCOpaqueEnforce,
		"allow":   ShellCOpaqueAllow,
		"deny":    ShellCOpaqueDeny,
		"bogus":   ShellCOpaqueEnforce, // defensive default
	}
	for in, want := range cases {
		if got := ParseShellCOpaqueMode(in); got != want {
			t.Errorf("ParseShellCOpaqueMode(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCheckCommand_OpaqueModeMatrix(t *testing.T) {
	cases := []struct {
		name     string
		mode     ShellCOpaqueMode
		execveOn bool
		wantDeny bool // true => denied as shellc-opaque-script
	}{
		{"enforce+active=allow", ShellCOpaqueEnforce, true, false},
		{"enforce+inactive=deny", ShellCOpaqueEnforce, false, true},
		{"allow+active=allow", ShellCOpaqueAllow, true, false},
		{"allow+inactive=allow", ShellCOpaqueAllow, false, false},
		{"deny+active=deny", ShellCOpaqueDeny, true, true},
		{"deny+inactive=deny", ShellCOpaqueDeny, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newInterceptionTestEngine(t) // has a restrictive rule (deny-shutdown)
			dec := e.CheckCommandWithExecve("/bin/sh", []string{"-c", opaqueScript}, tc.execveOn, tc.mode)
			gotDeny := dec.PolicyDecision == types.DecisionDeny && dec.Rule == "shellc-opaque-script"
			if gotDeny != tc.wantDeny {
				t.Fatalf("decision=%s rule=%q; want deny=%v", dec.PolicyDecision, dec.Rule, tc.wantDeny)
			}
			if tc.wantDeny && !strings.Contains(dec.Message, "shellc.opaque=allow") {
				t.Errorf("deny message should name the remedy; got %q", dec.Message)
			}
		})
	}
}

// With NO restrictive command rule, opaque scripts run regardless of mode.
func TestCheckCommand_OpaqueModeNoRestrictiveRuleAlwaysAllows(t *testing.T) {
	p := &Policy{
		CommandRules: []CommandRule{
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	for _, mode := range []ShellCOpaqueMode{ShellCOpaqueEnforce, ShellCOpaqueAllow, ShellCOpaqueDeny} {
		dec := e.CheckCommandWithExecve("/bin/sh", []string{"-c", opaqueScript}, false, mode)
		if dec.Rule == "shellc-opaque-script" {
			t.Errorf("mode=%v: opaque denied despite no restrictive rule", mode)
		}
	}
}
