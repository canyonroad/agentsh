package shellparse

import "testing"

// Issue #377: `command -v`/`-V NAME` is read-only introspection (prints whether
// NAME exists / its type; never executes NAME). It must not be classified as a
// wrapper-bypass. `command -p` (executes NAME) and `command NAME` (no flag,
// forwards to NAME) keep their existing behavior.

func TestIsShellCBypassAttempt_CommandIntrospection(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"command -v is introspection, not bypass", []string{"-c", "command -v ls"}, false},
		{"command -V is introspection, not bypass", []string{"-c", "command -V ls"}, false},
		{"command -p executes, still bypass", []string{"-c", "command -p ls"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsShellCBypassAttempt("/bin/sh", tc.args); got != tc.want {
				t.Errorf("IsShellCBypassAttempt(sh, %v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestDerivePolicyTarget_CommandForms(t *testing.T) {
	if cmd, _, ok := DerivePolicyTarget("/bin/sh", []string{"-c", "command shutdown"}); !ok || cmd != "shutdown" {
		t.Errorf("DerivePolicyTarget(command shutdown) = (%q, ok=%v), want (\"shutdown\", true)", cmd, ok)
	}
	if _, _, ok := DerivePolicyTarget("/bin/sh", []string{"-c", "command -v ls"}); ok {
		t.Error("DerivePolicyTarget(command -v ls) ok=true, want false (introspection)")
	}
	if _, _, ok := DerivePolicyTarget("/bin/sh", []string{"-c", "command -V ls"}); ok {
		t.Error("DerivePolicyTarget(command -V ls) ok=true, want false (introspection)")
	}
}
