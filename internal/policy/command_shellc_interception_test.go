package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// newInterceptionTestEngine builds an engine whose policy has a restrictive
// command rule (deny-shutdown), so hasRestrictiveCommandRule is set and the
// opaque pre-deny gate is reachable. Mirrors command_shellc_test.go.
func newInterceptionTestEngine(t *testing.T) *Engine {
	t.Helper()
	p := &Policy{
		CommandRules: []CommandRule{
			{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
			{Name: "allow-shells", Commands: []string{"sh", "bash", "dash", "zsh"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// Issue #375: with execve enforcement active, opaque shell-c scripts must NOT
// be statically pre-denied — inner execs are policed at runtime by CheckExecve.
func TestCheckCommand_OpaqueAllowedWhenExecveEnforced(t *testing.T) {
	e := newInterceptionTestEngine(t)

	battery := []string{
		"echo $HOME",
		"ls /tmp | head",
		"echo x > /tmp/a",
		"true && true",
		"echo $(date)",
		"for i in 1 2; do echo $i; done",
		"curl https://example.com",
	}
	for _, script := range battery {
		dec := e.CheckCommandWithExecve("/bin/sh", []string{"-c", script}, true, ShellCOpaqueEnforce)
		if dec.Rule == "shellc-opaque-script" {
			t.Errorf("script %q: pre-denied as opaque with execve enforcement active; want fall-through to allow", script)
		}
		if dec.PolicyDecision != types.DecisionAllow {
			t.Errorf("script %q: decision = %s (rule=%q), want allow", script, dec.PolicyDecision, dec.Rule)
		}
	}
}

// Without execve enforcement, the current hard-deny is preserved.
func TestCheckCommand_OpaqueDeniedWhenNoExecveEnforcement(t *testing.T) {
	e := newInterceptionTestEngine(t)

	dec := e.CheckCommandWithExecve("/bin/sh", []string{"-c", "echo $HOME | head"}, false, ShellCOpaqueEnforce)
	if dec.PolicyDecision != types.DecisionDeny || dec.Rule != "shellc-opaque-script" {
		t.Errorf("got %s rule=%q, want deny shellc-opaque-script", dec.PolicyDecision, dec.Rule)
	}

	// Plain CheckCommand (no execve param) must keep the legacy hard-deny too.
	dec2 := e.CheckCommand("/bin/sh", []string{"-c", "echo $HOME | head"})
	if dec2.PolicyDecision != types.DecisionDeny || dec2.Rule != "shellc-opaque-script" {
		t.Errorf("CheckCommand: got %s rule=%q, want deny shellc-opaque-script", dec2.PolicyDecision, dec2.Rule)
	}
}

// Even with execve enforcement active, a genuinely-denied DERIVABLE command
// (not opaque) must still be denied at pre-check — only the blunt opaque
// pre-deny is relaxed, never real policy. This is the security invariant the
// whole interception-aware change depends on (issue #375).
func TestCheckCommand_DerivableDenyStillDeniedWhenExecveEnforced(t *testing.T) {
	e := newInterceptionTestEngine(t)
	dec := e.CheckCommandWithExecve("/bin/sh", []string{"-c", "shutdown now"}, true, ShellCOpaqueEnforce)
	if dec.PolicyDecision != types.DecisionDeny || dec.Rule != "deny-shutdown" {
		t.Fatalf("got %s rule=%q, want deny rule=deny-shutdown (derivable deny must survive execve relaxation)", dec.PolicyDecision, dec.Rule)
	}
}
