package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// Issue #377: `command -v NAME` must be allowed (introspection), not denied as
// shellc-wrapper-bypass, while `command shutdown` (no flag) still derives to
// shutdown so a deny rule fires.
func TestCheckCommand_CommandVAllowed(t *testing.T) {
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

	dec := e.CheckCommand("/bin/sh", []string{"-c", "command -v ls"})
	if dec.Rule == "shellc-wrapper-bypass" {
		t.Errorf("command -v ls denied as wrapper-bypass; want allow")
	}
	if dec.PolicyDecision != types.DecisionAllow {
		t.Errorf("command -v ls decision = %s (rule=%q), want allow", dec.PolicyDecision, dec.Rule)
	}

	decAssign := e.CheckCommand("/bin/sh", []string{"-c", "FOO=1 command -v ls"})
	if decAssign.PolicyDecision != types.DecisionAllow {
		t.Errorf("FOO=1 command -v ls decision = %s (rule=%q), want allow", decAssign.PolicyDecision, decAssign.Rule)
	}

	// The reported scenario: introspection on a deny-listed binary must still
	// be allowed — `command -v shutdown` checks existence, it does not run it.
	decVShutdown := e.CheckCommand("/bin/sh", []string{"-c", "command -v shutdown"})
	if decVShutdown.PolicyDecision != types.DecisionAllow {
		t.Errorf("command -v shutdown decision = %s (rule=%q), want allow", decVShutdown.PolicyDecision, decVShutdown.Rule)
	}

	// `command -V` (uppercase, verbose type) is also introspection → allowed.
	decBigV := e.CheckCommand("/bin/sh", []string{"-c", "command -V ls"})
	if decBigV.PolicyDecision != types.DecisionAllow {
		t.Errorf("command -V ls decision = %s (rule=%q), want allow", decBigV.PolicyDecision, decBigV.Rule)
	}

	denied := e.CheckCommand("/bin/sh", []string{"-c", "command shutdown"})
	if denied.PolicyDecision != types.DecisionDeny || denied.Rule != "deny-shutdown" {
		t.Errorf("command shutdown = %s rule=%q, want deny deny-shutdown", denied.PolicyDecision, denied.Rule)
	}
}
