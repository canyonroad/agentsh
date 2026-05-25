package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

func newWrapEnvTestApp(t *testing.T, enabled bool, p *policy.Policy) *App {
	t.Helper()
	eng, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cfg := &config.Config{}
	cfg.Sandbox.WrapEnvPolicy.Enabled = enabled
	return &App{cfg: cfg, policy: eng}
}

func TestWrapEnvPolicyWire_NilWhenDisabled(t *testing.T) {
	p := &policy.Policy{
		EnvPolicy:    policy.EnvPolicy{Deny: []string{"FOO"}},
		CommandRules: []policy.CommandRule{{Name: "allow-sh", Commands: []string{"sh"}, Decision: "allow"}},
	}
	a := newWrapEnvTestApp(t, false, p)
	if w := a.wrapEnvPolicyWire(nil, types.WrapInitRequest{AgentCommand: "/bin/sh", AgentArgs: []string{"-c", "echo hi"}}); w != nil {
		t.Errorf("flag off must yield nil wire; got %+v", w)
	}
}

func TestWrapEnvPolicyWire_PopulatedWhenEnabled(t *testing.T) {
	p := &policy.Policy{
		EnvPolicy:    policy.EnvPolicy{Deny: []string{"FOO"}},
		CommandRules: []policy.CommandRule{{Name: "allow-sh", Commands: []string{"sh"}, Decision: "allow"}},
	}
	a := newWrapEnvTestApp(t, true, p)
	w := a.wrapEnvPolicyWire(nil, types.WrapInitRequest{AgentCommand: "/bin/sh", AgentArgs: []string{"-c", "echo hi"}})
	if w == nil {
		t.Fatal("flag on must yield a non-nil wire")
	}
	found := false
	for _, d := range w.Deny {
		if d == "FOO" {
			found = true
		}
	}
	if !found {
		t.Errorf("wire.Deny should contain FOO from the resolved policy; got %v", w.Deny)
	}
}

// Fail-open: flag on but no policy engine available ⇒ nil wire (no filtering),
// rather than blocking the command. Security-relevant path. Issue #379.
func TestWrapEnvPolicyWire_NilWhenNoEngine(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.WrapEnvPolicy.Enabled = true
	a := &App{cfg: cfg, policy: nil} // policyEngineFor(nil) -> a.Policy() -> nil
	if w := a.wrapEnvPolicyWire(nil, types.WrapInitRequest{AgentCommand: "/bin/sh", AgentArgs: []string{"-c", "echo hi"}}); w != nil {
		t.Errorf("flag on but nil engine must yield nil wire (fail-open); got %+v", w)
	}
}
