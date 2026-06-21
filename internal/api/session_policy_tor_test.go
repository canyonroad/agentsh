// internal/api/session_policy_tor_test.go
package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/tor"
)

func newDenyTorPolicy(t *testing.T) *tor.Policy {
	t.Helper()
	p, err := tor.New(config.ResolveTorConfig(config.TorConfig{Mode: "deny"}))
	if err != nil {
		t.Fatalf("tor.New: %v", err)
	}
	return p
}

// A per-session engine (distinct from the global one) must enforce Tor after
// attachSessionTor. We verify via dec.Tor != nil — that field is set only by
// the Tor checker path in CheckExecve, not by the regular command rules.
func TestAttachSessionTor_PerSessionEngineEnforcesTor(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	a := &App{torPolicy: newDenyTorPolicy(t), policy: global}

	sessionEng, err := policy.NewEngine(&policy.Policy{}, false, true)
	if err != nil {
		t.Fatalf("session engine: %v", err)
	}
	a.attachSessionTor(sessionEng)

	dec := sessionEng.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.Tor == nil {
		t.Fatalf("per-session engine should have Tor verdict set after attachSessionTor, got dec.Tor=nil (EffectiveDecision=%q)", dec.EffectiveDecision)
	}
	if dec.Tor.Decision != "deny" {
		t.Fatalf("per-session Tor verdict should be deny, got %q", dec.Tor.Decision)
	}
}

// The global engine must NOT be re-decorated (guard prevents racing shared state).
// The guard returns early when eng == a.Policy(), so no SetTorPolicy is called on
// the global engine. We confirm by checking dec.Tor == nil: any deny on the global
// engine comes from the default-deny-execve rule, not Tor policy.
func TestAttachSessionTor_SkipsGlobalEngine(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	a := &App{torPolicy: newDenyTorPolicy(t), policy: global}
	a.attachSessionTor(global) // same pointer as a.Policy()
	// dec.Tor is nil when Tor policy was NOT installed: any deny here is
	// the regular default-deny-execve rule, confirming the guard fired.
	dec := global.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.Tor != nil {
		t.Fatal("global engine must not be decorated by attachSessionTor: dec.Tor is non-nil")
	}
}
