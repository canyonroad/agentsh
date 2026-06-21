// internal/api/tor_failclosed_test.go
package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/tor"
)

func TestGatewayBranchFor(t *testing.T) {
	cases := []struct {
		active, up bool
		want       gatewayBranch
	}{
		{false, false, gatewayNone},
		{false, true, gatewayNone},
		{true, true, gatewayForceRedirect},
		{true, false, gatewayFailClosed},
	}
	for _, c := range cases {
		if got := gatewayBranchFor(c.active, c.up); got != c.want {
			t.Fatalf("gatewayBranchFor(%v,%v)=%v want %v", c.active, c.up, got, c.want)
		}
	}
}

// Default-engine session: attachDenyTor must give it a NEW per-session engine
// that denies Tor, without mutating the shared global engine.
func TestAttachDenyTor_DefaultEngine_ClonesAndDenies(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{}, false, true)
	if err != nil {
		t.Fatalf("global: %v", err)
	}
	a := &App{policy: global, cfg: &config.Config{}}
	deny, _ := tor.New(config.ResolveTorConfig(config.TorConfig{Mode: "deny"}))

	s := &session.Session{} // PolicyEngine() == nil -> policyEngineFor returns global
	ok := a.attachDenyTor(s, deny)
	if !ok {
		t.Fatal("attachDenyTor should succeed")
	}
	if s.PolicyEngine() == nil || s.PolicyEngine() == global {
		t.Fatal("session must get its own cloned engine, not the global one")
	}
	// Use dec.Tor as discriminator (NOT dec.Action — the default-deny-execve rule
	// makes Action=="deny" for any binary; only Tor checker sets dec.Tor).
	if dec := s.PolicyEngine().CheckExecve("/usr/bin/tor", []string{"tor"}, 0); dec.Tor == nil || dec.Tor.Decision != "deny" {
		t.Fatalf("session engine should have Tor deny verdict, got dec.Tor=%v", dec.Tor)
	}
	// Global must remain undecorated: dec.Tor nil means no Tor policy was installed.
	if dec := global.CheckExecve("/usr/bin/tor", []string{"tor"}, 0); dec.Tor != nil {
		t.Fatal("global engine must remain undecorated: dec.Tor is non-nil")
	}
}
