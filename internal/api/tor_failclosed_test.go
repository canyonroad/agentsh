// internal/api/tor_failclosed_test.go
package api

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
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

// newGatewayActiveTorPolicy returns an allow-mode Tor policy with an onion rule
// so that GatewayActive() returns true (Enabled + ModeAllow + onion_rules set).
// ClientBinaries and Vectors.Processes are populated so the DenyModeClone
// produced by applyTorFailClosed will match /usr/bin/tor via EvalExecve.
func newGatewayActiveTorPolicy(t *testing.T) *tor.Policy {
	t.Helper()
	p, err := tor.New(config.ResolvedTorConfig{
		Enabled:        true,
		Mode:           tor.ModeAllow,
		SocksPorts:     []int{9050},
		ClientBinaries: []string{"tor"},
		Vectors:        config.ResolvedTorVectors{Processes: true},
		OnionRules:     []config.TorOnionRule{{Onion: "*", Decision: "allow"}},
	})
	if err != nil {
		t.Fatalf("tor.New gateway-active: %v", err)
	}
	if !p.GatewayActive() {
		t.Fatal("test setup error: GatewayActive() is false; check TorConfig")
	}
	return p
}

// TestApplyTorFailClosed_ProfileSession verifies that a session whose gateway is
// active (allow-mode + onion_rules) but has no interceptor running (profile
// sessions never wire the transparent interceptor) receives a deny-mode Tor
// policy clone. This is the regression test for the profile-path fail-open fixed
// in createSessionWithProfile by inserting applyTorFailClosed(ctx, s, false).
//
// Coverage note: we cannot instantiate a full profile session (createSessionWithProfile
// requires a mounted filesystem, a loaded profile config, a TOTP key store, and a
// working store/broker — heavyweight infrastructure not available in a unit test).
// The fix is a one-line wiring call at the exit of createSessionWithProfile; the
// deny behaviour itself is already covered by TestAttachDenyTor_DefaultEngine_ClonesAndDenies
// and TestAttachSessionTor_PerSessionEngineEnforcesTor. This test confirms
// applyTorFailClosed(ctx, s, false) performs the wiring when interceptorUp=false
// (the invariant that holds for every profile session).
func TestApplyTorFailClosed_ProfileSession_DeniesTor(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	st := composite.New(memEventStore{}, nil)
	br := events.NewBroker()
	a := &App{
		torPolicy: newGatewayActiveTorPolicy(t),
		policy:    global,
		cfg:       &config.Config{},
		store:     st,
		broker:    br,
	}

	s := &session.Session{}
	// interceptorUp=false mirrors the profile-session path: the transparent
	// interceptor is never brought up in createSessionWithProfile.
	a.applyTorFailClosed(context.Background(), s, false)

	// The session must now have its own cloned engine with a deny Tor policy.
	eng := s.PolicyEngine()
	if eng == nil {
		t.Fatal("session engine is nil after applyTorFailClosed: deny policy was not attached")
	}
	if eng == global {
		t.Fatal("session must receive its own cloned engine, not the shared global engine")
	}
	// Use dec.Tor as discriminator (NOT dec.Action — the default-deny-execve rule
	// makes Action=="deny" for any binary; only the Tor checker path sets dec.Tor).
	dec := eng.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.Tor == nil {
		t.Fatalf("dec.Tor is nil: Tor policy was not installed on the session engine")
	}
	if dec.Tor.Decision != "deny" {
		t.Fatalf("expected dec.Tor.Decision=deny, got %q", dec.Tor.Decision)
	}
	// Global engine must remain undecorated.
	if gdec := global.CheckExecve("/usr/bin/tor", []string{"tor"}, 0); gdec.Tor != nil {
		t.Fatal("global engine must remain undecorated after applyTorFailClosed")
	}
}
