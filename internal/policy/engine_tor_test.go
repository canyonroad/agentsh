package policy

import (
	"context"
	"net"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

type fakeTor struct {
	execve, connect, onion *TorVerdict
}

func (f *fakeTor) EvalExecve(string, []string) (TorVerdict, bool) {
	if f.execve == nil {
		return TorVerdict{}, false
	}
	return *f.execve, true
}
func (f *fakeTor) EvalConnect(net.IP, int) (TorVerdict, bool) {
	if f.connect == nil {
		return TorVerdict{}, false
	}
	return *f.connect, true
}
func (f *fakeTor) EvalOnionName(string) (TorVerdict, bool) {
	if f.onion == nil {
		return TorVerdict{}, false
	}
	return *f.onion, true
}

func newAllowAllEngine(t *testing.T) *Engine {
	t.Helper()
	// A policy that would ALLOW everything, so we can prove Tor overrides it.
	p := &Policy{
		NetworkRules: []NetworkRule{{Name: "allow-all", Ports: []int{9050}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "allow-all", Decision: "allow"}},
	}
	e, err := NewEngine(p, false, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestCheckExecve_TorDenyOverridesAllow(t *testing.T) {
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{execve: &TorVerdict{Vector: "process", Mode: "deny", Decision: "deny", Target: "/usr/bin/tor"}})
	dec := e.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision=%v, want deny", dec.EffectiveDecision)
	}
	if dec.Tor == nil || dec.Tor.Vector != "process" {
		t.Fatalf("dec.Tor missing/wrong: %+v", dec.Tor)
	}
}

func TestCheckNetworkIP_TorDenySocksPort(t *testing.T) {
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{connect: &TorVerdict{Vector: "socks_port", Mode: "deny", Decision: "deny", Target: "127.0.0.1:9050"}})
	dec := e.CheckNetworkIP("", net.ParseIP("127.0.0.1"), 9050)
	if dec.EffectiveDecision != types.DecisionDeny || dec.Tor == nil {
		t.Fatalf("want tor deny, got dec=%+v tor=%+v", dec.EffectiveDecision, dec.Tor)
	}
}

func TestCheckNetworkIP_TorAuditDoesNotLoosenUserDeny(t *testing.T) {
	// Policy denies by default (no matching rule for this IP/port).
	p := &Policy{NetworkRules: []NetworkRule{{Name: "deny-all", Decision: "deny"}}}
	e, _ := NewEngine(p, false, false)
	e.SetTorPolicy(&fakeTor{connect: &TorVerdict{Vector: "relay_ip", Mode: "audit", Decision: "audit", Target: "1.2.3.4:443"}})
	dec := e.CheckNetworkIP("", net.ParseIP("1.2.3.4"), 443)
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("audit must not loosen a deny; got %v", dec.EffectiveDecision)
	}
	if dec.Tor == nil || dec.Tor.Decision != "audit" {
		t.Fatalf("audit verdict must attach; got %+v", dec.Tor)
	}
}

func TestCheckNetworkCtx_TorOnionDeny(t *testing.T) {
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{onion: &TorVerdict{Vector: "onion_dns", Mode: "deny", Decision: "deny", Target: "x.onion"}})
	dec := e.CheckNetworkCtx(nil, "x.onion", 53)
	if dec.EffectiveDecision != types.DecisionDeny || dec.Tor == nil {
		t.Fatalf("want onion deny, got dec=%+v tor=%+v", dec.EffectiveDecision, dec.Tor)
	}
}

func TestCheckNetworkCtx_TorDenySocksPort_LivePath(t *testing.T) {
	// The ptrace connect path goes through CheckNetworkCtx with an IP-literal
	// domain — NOT CheckNetworkIP. This is the path that was Tor-blind.
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{connect: &TorVerdict{Vector: "socks_port", Mode: "deny", Decision: "deny", Target: "127.0.0.1:9050"}})
	dec := e.CheckNetworkCtx(context.Background(), "127.0.0.1", 9050)
	if dec.EffectiveDecision != types.DecisionDeny || dec.Tor == nil || dec.Tor.Vector != "socks_port" {
		t.Fatalf("want socks_port deny via CheckNetworkCtx, got dec=%+v tor=%+v", dec.EffectiveDecision, dec.Tor)
	}
}

func TestCheckNetworkCtx_TorDenyRelayIP_LivePath(t *testing.T) {
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{connect: &TorVerdict{Vector: "relay_ip", Mode: "deny", Decision: "deny", Target: "1.2.3.4:443"}})
	dec := e.CheckNetworkCtx(context.Background(), "1.2.3.4", 443)
	if dec.EffectiveDecision != types.DecisionDeny || dec.Tor == nil || dec.Tor.Vector != "relay_ip" {
		t.Fatalf("want relay_ip deny via CheckNetworkCtx, got dec=%+v tor=%+v", dec.EffectiveDecision, dec.Tor)
	}
}

func TestCheckNetworkCtx_TorAuditConnectAttachesOnAllow(t *testing.T) {
	// audit must attach .Tor without changing an allow, on the connect path.
	e := newAllowAllEngine(t) // allows port 9050
	e.SetTorPolicy(&fakeTor{connect: &TorVerdict{Vector: "relay_ip", Mode: "audit", Decision: "audit", Target: "1.2.3.4:9050"}})
	dec := e.CheckNetworkCtx(context.Background(), "1.2.3.4", 9050)
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("audit must not change allow; got %v", dec.EffectiveDecision)
	}
	if dec.Tor == nil || dec.Tor.Decision != "audit" {
		t.Fatalf("audit verdict must attach on connect-allow; got %+v", dec.Tor)
	}
}

func TestCheckNetworkCtx_TorOnionStillWorks(t *testing.T) {
	// Regression guard: the onion pre-check must still fire (the new connect
	// block must not shadow it for non-IP domains).
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{onion: &TorVerdict{Vector: "onion_dns", Mode: "deny", Decision: "deny", Target: "x.onion"}})
	dec := e.CheckNetworkCtx(context.Background(), "x.onion", 53)
	if dec.EffectiveDecision != types.DecisionDeny || dec.Tor == nil || dec.Tor.Vector != "onion_dns" {
		t.Fatalf("onion deny must still work, got dec=%+v tor=%+v", dec.EffectiveDecision, dec.Tor)
	}
}

func TestCheckNetworkIP_TorAuditAttachesOnAllow(t *testing.T) {
	// Audit verdict over an allow-all policy: decision stays allow, but the
	// verdict must ride along via the deferred attach (the common case).
	e := newAllowAllEngine(t)
	e.SetTorPolicy(&fakeTor{connect: &TorVerdict{Vector: "relay_ip", Mode: "audit", Decision: "audit", Target: "1.2.3.4:443"}})
	dec := e.CheckNetworkIP("", net.ParseIP("1.2.3.4"), 9050)
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("audit must not change an allow; got %v", dec.EffectiveDecision)
	}
	if dec.Tor == nil || dec.Tor.Decision != "audit" {
		t.Fatalf("audit verdict must attach on allow; got %+v", dec.Tor)
	}
}
