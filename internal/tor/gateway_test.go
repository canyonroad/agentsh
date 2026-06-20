package tor

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func gwPolicy(t *testing.T, rules []config.TorOnionRule) *Policy {
	t.Helper()
	p, err := New(config.ResolvedTorConfig{
		Enabled:    true,
		Mode:       ModeAllow,
		SocksPorts: []int{9050, 9150},
		Vectors:    config.ResolvedTorVectors{Processes: true, SocksPorts: true, Onion: true, RelayIPs: true},
		OnionRules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGatewayActive(t *testing.T) {
	if gwPolicy(t, nil).GatewayActive() {
		t.Error("no onion_rules → gateway inactive")
	}
	if !gwPolicy(t, []config.TorOnionRule{{Onion: "*", Decision: "deny"}}).GatewayActive() {
		t.Error("allow mode + onion_rules → gateway active")
	}
	// deny mode is never a gateway, even with rules.
	p, _ := New(config.ResolvedTorConfig{Enabled: true, Mode: ModeDeny, SocksPorts: []int{9050},
		OnionRules: []config.TorOnionRule{{Onion: "*", Decision: "deny"}}})
	if p.GatewayActive() {
		t.Error("deny mode must not activate gateway")
	}
}

func TestEvalSocksTarget(t *testing.T) {
	p := gwPolicy(t, []config.TorOnionRule{
		{Onion: "good.onion", Decision: "allow"},
		{Onion: "*.evil.onion", Decision: "deny"},
		{Onion: "*", Decision: "deny"},
	})
	cases := []struct {
		host    string
		wantDec string
	}{
		{"good.onion", "allow"},
		{"GOOD.onion", "allow"},  // case-insensitive
		{"x.evil.onion", "deny"}, // glob
		{"random.onion", "deny"}, // catch-all
		{"example.com", "deny"},  // clearnet via Tor, catch-all denies
	}
	for _, c := range cases {
		v, ok := p.EvalSocksTarget(c.host, 443)
		if !ok {
			t.Fatalf("%s: expected ok (gateway active)", c.host)
		}
		if v.Decision != c.wantDec {
			t.Errorf("%s: decision = %q, want %q", c.host, v.Decision, c.wantDec)
		}
		if v.Vector != VectorOnion {
			t.Errorf("%s: vector = %q, want onion", c.host, v.Vector)
		}
	}
}

func TestEvalSocksTarget_NoMatchFailsClosed(t *testing.T) {
	p := gwPolicy(t, []config.TorOnionRule{{Onion: "only.onion", Decision: "allow"}})
	v, ok := p.EvalSocksTarget("other.onion", 443)
	if !ok || v.Decision != "deny" {
		t.Fatalf("unmatched target must fail closed: ok=%v dec=%q", ok, v.Decision)
	}
}

func TestUpstreamSocksAddr(t *testing.T) {
	if got := gwPolicy(t, nil).UpstreamSocksAddr(); got != "127.0.0.1:9050" {
		t.Errorf("UpstreamSocksAddr = %q, want 127.0.0.1:9050", got)
	}
}
