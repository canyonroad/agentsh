package tor

import (
	"net"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/ipset"
)

func newDenyPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := New(config.ResolveTorConfig(config.TorConfig{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestPolicy_EvalExecve_DenyTorBinary(t *testing.T) {
	p := newDenyPolicy(t)
	v, ok := p.EvalExecve("/usr/bin/tor", []string{"tor"})
	if !ok || v.Vector != "process" || v.Decision != "deny" {
		t.Fatalf("got ok=%v verdict=%+v, want deny/process", ok, v)
	}
	v, ok = p.EvalExecve("/usr/bin/torsocks", []string{"torsocks", "curl"})
	if !ok || v.Decision != "deny" {
		t.Fatalf("torsocks should be denied: ok=%v v=%+v", ok, v)
	}
	if _, ok := p.EvalExecve("/usr/bin/curl", []string{"curl"}); ok {
		t.Fatal("curl must not be a Tor match")
	}
}

func TestPolicy_EvalConnect_SocksPortLoopback(t *testing.T) {
	p := newDenyPolicy(t)
	v, ok := p.EvalConnect(net.ParseIP("127.0.0.1"), 9050)
	if !ok || v.Vector != "socks_port" || v.Decision != "deny" {
		t.Fatalf("loopback :9050 should deny: ok=%v v=%+v", ok, v)
	}
	// Default socks_loopback_only=true: non-loopback :9050 is not Tor.
	if _, ok := p.EvalConnect(net.ParseIP("203.0.113.7"), 9050); ok {
		t.Fatal("non-loopback :9050 must not match when loopback_only")
	}
}

func TestPolicy_EvalConnect_RelaySeedIP(t *testing.T) {
	p := newDenyPolicy(t)
	v, ok := p.EvalConnect(net.ParseIP("128.31.0.39"), 443) // moria1 authority
	if !ok || v.Vector != "relay_ip" || v.Decision != "deny" {
		t.Fatalf("authority IP should deny: ok=%v v=%+v", ok, v)
	}
	if _, ok := p.EvalConnect(net.ParseIP("1.1.1.1"), 443); ok {
		t.Fatal("non-relay IP must not match")
	}
}

func TestPolicy_EvalOnionName(t *testing.T) {
	p := newDenyPolicy(t)
	v, ok := p.EvalOnionName("abcdefghij234567.onion")
	if !ok || v.Vector != "onion_dns" || v.Decision != "deny" {
		t.Fatalf(".onion should deny: ok=%v v=%+v", ok, v)
	}
	if _, ok := p.EvalOnionName("example.com"); ok {
		t.Fatal("clearnet host must not match")
	}
}

func TestPolicy_AuditMode(t *testing.T) {
	tr := true
	p, _ := New(config.ResolveTorConfig(config.TorConfig{Enabled: &tr, Mode: "audit"}))
	v, ok := p.EvalExecve("/usr/bin/tor", []string{"tor"})
	if !ok || v.Decision != "audit" {
		t.Fatalf("audit mode must report audit: ok=%v v=%+v", ok, v)
	}
}

func TestPolicy_AllowMode_NoMatches(t *testing.T) {
	tr := true
	p, _ := New(config.ResolveTorConfig(config.TorConfig{Enabled: &tr, Mode: "allow"}))
	if _, ok := p.EvalExecve("/usr/bin/tor", []string{"tor"}); ok {
		t.Fatal("allow mode: Tor vectors must be no-ops")
	}
	if _, ok := p.EvalConnect(net.ParseIP("127.0.0.1"), 9050); ok {
		t.Fatal("allow mode: connect must be a no-op")
	}
}

func TestPolicy_DisabledVector(t *testing.T) {
	tr, f := true, false
	p, _ := New(config.ResolveTorConfig(config.TorConfig{
		Enabled: &tr,
		Vectors: config.TorVectors{Processes: &f},
	}))
	if _, ok := p.EvalExecve("/usr/bin/tor", []string{"tor"}); ok {
		t.Fatal("processes vector disabled: must not match")
	}
	// other vectors still active
	if _, ok := p.EvalOnionName("x.onion"); !ok {
		t.Fatal("onion_dns still enabled: should match")
	}
}

func TestPolicy_EvalConnect_ControlPort(t *testing.T) {
	p := newDenyPolicy(t)
	v, ok := p.EvalConnect(net.ParseIP("127.0.0.1"), 9051) // default control port
	if !ok || v.Vector != "socks_port" || v.Decision != "deny" {
		t.Fatalf("loopback :9051 control port should deny: ok=%v v=%+v", ok, v)
	}
}

func TestPolicy_EvalOnionName_Normalization(t *testing.T) {
	p := newDenyPolicy(t)
	for _, host := range []string{"ABCDEF.onion", "abcdef.onion.", "  abc.onion  ", "onion"} {
		if _, ok := p.EvalOnionName(host); !ok {
			t.Fatalf("expected %q to match after normalization", host)
		}
	}
	for _, host := range []string{"notonion", "foo.onionx", "onion.com"} {
		if _, ok := p.EvalOnionName(host); ok {
			t.Fatalf("did not expect %q to match", host)
		}
	}
}

func TestPolicy_OnionVectorDisabled(t *testing.T) {
	tr, f := true, false
	p, _ := New(config.ResolveTorConfig(config.TorConfig{Enabled: &tr, Vectors: config.TorVectors{Onion: &f}}))
	if _, ok := p.EvalOnionName("x.onion"); ok {
		t.Fatal("onion vector disabled: .onion must not match")
	}
	// other vectors unaffected
	if _, ok := p.EvalConnect(net.ParseIP("127.0.0.1"), 9050); !ok {
		t.Fatal("socks_port vector should still match")
	}
}

func TestPolicy_EvalExecve_PathAndGlob(t *testing.T) {
	tr := true
	p, _ := New(config.ResolveTorConfig(config.TorConfig{
		Enabled:        &tr,
		ClientBinaries: []string{"tor", "/opt/tor/bin/torbrowser", "obfs*"},
	}))
	// exact basename still works
	if _, ok := p.EvalExecve("/usr/bin/tor", []string{"tor"}); !ok {
		t.Fatal("exact basename must match")
	}
	// full-path entry matches the full path
	if _, ok := p.EvalExecve("/opt/tor/bin/torbrowser", []string{"torbrowser"}); !ok {
		t.Fatal("full-path client_binary entry must match")
	}
	// glob matches the basename
	if _, ok := p.EvalExecve("/usr/bin/obfs4proxy", []string{"obfs4proxy"}); !ok {
		t.Fatal("glob client_binary entry must match basename")
	}
	// non-Tor stays unmatched
	if _, ok := p.EvalExecve("/usr/bin/curl", []string{"curl"}); ok {
		t.Fatal("curl must not match")
	}
}

func TestPolicy_SetRelays_HotSwapMatch(t *testing.T) {
	p := newDenyPolicy(t)
	// A non-seed public IP is initially not a relay.
	ip := net.ParseIP("203.0.113.50")
	if _, ok := p.EvalConnect(ip, 443); ok {
		t.Fatal("IP should not match before feed swap")
	}
	// Swap in a relay set containing it; the next Eval must see it.
	s := ipset.New()
	if err := s.Add("203.0.113.0/24"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	p.SetRelays(s)
	v, ok := p.EvalConnect(ip, 443)
	if !ok || v.Vector != "relay_ip" || v.Decision != "deny" {
		t.Fatalf("post-swap relay match failed: ok=%v v=%+v", ok, v)
	}
}
