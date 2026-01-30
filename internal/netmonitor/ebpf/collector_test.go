//go:build linux

package ebpf

import (
	"net"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/netmonitor/redirect"
	"github.com/agentsh/agentsh/internal/policy"
)

func TestCopyToEventBounds(t *testing.T) {
	var ev ConnectEvent
	data := make([]byte, 48)
	copyToEvent(&ev, data)
}

func TestExtractDstIP_IPv4(t *testing.T) {
	c := &Collector{}
	ev := &ConnectEvent{
		Family:  2, // AF_INET
		DstIPv4: 0x0100007f, // 127.0.0.1 in little-endian
	}

	ip := c.extractDstIP(ev)
	if ip == nil {
		t.Fatal("expected IP, got nil")
	}
	expected := net.ParseIP("127.0.0.1").To4()
	if !ip.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ip)
	}
}

func TestExtractDstIP_IPv6(t *testing.T) {
	c := &Collector{}
	// IPv6 loopback ::1
	var ipv6 [16]byte
	ipv6[15] = 1
	ev := &ConnectEvent{
		Family:  10, // AF_INET6
		DstIPv6: ipv6,
	}

	ip := c.extractDstIP(ev)
	if ip == nil {
		t.Fatal("expected IP, got nil")
	}
	expected := net.ParseIP("::1")
	if !ip.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ip)
	}
}

func TestExtractDstIP_UnknownFamily(t *testing.T) {
	c := &Collector{}
	ev := &ConnectEvent{
		Family: 99, // Unknown family
	}

	ip := c.extractDstIP(ev)
	if ip != nil {
		t.Errorf("expected nil for unknown family, got %v", ip)
	}
}

func TestEvaluateConnectRedirect_NoEngine(t *testing.T) {
	c := &Collector{}
	ev := &ConnectEvent{
		Family:  2,
		DstIPv4: 0x0100007f,
		Dport:   443,
	}

	// Should not panic when engine is nil
	c.evaluateConnectRedirect(ev)
}

func TestEvaluateConnectRedirect_NoCallback(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "test-rule",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
			},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	c := &Collector{}
	c.SetPolicyEngine(engine)
	// onRedirect callback not set

	ev := &ConnectEvent{
		Family:  2,
		DstIPv4: 0x0100007f,
		Dport:   443,
	}

	// Should not panic when callback is nil
	c.evaluateConnectRedirect(ev)
}

func TestEvaluateConnectRedirect_MatchingRule(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "anthropic-redirect",
				Match:      "api\\.anthropic\\.com:443",
				RedirectTo: "vertex-proxy:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "passthrough"},
				Visibility: "audit_only",
				Message:    "Routed through Vertex",
			},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	corrMap := redirect.NewCorrelationMap(5 * time.Minute)
	// Simulate DNS lookup: api.anthropic.com resolved to 140.82.114.4
	corrMap.AddResolution("api.anthropic.com", []net.IP{net.ParseIP("140.82.114.4")})

	var receivedEvent *events.ConnectRedirectEvent
	c := &Collector{}
	c.SetPolicyEngine(engine)
	c.SetCorrelationMap(corrMap)
	c.SetOnRedirect(func(ev *events.ConnectRedirectEvent) {
		receivedEvent = ev
	})

	// Create event with IP that maps to api.anthropic.com (140.82.114.4 = 0x0472528c in little-endian)
	ev := &ConnectEvent{
		Family:  2,
		DstIPv4: 0x0472528c,
		Dport:   443,
	}

	c.evaluateConnectRedirect(ev)

	if receivedEvent == nil {
		t.Fatal("expected redirect event, got nil")
	}
	if receivedEvent.Rule != "anthropic-redirect" {
		t.Errorf("expected rule 'anthropic-redirect', got %s", receivedEvent.Rule)
	}
	if receivedEvent.RedirectedTo != "vertex-proxy:443" {
		t.Errorf("expected redirect to 'vertex-proxy:443', got %s", receivedEvent.RedirectedTo)
	}
	if receivedEvent.TLSMode != "passthrough" {
		t.Errorf("expected TLS mode 'passthrough', got %s", receivedEvent.TLSMode)
	}
	if receivedEvent.Visibility != "audit_only" {
		t.Errorf("expected visibility 'audit_only', got %s", receivedEvent.Visibility)
	}
}

func TestEvaluateConnectRedirect_NoMatch(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "anthropic-redirect",
				Match:      "api\\.anthropic\\.com:443",
				RedirectTo: "vertex-proxy:443",
			},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	var callCount int
	c := &Collector{}
	c.SetPolicyEngine(engine)
	c.SetOnRedirect(func(ev *events.ConnectRedirectEvent) {
		callCount++
	})

	// Non-matching destination (127.0.0.1:443)
	ev := &ConnectEvent{
		Family:  2,
		DstIPv4: 0x0100007f,
		Dport:   443,
	}

	c.evaluateConnectRedirect(ev)

	if callCount != 0 {
		t.Errorf("expected no callback for non-matching rule, got %d calls", callCount)
	}
}

func TestEvaluateConnectRedirect_WithoutCorrelationMap(t *testing.T) {
	// Test that IP address is used as hostname when correlation map is not set
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "ip-redirect",
				Match:      "10\\.0\\.0\\.1:443",
				RedirectTo: "proxy:443",
			},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	var receivedEvent *events.ConnectRedirectEvent
	c := &Collector{}
	c.SetPolicyEngine(engine)
	// No correlation map set
	c.SetOnRedirect(func(ev *events.ConnectRedirectEvent) {
		receivedEvent = ev
	})

	// 10.0.0.1 = 0x0100000a in little-endian
	ev := &ConnectEvent{
		Family:  2,
		DstIPv4: 0x0100000a,
		Dport:   443,
	}

	c.evaluateConnectRedirect(ev)

	if receivedEvent == nil {
		t.Fatal("expected redirect event, got nil")
	}
	if receivedEvent.Original != "10.0.0.1:443" {
		t.Errorf("expected original '10.0.0.1:443', got %s", receivedEvent.Original)
	}
}

func TestEvaluateConnectRedirect_SNIRewrite(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "sni-rewrite-rule",
				Match:      "api\\.openai\\.com:443",
				RedirectTo: "vertex-proxy:443",
				TLS: &policy.ConnectRedirectTLSConfig{
					Mode: "rewrite_sni",
					SNI:  "vertex-proxy.internal",
				},
			},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	corrMap := redirect.NewCorrelationMap(5 * time.Minute)
	corrMap.AddResolution("api.openai.com", []net.IP{net.ParseIP("104.18.7.192")})

	var receivedEvent *events.ConnectRedirectEvent
	c := &Collector{}
	c.SetPolicyEngine(engine)
	c.SetCorrelationMap(corrMap)
	c.SetOnRedirect(func(ev *events.ConnectRedirectEvent) {
		receivedEvent = ev
	})

	// 104.18.7.192 = 0xc00712068 in little-endian
	ev := &ConnectEvent{
		Family:  2,
		DstIPv4: 0xc0071268,
		Dport:   443,
	}

	c.evaluateConnectRedirect(ev)

	if receivedEvent == nil {
		t.Fatal("expected redirect event, got nil")
	}
	if receivedEvent.TLSMode != "rewrite_sni" {
		t.Errorf("expected TLS mode 'rewrite_sni', got %s", receivedEvent.TLSMode)
	}
}
