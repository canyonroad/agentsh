package netmonitor

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/mcpregistry"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

type stubEmitter struct {
	events []types.Event
}

func (s *stubEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	s.events = append(s.events, ev)
	return nil
}
func (s *stubEmitter) Publish(ev types.Event) {
	s.events = append(s.events, ev)
}

func TestMustAtoi(t *testing.T) {
	if got := mustAtoi("123", 9); got != 123 {
		t.Fatalf("want 123, got %d", got)
	}
	if got := mustAtoi("abc", 7); got != 7 {
		t.Fatalf("non-numeric should return default, got %d", got)
	}
	if got := mustAtoi("0", 5); got != 5 {
		t.Fatalf("zero should return default, got %d", got)
	}
}

func TestResolveAndEmitDNSIPBypassesLookup(t *testing.T) {
	p := &Proxy{emit: &stubEmitter{}}
	ip := p.resolveAndEmitDNS(context.Background(), "cmd", "127.0.0.1")
	if ip != "127.0.0.1" {
		t.Fatalf("expected ip passthrough, got %q", ip)
	}
}

func TestMaybeApproveTimeoutDenies(t *testing.T) {
	em := &stubEmitter{}
	mgr := approvals.New("remote", 1*time.Millisecond, em) // remote mode skips prompt goroutine

	p := &Proxy{approvals: mgr}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
		Rule:              "r",
	}
	got := p.maybeApprove(context.Background(), "", dec, "network", "example.com")
	if got.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("expected deny when approval times out, got %v", got.EffectiveDecision)
	}
}

func TestMaybeApproveNoApprovalsLeavesDecision(t *testing.T) {
	p := &Proxy{approvals: nil}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionApprove,
	}
	got := p.maybeApprove(context.Background(), "", dec, "network", "example.com")
	if got.EffectiveDecision != types.DecisionApprove {
		t.Fatalf("expected unchanged decision when approvals manager missing, got %v", got.EffectiveDecision)
	}
}

func TestEmitConnectRedirectEvent(t *testing.T) {
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "test-session",
		emit:      em,
	}

	result := &policy.ConnectRedirectResult{
		Matched:    true,
		Rule:       "anthropic-redirect",
		RedirectTo: "vertex-proxy.internal:443",
		TLSMode:    "passthrough",
		Visibility: "audit_only",
		Message:    "Routed through Vertex",
	}

	p.emitConnectRedirectEvent(context.Background(), "cmd-123", "api.anthropic.com", "api.anthropic.com:443", 443, result)

	// Event should be emitted twice (AppendEvent + Publish)
	if len(em.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(em.events))
	}

	ev := em.events[0]
	if ev.Type != "connect_redirect" {
		t.Errorf("expected type 'connect_redirect', got %s", ev.Type)
	}
	if ev.SessionID != "test-session" {
		t.Errorf("expected sessionID 'test-session', got %s", ev.SessionID)
	}
	if ev.Domain != "api.anthropic.com" {
		t.Errorf("expected domain 'api.anthropic.com', got %s", ev.Domain)
	}
	if ev.Fields["redirect_to"] != "vertex-proxy.internal:443" {
		t.Errorf("expected redirect_to 'vertex-proxy.internal:443', got %v", ev.Fields["redirect_to"])
	}
	if ev.Fields["tls_mode"] != "passthrough" {
		t.Errorf("expected tls_mode 'passthrough', got %v", ev.Fields["tls_mode"])
	}
}

func TestEmitConnectRedirectEventWithSNI(t *testing.T) {
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "test-session",
		emit:      em,
	}

	result := &policy.ConnectRedirectResult{
		Matched:    true,
		Rule:       "sni-rewrite",
		RedirectTo: "vertex-proxy.internal:443",
		TLSMode:    "rewrite_sni",
		SNI:        "vertex-proxy.internal",
		Visibility: "audit_only",
		Message:    "SNI rewritten",
	}

	p.emitConnectRedirectEvent(context.Background(), "cmd-456", "api.openai.com", "api.openai.com:443", 443, result)

	if len(em.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(em.events))
	}

	ev := em.events[0]
	if ev.Fields["sni"] != "vertex-proxy.internal" {
		t.Errorf("expected sni 'vertex-proxy.internal', got %v", ev.Fields["sni"])
	}
	if ev.Fields["tls_mode"] != "rewrite_sni" {
		t.Errorf("expected tls_mode 'rewrite_sni', got %v", ev.Fields["tls_mode"])
	}
}

func TestEmitConnectRedirectEventNilEmitter(t *testing.T) {
	p := &Proxy{
		sessionID: "test-session",
		emit:      nil,
	}

	result := &policy.ConnectRedirectResult{
		Matched:    true,
		Rule:       "test",
		RedirectTo: "proxy:443",
	}

	// Should not panic
	p.emitConnectRedirectEvent(context.Background(), "cmd", "example.com", "example.com:443", 443, result)
}

func newSessionWithRegistry(addrs map[string]string) *session.Session {
	sess := &session.Session{ID: "test-session"}
	reg := mcpregistry.NewRegistry()
	for addr, serverID := range addrs {
		reg.Register(serverID, "http", addr, nil)
	}
	sess.SetMCPRegistry(reg)
	return sess
}

func TestMCPConnectionTaggingMatchesDomain(t *testing.T) {
	em := &stubEmitter{}
	sess := newSessionWithRegistry(map[string]string{
		"mcp.example.com:443": "test-server",
	})

	emitMCPConnectionIfMatched(context.Background(), sess, em, "test-session", "cmd-1", "MCP.Example.Com", "mcp.example.com:443", 443)

	var mcpEvents []types.Event
	for _, ev := range em.events {
		if ev.Type == "mcp_network_connection" {
			mcpEvents = append(mcpEvents, ev)
		}
	}
	if len(mcpEvents) != 2 { // AppendEvent + Publish
		t.Fatalf("expected 2 mcp_network_connection events, got %d", len(mcpEvents))
	}
	ev := mcpEvents[0]
	if ev.Domain != "mcp.example.com" {
		t.Errorf("expected lowercased domain 'mcp.example.com', got %q", ev.Domain)
	}
	if ev.Fields["server_id"] != "test-server" {
		t.Errorf("expected server_id 'test-server', got %v", ev.Fields["server_id"])
	}
	if ev.SessionID != "test-session" {
		t.Errorf("expected sessionID 'test-session', got %q", ev.SessionID)
	}
	if ev.CommandID != "cmd-1" {
		t.Errorf("expected commandID 'cmd-1', got %q", ev.CommandID)
	}
}

func TestMCPConnectionTaggingMatchesRemote(t *testing.T) {
	em := &stubEmitter{}
	sess := newSessionWithRegistry(map[string]string{
		"192.168.1.10:8080": "ip-server",
	})

	// domain won't match, but remote (IP:port) should
	emitMCPConnectionIfMatched(context.Background(), sess, em, "test-session", "cmd-2", "some-host", "192.168.1.10:8080", 8080)

	var mcpEvents []types.Event
	for _, ev := range em.events {
		if ev.Type == "mcp_network_connection" {
			mcpEvents = append(mcpEvents, ev)
		}
	}
	if len(mcpEvents) != 2 {
		t.Fatalf("expected 2 mcp_network_connection events, got %d", len(mcpEvents))
	}
	if mcpEvents[0].Fields["server_id"] != "ip-server" {
		t.Errorf("expected server_id 'ip-server', got %v", mcpEvents[0].Fields["server_id"])
	}
}

func TestMCPConnectionTaggingNoMatchSkips(t *testing.T) {
	em := &stubEmitter{}
	sess := newSessionWithRegistry(map[string]string{
		"mcp.example.com:443": "test-server",
	})

	emitMCPConnectionIfMatched(context.Background(), sess, em, "test-session", "cmd-3", "other.com", "other.com:443", 443)

	for _, ev := range em.events {
		if ev.Type == "mcp_network_connection" {
			t.Fatal("unexpected mcp_network_connection event for unregistered address")
		}
	}
}

func TestMCPConnectionTaggingNilSession(t *testing.T) {
	em := &stubEmitter{}

	// Should not panic
	emitMCPConnectionIfMatched(context.Background(), nil, em, "test-session", "cmd", "example.com", "example.com:443", 443)

	if len(em.events) != 0 {
		t.Fatalf("expected 0 events with nil session, got %d", len(em.events))
	}
}

func TestMCPConnectionTaggingNoRegistry(t *testing.T) {
	em := &stubEmitter{}
	sess := &session.Session{ID: "test-session"}
	// Don't set registry

	// Should not panic, no events emitted
	emitMCPConnectionIfMatched(context.Background(), sess, em, "test-session", "cmd", "example.com", "example.com:443", 443)

	if len(em.events) != 0 {
		t.Fatalf("expected 0 events with no registry, got %d", len(em.events))
	}
}

func TestProxyEmitNetEventThreatMetadata(t *testing.T) {
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "test-session",
		emit:      em,
	}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionDeny,
		EffectiveDecision: types.DecisionDeny,
		Rule:              "threat-feed:urlhaus",
		ThreatFeed:        "urlhaus",
		ThreatMatch:       "evil.com",
		ThreatAction:      "deny",
	}
	ev := p.emitNetEvent(context.Background(), "net_connect", "cmd-1", "evil.com", "1.2.3.4:443", 443, dec, nil)
	if ev.Policy == nil {
		t.Fatal("expected Policy to be set")
	}
	if ev.Policy.ThreatFeed != "urlhaus" {
		t.Errorf("expected ThreatFeed %q, got %q", "urlhaus", ev.Policy.ThreatFeed)
	}
	if ev.Policy.ThreatMatch != "evil.com" {
		t.Errorf("expected ThreatMatch %q, got %q", "evil.com", ev.Policy.ThreatMatch)
	}
	if ev.Policy.ThreatAction != "deny" {
		t.Errorf("expected ThreatAction %q, got %q", "deny", ev.Policy.ThreatAction)
	}
}

func TestProxyEmitNetEventNoThreatMetadata(t *testing.T) {
	em := &stubEmitter{}
	p := &Proxy{
		sessionID: "test-session",
		emit:      em,
	}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
		Rule:              "allow-all",
	}
	ev := p.emitNetEvent(context.Background(), "net_connect", "cmd-1", "safe.com", "1.2.3.4:443", 443, dec, nil)
	if ev.Policy == nil {
		t.Fatal("expected Policy to be set")
	}
	if ev.Policy.ThreatFeed != "" {
		t.Errorf("expected empty ThreatFeed, got %q", ev.Policy.ThreatFeed)
	}
	if ev.Policy.ThreatAction != "" {
		t.Errorf("expected empty ThreatAction, got %q", ev.Policy.ThreatAction)
	}
}

func TestMCPConnectionTaggingNilEmitter(t *testing.T) {
	sess := newSessionWithRegistry(map[string]string{
		"mcp.example.com:443": "test-server",
	})

	// Should not panic with nil emitter
	emitMCPConnectionIfMatched(context.Background(), sess, nil, "test-session", "cmd", "mcp.example.com", "mcp.example.com:443", 443)
}
