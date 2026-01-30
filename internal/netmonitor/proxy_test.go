package netmonitor

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
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
