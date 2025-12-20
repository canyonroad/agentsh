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
