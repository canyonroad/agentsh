//go:build linux
// +build linux

package netmonitor

import (
	"context"
	"net"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// Pure policy/netEvent helpers coverage; doesn't open sockets.
func TestTransparentTCPPolicyDecisionNilPolicyAllows(t *testing.T) {
	tcp := &TransparentTCP{}
	dec := tcp.policyDecision("example.com", net.ParseIP("1.1.1.1"), 80)
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("expected allow with nil policy, got %v", dec.EffectiveDecision)
	}
}

func TestTransparentTCPMaybeApproveWithoutManager(t *testing.T) {
	tcp := &TransparentTCP{}
	in := policy.Decision{PolicyDecision: types.DecisionApprove, EffectiveDecision: types.DecisionApprove}
	out := tcp.maybeApprove(context.Background(), "", in, "network", "t")
	if out.EffectiveDecision != types.DecisionApprove {
		t.Fatalf("expected unchanged decision without approvals manager")
	}
}

func TestTransparentTCPNetEventThreatMetadata(t *testing.T) {
	tcp := &TransparentTCP{sessionID: "test-session"}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionDeny,
		EffectiveDecision: types.DecisionDeny,
		Rule:              "threat-feed:urlhaus",
		ThreatFeed:        "urlhaus",
		ThreatMatch:       "evil.com",
		ThreatAction:      "deny",
	}
	ev := tcp.netEvent("net_connect", "cmd-1", "evil.com", "1.2.3.4:443", 443, dec, nil)
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

func TestTransparentTCPNetEventNoThreatMetadata(t *testing.T) {
	tcp := &TransparentTCP{sessionID: "test-session"}
	dec := policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
		Rule:              "allow-all",
	}
	ev := tcp.netEvent("net_connect", "cmd-1", "safe.com", "1.2.3.4:443", 443, dec, nil)
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
