//go:build linux
// +build linux

package netmonitor

import (
	"context"
	"net"
	"path/filepath"
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

func TestTransparentTCPCheckConnectNetwork_DBUnixRedirectBypassesGeneratedDeny(t *testing.T) {
	engine := newTransparentDBRedirectEngine(t, true)
	redirect := engine.EvaluateConnectRedirect("db.internal:5432")
	if !redirect.Matched || redirect.RedirectToUnix == "" {
		t.Fatalf("EvaluateConnectRedirect = %+v", redirect)
	}

	tcp := &TransparentTCP{policy: engine}
	dec := tcp.checkConnectNetwork(context.Background(), "", "db.internal", "db.internal:5432", net.ParseIP("10.0.0.15"), 5432, redirect)
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("EffectiveDecision = %v, want allow", dec.EffectiveDecision)
	}
	if dec.Rule != "db-unix-redirect" {
		t.Fatalf("Rule = %q, want redirect rule", dec.Rule)
	}
}

func TestTransparentTCPCheckConnectNetwork_RequiresDBRedirectMetadata(t *testing.T) {
	engine := newTransparentDBRedirectEngine(t, false)
	redirect := engine.EvaluateConnectRedirect("db.internal:5432")
	if !redirect.Matched || redirect.RedirectToUnix == "" {
		t.Fatalf("EvaluateConnectRedirect = %+v", redirect)
	}

	tcp := &TransparentTCP{policy: engine}
	dec := tcp.checkConnectNetwork(context.Background(), "", "db.internal", "db.internal:5432", net.ParseIP("10.0.0.15"), 5432, redirect)
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %v, want deny", dec.EffectiveDecision)
	}
	if dec.Rule != "deny-db-direct" {
		t.Fatalf("Rule = %q, want deny rule", dec.Rule)
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

func newTransparentDBRedirectEngine(t *testing.T, includeRedirectMetadata bool) *policy.Engine {
	t.Helper()

	metadata := []policy.RuleMetadata{
		{
			RuleName:   "deny-db-direct",
			Source:     "db_unavoidability",
			BypassMode: "tcp_direct",
		},
	}
	if includeRedirectMetadata {
		metadata = append(metadata, policy.RuleMetadata{
			RuleName:   "db-unix-redirect",
			Source:     "db_unavoidability",
			BypassMode: "tcp_direct",
		})
	}

	pol := &policy.Policy{
		Version:  1,
		Metadata: metadata,
		NetworkRules: []policy.NetworkRule{
			{Name: "deny-db-direct", Decision: "deny", Domains: []string{"db.internal"}, Ports: []int{5432}},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:           "db-unix-redirect",
				Match:          `^db\.internal:5432$`,
				RedirectToUnix: filepath.Join(t.TempDir(), "agentsh-db.sock"),
				Visibility:     "audit_only",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}
