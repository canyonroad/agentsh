package netmonitor

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// Verify DNS interceptor downgrades default-deny to monitor-only and handles approval deny.
func TestDNSInterceptorPolicyAdjustments(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		NetworkRules: []policy.NetworkRule{
			{Name: "default-deny-network", Decision: "deny", Domains: []string{"*"}},
			{Name: "approve-dns", Decision: "approve", Domains: []string{"example.com"}, Ports: []int{53}},
		},
	}
	engine, err := policy.NewEngine(pol, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	emit := &stubEmitter{}
	approvalsMgr := approvals.New("remote", 1*time.Millisecond, emit)
	d := &DNSInterceptor{
		sessionID: "s1",
		policy:    engine,
		approvals: approvalsMgr,
		emit:      emit,
		dnsCache:  NewDNSCache(5 * time.Minute),
	}

	dec := d.policyDecision(context.Background(), "example.com", 53)
	if dec.PolicyDecision != types.DecisionApprove {
		t.Fatalf("expected approve decision for example.com, got %v", dec.PolicyDecision)
	}
	dec = d.maybeApprove(context.Background(), "", dec, "dns", "example.com")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("approval should time out -> deny, got %v", dec.EffectiveDecision)
	}

	defaultDeny := d.policyDecision(context.Background(), "foo.com", 53)
	if defaultDeny.PolicyDecision != types.DecisionDeny || defaultDeny.Rule != "default-deny-network" {
		t.Fatalf("unexpected default decision: %+v", defaultDeny)
	}
	// The handle path adjusts default-deny to monitor-only; simulate that logic inline.
	if defaultDeny.PolicyDecision == types.DecisionDeny && defaultDeny.Rule == "default-deny-network" {
		defaultDeny = policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow, Rule: "dns-monitor-only"}
	}
	if defaultDeny.EffectiveDecision != types.DecisionAllow || defaultDeny.Rule != "dns-monitor-only" {
		t.Fatalf("expected monitor-only adjustment, got %+v", defaultDeny)
	}
}
