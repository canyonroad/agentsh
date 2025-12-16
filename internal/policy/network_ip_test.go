package policy

import (
	"net"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestEngine_CheckNetworkIP_MatchesDomainAndCIDR(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		NetworkRules: []NetworkRule{
			{Name: "allow-example", Domains: []string{"example.com"}, Ports: []int{443}, Decision: "allow"},
			{Name: "deny-private", CIDRs: []string{"10.0.0.0/8"}, Decision: "deny"},
			{Name: "default", Domains: []string{"*"}, Decision: "deny"},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	dec := e.CheckNetworkIP("example.com", net.ParseIP("93.184.216.34"), 443)
	if dec.EffectiveDecision != types.DecisionAllow || dec.Rule != "allow-example" {
		t.Fatalf("expected allow-example, got %+v", dec)
	}

	dec = e.CheckNetworkIP("", net.ParseIP("10.0.0.1"), 443)
	if dec.EffectiveDecision != types.DecisionDeny || dec.Rule != "deny-private" {
		t.Fatalf("expected deny-private, got %+v", dec)
	}
}
