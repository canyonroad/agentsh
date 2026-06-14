package tor_test

import (
	"context"
	"net"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/tor"
	"github.com/agentsh/agentsh/pkg/types"
)

func denyEngine(t *testing.T) *policy.Engine {
	t.Helper()
	// Minimal allow-all policy so any deny we see comes from Tor.
	p := &policy.Policy{
		CommandRules: []policy.CommandRule{{Name: "allow-all", Decision: "allow"}},
		NetworkRules: []policy.NetworkRule{{Name: "allow-all", Decision: "allow"}},
	}
	e, err := policy.NewEngine(p, false, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	tp, _ := tor.New(config.ResolveTorConfig(config.TorConfig{}))
	e.SetTorPolicy(&tor.PolicyAdapter{Policy: tp})
	return e
}

func TestE2E_TorBlocksAllVectors(t *testing.T) {
	e := denyEngine(t)

	if d := e.CheckExecve("/usr/bin/tor", []string{"tor"}, 0); d.EffectiveDecision != types.DecisionDeny || d.Tor == nil {
		t.Fatalf("process vector: %+v", d)
	}
	if d := e.CheckNetworkIP("", net.ParseIP("127.0.0.1"), 9050); d.EffectiveDecision != types.DecisionDeny || d.Tor == nil {
		t.Fatalf("socks_port vector: %+v", d)
	}
	if d := e.CheckNetworkIP("", net.ParseIP("128.31.0.39"), 443); d.EffectiveDecision != types.DecisionDeny || d.Tor == nil {
		t.Fatalf("relay_ip vector: %+v", d)
	}
	if d := e.CheckNetworkCtx(nil, "abc.onion", 53); d.EffectiveDecision != types.DecisionDeny || d.Tor == nil {
		t.Fatalf("onion_dns vector: %+v", d)
	}

	// ptrace connect path: CheckNetworkCtx with an IP-literal domain must also
	// reach EvalConnect (this is the path the ptrace runtime actually uses).
	if dec := e.CheckNetworkCtx(context.Background(), "127.0.0.1", 9050); dec.EffectiveDecision != types.DecisionDeny || dec.Tor == nil {
		t.Fatalf("ptrace path: loopback :9050 must deny via CheckNetworkCtx, got dec=%+v tor=%+v", dec.EffectiveDecision, dec.Tor)
	}
	if dec := e.CheckNetworkCtx(context.Background(), "128.31.0.39", 443); dec.EffectiveDecision != types.DecisionDeny || dec.Tor == nil {
		t.Fatalf("ptrace path: relay seed IP must deny via CheckNetworkCtx, got dec=%+v tor=%+v", dec.EffectiveDecision, dec.Tor)
	}
}
