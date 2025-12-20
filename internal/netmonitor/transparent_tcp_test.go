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
