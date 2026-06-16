package server

import (
	"testing"

	"github.com/agentsh/agentsh/internal/decisionctx"
	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
)

func TestToWireDecisionContext(t *testing.T) {
	in := decisionctx.DecisionContext{
		Hostname: "h",
		Tags:     []string{"a", "b"},
		User:     decisionctx.User{Value: "eran@x", Source: decisionctx.SourceTailscale},
		Extra:    map[string]string{"region": "us"},
	}
	got := toWireDecisionContext(in)
	if got.GetHostname() != "h" || len(got.GetTags()) != 2 {
		t.Fatalf("hostname/tags wrong: %+v", got)
	}
	if got.GetUser().GetSource() != wtpv1.UserSource_USER_SOURCE_TAILSCALE {
		t.Errorf("source = %v, want TAILSCALE", got.GetUser().GetSource())
	}
	if got.GetExtra()["region"] != "us" {
		t.Errorf("extra not copied")
	}
}
