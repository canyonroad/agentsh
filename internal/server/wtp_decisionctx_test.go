package server

import (
	"testing"

	"github.com/agentsh/agentsh/internal/decisionctx"
	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
)

func TestToWireDecisionContext(t *testing.T) {
	t.Run("tailscale source", func(t *testing.T) {
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
	})

	t.Run("os source", func(t *testing.T) {
		in := decisionctx.DecisionContext{
			User: decisionctx.User{Value: "alice", Source: decisionctx.SourceOS},
		}
		got := toWireDecisionContext(in)
		if got.GetUser() == nil {
			t.Fatal("expected User to be populated, got nil")
		}
		if got.GetUser().GetValue() != "alice" {
			t.Errorf("user value = %q, want %q", got.GetUser().GetValue(), "alice")
		}
		if got.GetUser().GetSource() != wtpv1.UserSource_USER_SOURCE_OS {
			t.Errorf("source = %v, want USER_SOURCE_OS", got.GetUser().GetSource())
		}
	})

	t.Run("zero user suppressed", func(t *testing.T) {
		in := decisionctx.DecisionContext{}
		got := toWireDecisionContext(in)
		if got.GetUser() != nil {
			t.Errorf("expected User to be nil for zero context, got %+v", got.GetUser())
		}
	})

	t.Run("value set source unspecified", func(t *testing.T) {
		in := decisionctx.DecisionContext{
			User: decisionctx.User{Value: "x", Source: ""},
		}
		got := toWireDecisionContext(in)
		if got.GetUser() == nil {
			t.Fatal("expected User to be populated when value is non-empty, got nil")
		}
		if got.GetUser().GetValue() != "x" {
			t.Errorf("user value = %q, want %q", got.GetUser().GetValue(), "x")
		}
		if got.GetUser().GetSource() != wtpv1.UserSource_USER_SOURCE_UNSPECIFIED {
			t.Errorf("source = %v, want USER_SOURCE_UNSPECIFIED", got.GetUser().GetSource())
		}
	})
}
