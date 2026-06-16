package transport

import (
	"testing"

	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
)

func TestSessionInit_CarriesDecisionContext(t *testing.T) {
	dc := &wtpv1.DecisionContext{
		Hostname: "host-1",
		Tags:     []string{"a"},
		User:     &wtpv1.DecisionContext_User{Value: "eran@x", Source: wtpv1.UserSource_USER_SOURCE_TAILSCALE},
	}
	// sessionInit() reads only opts and persistedAck; persistedAck's zero
	// value (seq 0, gen 0) is fine here.
	tr := &Transport{opts: Options{
		AgentID:         "agent-1",
		SessionID:       "sess-1",
		DecisionContext: dc,
	}}
	msg := tr.sessionInit()
	got := msg.GetSessionInit().GetDecisionContext()
	if got.GetHostname() != "host-1" || got.GetUser().GetValue() != "eran@x" {
		t.Fatalf("decision_context not set on SessionInit: %+v", got)
	}
}
