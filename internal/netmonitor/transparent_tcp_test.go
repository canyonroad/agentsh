//go:build linux
// +build linux

package netmonitor

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	dbevents "github.com/agentsh/agentsh/internal/db/events"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
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

func TestTransparentTCPEmitDBBypassAttempt(t *testing.T) {
	capture := &captureDBBypassEmitter{}
	tcp := &TransparentTCP{
		sessionID: "session-db",
		policy:    newNetmonitorDBUnavoidabilityEngine(t),
	}
	tcp.SetDBBypassEmitter(dbevents.NewBypassEmitter(capture))

	tcp.emitDBBypassAttempt(context.Background(), "", 0, "db-appdb-deny-direct", "blocked by transparent policy")

	if len(capture.events) != 1 {
		t.Fatalf("db bypass events = %d, want 1", len(capture.events))
	}
	ev := capture.events[0]
	if ev.Type != "db_bypass_attempt" {
		t.Fatalf("event type = %q, want db_bypass_attempt", ev.Type)
	}
	if ev.Fields["process_identity"] != "session:session-db" {
		t.Fatalf("process_identity = %v, want session:session-db", ev.Fields["process_identity"])
	}
	if ev.Fields["rule_name"] != "db-appdb-deny-direct" || ev.Fields["bypass_mode"] != dbservice.BypassModeTCPDirect {
		t.Fatalf("db metadata fields = %+v", ev.Fields)
	}
	if ev.Fields["reason"] != "blocked by transparent policy" {
		t.Fatalf("reason = %v", ev.Fields["reason"])
	}
}

func TestStartTransparentTCPInstallsInitialDBBypassEmitter(t *testing.T) {
	capture := &captureDBBypassEmitter{}
	tcp, _, err := StartTransparentTCP("127.0.0.1:0", "session-db", nil, nil, newNetmonitorDBUnavoidabilityEngine(t), nil, &stubEmitter{}, dbevents.NewBypassEmitter(capture))
	if err != nil {
		t.Fatalf("StartTransparentTCP: %v", err)
	}
	defer tcp.Close()

	tcp.emitDBBypassAttempt(context.Background(), "", 0, "db-appdb-deny-direct", "blocked before publish")

	if len(capture.events) != 1 {
		t.Fatalf("db bypass events = %d, want 1", len(capture.events))
	}
}

func TestTransparentTCPUsesSessionPolicyEngineForNetworkChecks(t *testing.T) {
	basePolicy := &policy.Policy{
		Version: 1,
		Name:    "base-allow",
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-db",
				Domains:  []string{"db.internal"},
				Ports:    []int{5432},
				Decision: "allow",
			},
		},
	}
	baseEngine, err := policy.NewEngine(basePolicy, false, true)
	if err != nil {
		t.Fatalf("NewEngine(base): %v", err)
	}
	mgr := session.NewManager(1)
	sess, err := mgr.CreateWithID("session-db-policy", t.TempDir(), "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	sess.SetPolicyEngine(newNetmonitorDBUnavoidabilityEngine(t))

	tcp := &TransparentTCP{sessionID: sess.ID, sess: sess, policy: baseEngine}
	got := tcp.policyDecision("db.internal", nil, 5432)
	if got.EffectiveDecision != types.DecisionDeny || got.Rule != "db-appdb-deny-direct" {
		t.Fatalf("policyDecision = %+v, want session-local DB deny", got)
	}
}

func TestTransparentTCP_TorControlCarriesCommandPID(t *testing.T) {
	em := &captureEmitter{}
	tcp := &TransparentTCP{sessionID: "s", emit: em}
	tcp.emitTorControl("cmd-1", 4242, &policy.TorVerdict{
		Vector: "relay_ip", Mode: "deny", Decision: "deny", Target: "10.0.0.1:443",
	})
	if len(em.events) != 1 {
		t.Fatalf("want 1 event, got %d", len(em.events))
	}
	ev := em.events[0]
	if ev.Type != "tor_control" {
		t.Fatalf("type = %q, want tor_control", ev.Type)
	}
	if ev.PID != 4242 {
		t.Fatalf("PID = %d, want 4242", ev.PID)
	}
	if ev.Fields["vector"] != "relay_ip" {
		t.Fatalf("vector = %v, want relay_ip", ev.Fields["vector"])
	}
}

func TestTransparentTCP_TorControlIdlePIDZero(t *testing.T) {
	em := &captureEmitter{}
	tcp := &TransparentTCP{sessionID: "s", emit: em}
	tcp.emitTorControl("", 0, &policy.TorVerdict{
		Vector: "socks_port", Mode: "deny", Decision: "deny", Target: "127.0.0.1:9050",
	})
	if len(em.events) != 1 {
		t.Fatalf("want 1 event, got %d", len(em.events))
	}
	if em.events[0].PID != 0 {
		t.Fatalf("PID = %d, want 0", em.events[0].PID)
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
