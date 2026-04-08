package api

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

// newEngineDenyingOnly returns a *policy.Engine with a single explicit
// deny rule for the named command. The rule name embeds the command so
// tests can tell which engine produced the decision (distinguishing it
// from a default-deny fallback or from an engine built by
// newEngineAllowingCommand in session_policy_test.go).
func newEngineDenyingOnly(t *testing.T, cmdName string) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "global-deny-" + cmdName,
		CommandRules: []policy.CommandRule{
			{
				Name:     "global-deny-" + cmdName,
				Commands: []string{cmdName},
				Decision: string(types.DecisionDeny),
				Message:  "denied by global policy",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// TestExecInSessionCore_PrecheckConsultsSessionPolicy is the regression
// test for #191. It constructs an App whose global policy denies "widget"
// and whose session policy allows "widget", then calls execInSessionCore
// and asserts the emitted command_precheck event reflects the session
// policy's ALLOW decision — not the global policy's DENY.
//
// newEngineAllowingCommand comes from session_policy_test.go (same package).
func TestExecInSessionCore_PrecheckConsultsSessionPolicy(t *testing.T) {
	// Use a guaranteed-missing path under t.TempDir() so the command
	// cannot possibly exist/block on the runner, regardless of what's
	// installed on PATH. Lowercased to match the engine's internal
	// normalization in CheckCommand (see internal/policy/engine.go).
	// filepath.ToSlash normalizes backslashes to forward slashes on
	// Windows so the policy engine compiles the rule as a full path
	// (it only treats "/" as a path separator — see engine.go ~line 196).
	cmdPath := strings.ToLower(filepath.ToSlash(filepath.Join(t.TempDir(), "agentsh191-nonexistent")))

	globalEngine := newEngineDenyingOnly(t, cmdPath)
	sessionEngine := newEngineAllowingCommand(t, "session-allow-widget", cmdPath)

	mgr := session.NewManager(5)
	captured := &capturingEventStore{}
	store := composite.New(captured, nil)
	broker := events.NewBroker()

	cfg := &config.Config{}
	app := NewApp(cfg, mgr, store, globalEngine, broker, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	// We don't care whether the command actually runs — we only care which
	// engine the precheck consulted. The precheck event is emitted BEFORE
	// the command would be run, so even if runCommandWithResources errors
	// later (no ptrace tracer, binary doesn't exist), the captured event
	// tells us what we need. A bounded context is used as a safety net so
	// this test can never hang if something downstream were to block.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, _ = app.execInSessionCore(ctx, s.ID, types.ExecRequest{
		Command: cmdPath,
	})

	ev := captured.firstCommandPrecheck()
	if ev == nil {
		t.Fatal("no command_precheck event was emitted")
	}
	if ev.Policy == nil {
		t.Fatal("command_precheck event has nil Policy")
	}
	if ev.Policy.Rule != "session-allow-widget" {
		t.Errorf("precheck consulted the wrong engine: event rule = %q, want %q. "+
			"This means the precheck is still using a.policy instead of the session engine.",
			ev.Policy.Rule, "session-allow-widget")
	}
	if ev.Policy.EffectiveDecision != types.DecisionAllow {
		t.Errorf("precheck should have returned allow, got %v", ev.Policy.EffectiveDecision)
	}
}

// capturingEventStore is a minimal store.EventStore implementation that
// records every AppendEvent call so tests can inspect what was emitted.
// It satisfies the same interface as mockEventStore (see policies_test.go)
// but, unlike that one, keeps the events so we can assert on them.
type capturingEventStore struct {
	events []types.Event
}

func (c *capturingEventStore) AppendEvent(_ context.Context, ev types.Event) error {
	c.events = append(c.events, ev)
	return nil
}

func (c *capturingEventStore) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (c *capturingEventStore) Close() error { return nil }

func (c *capturingEventStore) firstCommandPrecheck() *types.Event {
	for i := range c.events {
		if c.events[i].Operation == "command_precheck" {
			return &c.events[i]
		}
	}
	return nil
}
