package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

// newEngineAllowingCommand returns a minimal *policy.Engine with a single
// allow rule for the named command. The rule name is caller-supplied so
// tests can tell which engine produced a decision (by inspecting .Rule on
// the returned Decision).
//
// Shared by session_policy_test.go and session_policy_integration_test.go.
func newEngineAllowingCommand(t *testing.T, ruleName, cmdName string) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    ruleName,
		CommandRules: []policy.CommandRule{
			{
				Name:     ruleName,
				Commands: []string{cmdName},
				Decision: string(types.DecisionAllow),
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestPolicyEngineFor_PrefersSessionEngine(t *testing.T) {
	globalEngine := newEngineAllowingCommand(t, "allow-global-cmd", "global-cmd")
	sessionEngine := newEngineAllowingCommand(t, "allow-session-cmd", "session-cmd")

	mgr := session.NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	app := &App{policy: globalEngine}

	got := app.policyEngineFor(s)
	if got != sessionEngine {
		t.Fatalf("expected session engine, got %p (sessionEngine=%p, globalEngine=%p)",
			got, sessionEngine, globalEngine)
	}

	// Functional check: the returned engine must allow session-cmd and deny global-cmd,
	// proving we're consulting the session policy and not the global one.
	if dec := got.CheckCommand("session-cmd", nil); dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("session-cmd should be allowed via session engine, got %v (rule=%s)",
			dec.EffectiveDecision, dec.Rule)
	}
	if dec := got.CheckCommand("global-cmd", nil); dec.EffectiveDecision == types.DecisionAllow {
		t.Errorf("global-cmd should NOT be allowed via session engine, got %v (rule=%s)",
			dec.EffectiveDecision, dec.Rule)
	}
}

func TestPolicyEngineFor_FallsBackToGlobalWhenSessionEngineUnset(t *testing.T) {
	globalEngine := newEngineAllowingCommand(t, "allow-global-cmd", "global-cmd")

	mgr := session.NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Intentionally do NOT call s.SetPolicyEngine.

	app := &App{policy: globalEngine}

	got := app.policyEngineFor(s)
	if got != globalEngine {
		t.Fatalf("expected fallback to global engine, got %p (globalEngine=%p)", got, globalEngine)
	}
}

func TestPolicyEngineFor_NilSessionFallsBackToGlobal(t *testing.T) {
	globalEngine := newEngineAllowingCommand(t, "allow-global-cmd", "global-cmd")
	app := &App{policy: globalEngine}

	got := app.policyEngineFor(nil)
	if got != globalEngine {
		t.Fatalf("expected global engine for nil session, got %p", got)
	}
}
