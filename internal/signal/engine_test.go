//go:build !windows

// internal/signal/engine_test.go
package signal

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNewEngineBasic(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "allow-term-children",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "children"},
			Decision: "allow",
			Message:  "allow SIGTERM to children",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)
	assert.NotNil(t, engine)
	assert.Len(t, engine.rules, 1)
}

func TestNewEngineSignalGroup(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "allow-fatal-children",
			Signals:  []string{"@fatal"},
			Target:   policy.SignalTargetSpec{Type: "children"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	// @fatal should expand to SIGKILL, SIGTERM, SIGQUIT, SIGABRT
	assert.Len(t, engine.rules[0].signals, 4)
	_, hasKill := engine.rules[0].signals[int(unix.SIGKILL)]
	_, hasTerm := engine.rules[0].signals[int(unix.SIGTERM)]
	_, hasQuit := engine.rules[0].signals[int(unix.SIGQUIT)]
	_, hasAbrt := engine.rules[0].signals[int(unix.SIGABRT)]
	assert.True(t, hasKill)
	assert.True(t, hasTerm)
	assert.True(t, hasQuit)
	assert.True(t, hasAbrt)
}

func TestNewEngineMixedSignals(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "mixed-signals",
			Signals:  []string{"@reload", "SIGINT", "15"}, // group + name + number
			Target:   policy.SignalTargetSpec{Type: "self"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	// @reload = HUP, USR1, USR2 (3) + INT + 15 (TERM) = 5 unique
	// But SIGTERM (15) might not be in @reload, so let's check
	expectedSignals := []int{
		int(unix.SIGHUP), int(unix.SIGUSR1), int(unix.SIGUSR2), // @reload
		int(unix.SIGINT), // SIGINT
		15,               // signal 15
	}
	for _, sig := range expectedSignals {
		_, ok := engine.rules[0].signals[sig]
		assert.True(t, ok, "expected signal %d to be present", sig)
	}
}

func TestNewEngineInvalidSignal(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "invalid",
			Signals:  []string{"INVALID_SIGNAL"},
			Target:   policy.SignalTargetSpec{Type: "self"},
			Decision: "allow",
		},
	}

	_, err := NewEngine(rules)
	assert.Error(t, err)
}

func TestNewEngineInvalidSignalGroup(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "invalid",
			Signals:  []string{"@nonexistent"},
			Target:   policy.SignalTargetSpec{Type: "self"},
			Decision: "allow",
		},
	}

	_, err := NewEngine(rules)
	assert.Error(t, err)
}

func TestNewEngineInvalidTargetType(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "invalid",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "invalid_type"},
			Decision: "allow",
		},
	}

	_, err := NewEngine(rules)
	assert.Error(t, err)
}

func TestNewEngineRedirectSignal(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:       "redirect-kill-to-term",
			Signals:    []string{"SIGKILL"},
			Target:     policy.SignalTargetSpec{Type: "children"},
			Decision:   "redirect",
			RedirectTo: "SIGTERM",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)
	assert.Equal(t, int(unix.SIGTERM), engine.rules[0].redirect)
}

func TestNewEngineInvalidRedirectSignal(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:       "redirect-invalid",
			Signals:    []string{"SIGKILL"},
			Target:     policy.SignalTargetSpec{Type: "children"},
			Decision:   "redirect",
			RedirectTo: "INVALID",
		},
	}

	_, err := NewEngine(rules)
	assert.Error(t, err)
}

func TestCheckBasicAllow(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "allow-term-children",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "children"},
			Decision: "allow",
			Message:  "allowed",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{IsChild: true}
	dec := engine.Check(int(unix.SIGTERM), ctx)

	assert.Equal(t, DecisionAllow, dec.Action)
	assert.Equal(t, "allow-term-children", dec.Rule)
	assert.Equal(t, "allowed", dec.Message)
}

func TestCheckBasicDeny(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "deny-kill-external",
			Signals:  []string{"SIGKILL"},
			Target:   policy.SignalTargetSpec{Type: "external"},
			Decision: "deny",
			Message:  "denied",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{InSession: false} // external = not in session
	dec := engine.Check(int(unix.SIGKILL), ctx)

	assert.Equal(t, DecisionDeny, dec.Action)
	assert.Equal(t, "deny-kill-external", dec.Rule)
}

func TestCheckDefaultDeny(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "allow-term-children",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "children"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	// Signal doesn't match
	ctx := &TargetContext{IsChild: true}
	dec := engine.Check(int(unix.SIGKILL), ctx)
	assert.Equal(t, DecisionDeny, dec.Action)
	assert.Empty(t, dec.Rule)
	assert.Equal(t, "no matching rule", dec.Message)

	// Target doesn't match
	ctx = &TargetContext{IsChild: false}
	dec = engine.Check(int(unix.SIGTERM), ctx)
	assert.Equal(t, DecisionDeny, dec.Action)
}

func TestCheckFirstMatchWins(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "deny-term-external",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "external"},
			Decision: "deny",
			Message:  "first rule",
		},
		{
			Name:     "allow-term-external",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "external"},
			Decision: "allow",
			Message:  "second rule",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{InSession: false}
	dec := engine.Check(int(unix.SIGTERM), ctx)

	// First matching rule should win
	assert.Equal(t, DecisionDeny, dec.Action)
	assert.Equal(t, "deny-term-external", dec.Rule)
	assert.Equal(t, "first rule", dec.Message)
}

func TestCheckMultipleRulesCorrectMatch(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "allow-term-children",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "children"},
			Decision: "allow",
			Message:  "children rule",
		},
		{
			Name:     "deny-term-external",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "external"},
			Decision: "deny",
			Message:  "external rule",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	// Match children rule
	ctx := &TargetContext{IsChild: true}
	dec := engine.Check(int(unix.SIGTERM), ctx)
	assert.Equal(t, DecisionAllow, dec.Action)
	assert.Equal(t, "children rule", dec.Message)

	// Match external rule
	ctx = &TargetContext{InSession: false}
	dec = engine.Check(int(unix.SIGTERM), ctx)
	assert.Equal(t, DecisionDeny, dec.Action)
	assert.Equal(t, "external rule", dec.Message)
}

func TestCheckSignalGroup(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "allow-fatal-children",
			Signals:  []string{"@fatal"},
			Target:   policy.SignalTargetSpec{Type: "children"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{IsChild: true}

	// All @fatal signals should match
	for _, sig := range []int{int(unix.SIGKILL), int(unix.SIGTERM), int(unix.SIGQUIT), int(unix.SIGABRT)} {
		dec := engine.Check(sig, ctx)
		assert.Equal(t, DecisionAllow, dec.Action, "expected ALLOW for signal %d", sig)
	}

	// Non-fatal signal should not match
	dec := engine.Check(int(unix.SIGUSR1), ctx)
	assert.Equal(t, DecisionDeny, dec.Action)
}

func TestCheckRedirectDecision(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:       "redirect-kill-to-term",
			Signals:    []string{"SIGKILL"},
			Target:     policy.SignalTargetSpec{Type: "children"},
			Decision:   "redirect",
			RedirectTo: "SIGTERM",
			Message:    "redirecting SIGKILL",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{IsChild: true}
	dec := engine.Check(int(unix.SIGKILL), ctx)

	assert.Equal(t, DecisionRedirect, dec.Action)
	assert.Equal(t, int(unix.SIGTERM), dec.RedirectSignal)
	assert.Equal(t, "redirecting SIGKILL", dec.Message)
}

func TestCheckAuditDecision(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "audit-signals",
			Signals:  []string{"SIGUSR1"},
			Target:   policy.SignalTargetSpec{Type: "session"},
			Decision: "audit",
			Message:  "audit only",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{InSession: true}
	dec := engine.Check(int(unix.SIGUSR1), ctx)

	assert.Equal(t, DecisionAudit, dec.Action)
	assert.Equal(t, "audit only", dec.Message)
}

func TestCheckApproveDecision(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "approve-kill",
			Signals:  []string{"SIGKILL"},
			Target:   policy.SignalTargetSpec{Type: "external"},
			Decision: "approve",
			Message:  "needs approval",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{InSession: false}
	dec := engine.Check(int(unix.SIGKILL), ctx)

	assert.Equal(t, DecisionApprove, dec.Action)
	assert.Equal(t, "needs approval", dec.Message)
}

func TestCheckAbsorbDecision(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "absorb-int",
			Signals:  []string{"SIGINT"},
			Target:   policy.SignalTargetSpec{Type: "self"},
			Decision: "absorb",
			Message:  "absorbed",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{SourcePID: 1000, TargetPID: 1000}
	dec := engine.Check(int(unix.SIGINT), ctx)

	assert.Equal(t, DecisionAbsorb, dec.Action)
	assert.Equal(t, "absorbed", dec.Message)
}

func TestCheckProcessTarget(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "allow-term-nginx",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "process", Pattern: "nginx*"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	// Match nginx process
	ctx := &TargetContext{TargetCmd: "nginx-worker"}
	dec := engine.Check(int(unix.SIGTERM), ctx)
	assert.Equal(t, DecisionAllow, dec.Action)

	// Don't match other processes
	ctx = &TargetContext{TargetCmd: "apache"}
	dec = engine.Check(int(unix.SIGTERM), ctx)
	assert.Equal(t, DecisionDeny, dec.Action)
}

func TestCheckPIDRangeTarget(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "deny-signals-low-pids",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "pid_range", Min: 1, Max: 100},
			Decision: "deny",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	// Match PID in range
	ctx := &TargetContext{TargetPID: 50}
	dec := engine.Check(int(unix.SIGTERM), ctx)
	assert.Equal(t, DecisionDeny, dec.Action)

	// Don't match PID outside range
	ctx = &TargetContext{TargetPID: 1000}
	dec = engine.Check(int(unix.SIGTERM), ctx)
	assert.Equal(t, DecisionDeny, dec.Action) // default deny, but not from our rule
	assert.Empty(t, dec.Rule)
}

func TestCheckFallbackPreserved(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "deny-with-fallback",
			Signals:  []string{"SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "external"},
			Decision: "deny",
			Fallback: "audit",
			Message:  "denied",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{InSession: false}
	dec := engine.Check(int(unix.SIGTERM), ctx)

	assert.Equal(t, DecisionDeny, dec.Action)
	assert.Equal(t, "audit", dec.Fallback)
}

func TestApplyFallbackCanBlock(t *testing.T) {
	dec := Decision{
		Action:   DecisionDeny,
		Rule:     "test",
		Message:  "denied",
		Fallback: "audit",
	}

	// When platform can block, decision should be unchanged
	result := ApplyFallback(dec, true)
	assert.Equal(t, DecisionDeny, result.Action)
	assert.Equal(t, "denied", result.Message)
}

func TestApplyFallbackCannotBlock(t *testing.T) {
	tests := []struct {
		name     string
		action   DecisionAction
		fallback string
		expected DecisionAction
	}{
		{"deny with fallback", DecisionDeny, "audit", DecisionAudit},
		{"approve with fallback", DecisionApprove, "allow", DecisionAllow},
		{"redirect with fallback", DecisionRedirect, "audit", DecisionAudit},
		{"absorb with fallback", DecisionAbsorb, "deny", DecisionDeny},
		{"deny no fallback", DecisionDeny, "", DecisionAudit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := Decision{
				Action:   tt.action,
				Rule:     "test",
				Message:  "original message",
				Fallback: tt.fallback,
			}

			result := ApplyFallback(dec, false)
			assert.Equal(t, tt.expected, result.Action)
		})
	}
}

func TestApplyFallbackAllowPassthrough(t *testing.T) {
	dec := Decision{
		Action:  DecisionAllow,
		Rule:    "test",
		Message: "allowed",
	}

	// Allow doesn't need blocking, should pass through unchanged
	result := ApplyFallback(dec, false)
	assert.Equal(t, DecisionAllow, result.Action)
	assert.Equal(t, "allowed", result.Message)
}

func TestApplyFallbackAuditPassthrough(t *testing.T) {
	dec := Decision{
		Action:  DecisionAudit,
		Rule:    "test",
		Message: "audit only",
	}

	// Audit doesn't need blocking, should pass through unchanged
	result := ApplyFallback(dec, false)
	assert.Equal(t, DecisionAudit, result.Action)
	assert.Equal(t, "audit only", result.Message)
}

func TestApplyFallbackMessageModification(t *testing.T) {
	dec := Decision{
		Action:   DecisionDeny,
		Rule:     "test",
		Message:  "denied",
		Fallback: "audit",
	}

	result := ApplyFallback(dec, false)
	assert.Contains(t, result.Message, "fallback applied")
}

func TestApplyFallbackNoFallbackMessage(t *testing.T) {
	dec := Decision{
		Action:  DecisionDeny,
		Rule:    "test",
		Message: "denied",
	}

	result := ApplyFallback(dec, false)
	assert.Contains(t, result.Message, "platform cannot enforce")
}

func TestNewEngineEmptyRules(t *testing.T) {
	engine, err := NewEngine(nil)
	require.NoError(t, err)
	assert.NotNil(t, engine)
	assert.Empty(t, engine.rules)

	// Any check should return default deny
	ctx := &TargetContext{}
	dec := engine.Check(int(unix.SIGTERM), ctx)
	assert.Equal(t, DecisionDeny, dec.Action)
}

func TestNewEngineMultipleSignalsInRule(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "multiple-signals",
			Signals:  []string{"SIGTERM", "SIGINT", "SIGHUP"},
			Target:   policy.SignalTargetSpec{Type: "children"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{IsChild: true}

	// All listed signals should match
	for _, sig := range []int{int(unix.SIGTERM), int(unix.SIGINT), int(unix.SIGHUP)} {
		dec := engine.Check(sig, ctx)
		assert.Equal(t, DecisionAllow, dec.Action, "expected ALLOW for signal %d", sig)
	}
}

func TestCheckSignalByNumber(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "allow-by-number",
			Signals:  []string{"9", "15"}, // SIGKILL, SIGTERM
			Target:   policy.SignalTargetSpec{Type: "children"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	ctx := &TargetContext{IsChild: true}

	dec := engine.Check(9, ctx)
	assert.Equal(t, DecisionAllow, dec.Action)

	dec = engine.Check(15, ctx)
	assert.Equal(t, DecisionAllow, dec.Action)

	// Different signal should not match
	dec = engine.Check(1, ctx)
	assert.Equal(t, DecisionDeny, dec.Action)
}

func TestDecisionConstants(t *testing.T) {
	assert.Equal(t, "allow", string(DecisionAllow))
	assert.Equal(t, "deny", string(DecisionDeny))
	assert.Equal(t, "audit", string(DecisionAudit))
	assert.Equal(t, "approve", string(DecisionApprove))
	assert.Equal(t, "redirect", string(DecisionRedirect))
	assert.Equal(t, "absorb", string(DecisionAbsorb))
}
