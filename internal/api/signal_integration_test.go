//go:build linux && cgo && integration

package api

import (
	"syscall"
	"testing"

	"github.com/agentsh/agentsh/internal/signal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignalFilterIntegration(t *testing.T) {
	if !signal.IsSignalSupportAvailable() {
		t.Skip("signal interception not available")
	}

	// This test verifies the signal handler can be started
	// Full e2e testing requires the wrapper which needs root

	engine, err := signal.NewEngine([]signal.SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGKILL", "SIGTERM"},
			Target:   signal.TargetSpec{Type: "external"},
			Decision: "deny",
		},
	})
	require.NoError(t, err)

	registry := signal.NewPIDRegistry("test", 1234)
	handler := signal.NewHandler(engine, registry, nil)

	// Evaluate a signal context - external target should be denied
	ctx := signal.SignalContext{
		PID:       1234,
		TargetPID: 9999, // External (not in session)
		Signal:    int(syscall.SIGTERM),
	}
	dec := handler.Evaluate(ctx)
	assert.Equal(t, signal.DecisionDeny, dec.Action)
	assert.Equal(t, "deny-external", dec.Rule)

	// Evaluate signal to self - should use default deny (no allow rule)
	ctxSelf := signal.SignalContext{
		PID:       1234,
		TargetPID: 1234, // Self
		Signal:    int(syscall.SIGTERM),
	}
	decSelf := handler.Evaluate(ctxSelf)
	// Default deny since no allow rule for self
	assert.Equal(t, signal.DecisionDeny, decSelf.Action)
}

func TestSignalFilterIntegrationWithAllowRule(t *testing.T) {
	if !signal.IsSignalSupportAvailable() {
		t.Skip("signal interception not available")
	}

	// Test with allow rules for session members
	engine, err := signal.NewEngine([]signal.SignalRule{
		{
			Name:     "allow-self",
			Signals:  []string{"SIGTERM", "SIGINT"},
			Target:   signal.TargetSpec{Type: "self"},
			Decision: "allow",
		},
		{
			Name:     "allow-children",
			Signals:  []string{"SIGTERM", "SIGKILL"},
			Target:   signal.TargetSpec{Type: "children"},
			Decision: "allow",
		},
		{
			Name:     "deny-external",
			Signals:  []string{"SIGKILL", "SIGTERM"},
			Target:   signal.TargetSpec{Type: "external"},
			Decision: "deny",
		},
	})
	require.NoError(t, err)

	registry := signal.NewPIDRegistry("test-session", 1000)
	// Register a child process
	registry.Register(2000, 1000, "child-process")

	handler := signal.NewHandler(engine, registry, nil)

	// Test: signal to self should be allowed
	decSelf := handler.Evaluate(signal.SignalContext{
		PID:       1000,
		TargetPID: 1000,
		Signal:    int(syscall.SIGTERM),
	})
	assert.Equal(t, signal.DecisionAllow, decSelf.Action)
	assert.Equal(t, "allow-self", decSelf.Rule)

	// Test: signal to child should be allowed
	decChild := handler.Evaluate(signal.SignalContext{
		PID:       1000,
		TargetPID: 2000,
		Signal:    int(syscall.SIGTERM),
	})
	assert.Equal(t, signal.DecisionAllow, decChild.Action)
	assert.Equal(t, "allow-children", decChild.Rule)

	// Test: signal to external should be denied
	decExternal := handler.Evaluate(signal.SignalContext{
		PID:       1000,
		TargetPID: 9999,
		Signal:    int(syscall.SIGTERM),
	})
	assert.Equal(t, signal.DecisionDeny, decExternal.Action)
	assert.Equal(t, "deny-external", decExternal.Rule)
}

func TestSignalFilterIntegrationAuditAndRedirect(t *testing.T) {
	if !signal.IsSignalSupportAvailable() {
		t.Skip("signal interception not available")
	}

	// Test audit and redirect decisions
	engine, err := signal.NewEngine([]signal.SignalRule{
		{
			Name:       "redirect-kill-to-term",
			Signals:    []string{"SIGKILL"},
			Target:     signal.TargetSpec{Type: "session"},
			Decision:   "redirect",
			RedirectTo: "SIGTERM",
		},
		{
			Name:     "audit-session-signals",
			Signals:  []string{"SIGTERM", "SIGINT"},
			Target:   signal.TargetSpec{Type: "session"},
			Decision: "audit",
		},
	})
	require.NoError(t, err)

	registry := signal.NewPIDRegistry("test-session", 1000)
	registry.Register(2000, 1000, "child")

	handler := signal.NewHandler(engine, registry, nil)

	// Test: SIGKILL to session member should be redirected
	decRedirect := handler.Evaluate(signal.SignalContext{
		PID:       1000,
		TargetPID: 2000,
		Signal:    int(syscall.SIGKILL),
	})
	assert.Equal(t, signal.DecisionRedirect, decRedirect.Action)
	assert.Equal(t, "redirect-kill-to-term", decRedirect.Rule)
	assert.Equal(t, int(syscall.SIGTERM), decRedirect.RedirectSignal)

	// Test: SIGTERM to session member should be audited
	decAudit := handler.Evaluate(signal.SignalContext{
		PID:       1000,
		TargetPID: 2000,
		Signal:    int(syscall.SIGTERM),
	})
	assert.Equal(t, signal.DecisionAudit, decAudit.Action)
	assert.Equal(t, "audit-session-signals", decAudit.Rule)
}
