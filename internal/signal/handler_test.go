//go:build !windows

package signal

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEmitter records emitted events for testing.
type mockEmitter struct {
	events []emittedEvent
}

type emittedEvent struct {
	eventType events.EventType
	data      map[string]interface{}
}

func (m *mockEmitter) Emit(ctx context.Context, eventType events.EventType, data map[string]interface{}) {
	m.events = append(m.events, emittedEvent{eventType: eventType, data: data})
}

func TestHandlerEvaluate(t *testing.T) {
	rules := []SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGKILL"},
			Target:   TargetSpec{Type: "external"},
			Decision: "deny",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	handler := NewHandler(engine, registry, nil)

	// Test deny external
	dec := handler.Evaluate(SignalContext{
		PID:       1001,
		TargetPID: 9999,
		Signal:    9,
	})
	assert.Equal(t, DecisionDeny, dec.Action)
	assert.Equal(t, "deny-external", dec.Rule)
}

func TestHandlerEvaluateAllowSelf(t *testing.T) {
	rules := []SignalRule{
		{
			Name:     "allow-self",
			Signals:  []string{"SIGTERM"},
			Target:   TargetSpec{Type: "self"},
			Decision: "allow",
		},
		{
			Name:     "deny-all",
			Signals:  []string{"SIGTERM"},
			Target:   TargetSpec{Type: "external"},
			Decision: "deny",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	handler := NewHandler(engine, registry, nil)

	// Test allow self (first rule matches)
	dec := handler.Evaluate(SignalContext{
		PID:       1001,
		TargetPID: 1001,
		Signal:    15, // SIGTERM
	})
	assert.Equal(t, DecisionAllow, dec.Action)
	assert.Equal(t, "allow-self", dec.Rule)
}

func TestHandlerEvaluateAllowSession(t *testing.T) {
	rules := []SignalRule{
		{
			Name:     "allow-session",
			Signals:  []string{"SIGTERM"},
			Target:   TargetSpec{Type: "session"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")
	registry.Register(1002, 1001, "cat")

	handler := NewHandler(engine, registry, nil)

	// Test allow within session
	dec := handler.Evaluate(SignalContext{
		PID:       1001,
		TargetPID: 1002,
		Signal:    15,
	})
	assert.Equal(t, DecisionAllow, dec.Action)
}

func TestHandlerHandle(t *testing.T) {
	if !CanBlockSignals() {
		t.Skip("signal blocking not supported on this platform")
	}
	rules := []SignalRule{
		{
			Name:     "deny-external-kill",
			Signals:  []string{"SIGKILL"},
			Target:   TargetSpec{Type: "external"},
			Decision: "deny",
			Message:  "cannot kill external processes",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	emitter := &mockEmitter{}
	handler := NewHandler(engine, registry, emitter)

	ctx := context.Background()
	dec := handler.Handle(ctx, SignalContext{
		PID:       1001,
		TargetPID: 9999,
		Signal:    9,
		Syscall:   62, // SYS_KILL
	})

	assert.Equal(t, DecisionDeny, dec.Action)
	require.Len(t, emitter.events, 1)
	assert.Equal(t, events.EventSignalBlocked, emitter.events[0].eventType)
	assert.Equal(t, 1001, emitter.events[0].data["source_pid"])
	assert.Equal(t, 9999, emitter.events[0].data["target_pid"])
	assert.Equal(t, 9, emitter.events[0].data["signal"])
	assert.Equal(t, "SIGKILL", emitter.events[0].data["signal_name"])
	assert.Equal(t, "deny-external-kill", emitter.events[0].data["rule"])
}

func TestHandlerHandleAllowEmitsEvent(t *testing.T) {
	rules := []SignalRule{
		{
			Name:     "allow-children",
			Signals:  []string{"SIGTERM"},
			Target:   TargetSpec{Type: "children"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")
	registry.Register(1002, 1001, "sleep")

	emitter := &mockEmitter{}
	handler := NewHandler(engine, registry, emitter)

	ctx := context.Background()
	dec := handler.Handle(ctx, SignalContext{
		PID:       1001,
		TargetPID: 1002,
		Signal:    15,
		Syscall:   62,
	})

	assert.Equal(t, DecisionAllow, dec.Action)
	require.Len(t, emitter.events, 1)
	assert.Equal(t, events.EventSignalSent, emitter.events[0].eventType)
}

func TestHandlerHandleRedirect(t *testing.T) {
	if !CanBlockSignals() {
		t.Skip("signal blocking not supported on this platform")
	}
	rules := []SignalRule{
		{
			Name:       "redirect-kill-to-term",
			Signals:    []string{"SIGKILL"},
			Target:     TargetSpec{Type: "children"},
			Decision:   "redirect",
			RedirectTo: "SIGTERM",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")
	registry.Register(1002, 1001, "process")

	emitter := &mockEmitter{}
	handler := NewHandler(engine, registry, emitter)

	ctx := context.Background()
	dec := handler.Handle(ctx, SignalContext{
		PID:       1001,
		TargetPID: 1002,
		Signal:    9,
		Syscall:   62,
	})

	assert.Equal(t, DecisionRedirect, dec.Action)
	assert.Equal(t, 15, dec.RedirectSignal) // SIGTERM
	require.Len(t, emitter.events, 1)
	assert.Equal(t, events.EventSignalRedirected, emitter.events[0].eventType)
	assert.Equal(t, 15, emitter.events[0].data["redirect_to"])
	assert.Equal(t, "SIGTERM", emitter.events[0].data["redirect_to_name"])
}

func TestHandlerHandleAudit(t *testing.T) {
	rules := []SignalRule{
		{
			Name:     "audit-external",
			Signals:  []string{"SIGUSR1"},
			Target:   TargetSpec{Type: "external"},
			Decision: "audit",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	emitter := &mockEmitter{}
	handler := NewHandler(engine, registry, emitter)

	ctx := context.Background()
	dec := handler.Handle(ctx, SignalContext{
		PID:       1001,
		TargetPID: 9999,
		Signal:    10, // SIGUSR1
		Syscall:   62,
	})

	assert.Equal(t, DecisionAudit, dec.Action)
	require.Len(t, emitter.events, 1)
	// Audit emits EventSignalSent since signal is allowed through
	assert.Equal(t, events.EventSignalSent, emitter.events[0].eventType)
}

func TestHandlerHandleAbsorb(t *testing.T) {
	if !CanBlockSignals() {
		t.Skip("signal blocking not supported on this platform")
	}
	rules := []SignalRule{
		{
			Name:     "absorb-sigchld",
			Signals:  []string{"SIGCHLD"},
			Target:   TargetSpec{Type: "session"},
			Decision: "absorb",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	emitter := &mockEmitter{}
	handler := NewHandler(engine, registry, emitter)

	ctx := context.Background()
	dec := handler.Handle(ctx, SignalContext{
		PID:       1001,
		TargetPID: 1000,
		Signal:    17, // SIGCHLD
		Syscall:   62,
	})

	assert.Equal(t, DecisionAbsorb, dec.Action)
	require.Len(t, emitter.events, 1)
	assert.Equal(t, events.EventSignalAbsorbed, emitter.events[0].eventType)
}

func TestHandlerHandleApprove(t *testing.T) {
	if !CanBlockSignals() {
		t.Skip("signal blocking not supported on this platform")
	}
	rules := []SignalRule{
		{
			Name:     "approve-external-kill",
			Signals:  []string{"SIGKILL"},
			Target:   TargetSpec{Type: "external"},
			Decision: "approve",
			Message:  "killing external process requires approval",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	emitter := &mockEmitter{}
	handler := NewHandler(engine, registry, emitter)

	ctx := context.Background()
	dec := handler.Handle(ctx, SignalContext{
		PID:       1001,
		TargetPID: 9999,
		Signal:    9,
		Syscall:   62,
	})

	assert.Equal(t, DecisionApprove, dec.Action)
	require.Len(t, emitter.events, 1)
	assert.Equal(t, events.EventSignalApproved, emitter.events[0].eventType)
	assert.Equal(t, "killing external process requires approval", emitter.events[0].data["message"])
}

func TestHandlerNilEmitter(t *testing.T) {
	if !CanBlockSignals() {
		t.Skip("signal blocking not supported on this platform")
	}
	rules := []SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGKILL"},
			Target:   TargetSpec{Type: "external"},
			Decision: "deny",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	// nil emitter should not panic
	handler := NewHandler(engine, registry, nil)

	ctx := context.Background()
	dec := handler.Handle(ctx, SignalContext{
		PID:       1001,
		TargetPID: 9999,
		Signal:    9,
		Syscall:   62,
	})

	// Should still work, just without emitting events
	assert.Equal(t, DecisionDeny, dec.Action)
}

func TestHandlerEventData(t *testing.T) {
	if !CanBlockSignals() {
		t.Skip("signal blocking not supported on this platform")
	}
	rules := []SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGKILL"},
			Target:   TargetSpec{Type: "external"},
			Decision: "deny",
			Message:  "test message",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	emitter := &mockEmitter{}
	handler := NewHandler(engine, registry, emitter)

	ctx := context.Background()
	handler.Handle(ctx, SignalContext{
		PID:       1001,
		TargetPID: 9999,
		TargetTID: 9999,
		Signal:    9,
		Syscall:   62,
	})

	require.Len(t, emitter.events, 1)
	data := emitter.events[0].data

	// Verify all expected fields are present
	assert.Equal(t, 1001, data["source_pid"])
	assert.Equal(t, 9999, data["target_pid"])
	assert.Equal(t, 9, data["signal"])
	assert.Equal(t, "SIGKILL", data["signal_name"])
	assert.Equal(t, 62, data["syscall"])
	assert.Equal(t, "deny", data["decision"])
	assert.Equal(t, "deny-external", data["rule"])
	assert.Equal(t, "test message", data["message"])

	// Verify timestamp is present and reasonable
	ts, ok := data["timestamp"].(time.Time)
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now(), ts, 5*time.Second)
}

func TestHandlerRespectsPlatformCapability(t *testing.T) {
	rules := []SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGTERM"},
			Target:   TargetSpec{Type: "external"},
			Decision: "deny",
			Fallback: "audit",
		},
	}
	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("test", 1000)
	handler := NewHandler(engine, registry, nil)

	// Handler should use platform detection
	dec := handler.Handle(context.Background(), SignalContext{
		PID:       1000,
		TargetPID: 9999, // External
		Signal:    15,
	})

	// On Linux with seccomp available, should be Deny
	// Otherwise (macOS, Windows, no seccomp), should fallback to Audit
	if CanBlockSignals() {
		assert.Equal(t, DecisionDeny, dec.Action)
	} else {
		assert.Equal(t, DecisionAudit, dec.Action)
	}
}
