//go:build linux

package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

// newProbeTestApp builds the minimal *App needed to exercise initPtraceTracer
// with sandbox.ptrace.enabled = true. It mirrors newPtraceTestApp in
// app_ptrace_init_linux_test.go. NewApp calls initPtraceTracer exactly once
// internally, so callers MUST override the ptraceInjectProbe seam BEFORE calling
// this helper; the assertions then inspect the resulting App state.
func newProbeTestApp(t *testing.T) *App {
	t.Helper()
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Sandbox.Ptrace.Enabled = true
	cfg.Sandbox.Ptrace.Trace.Execve = true
	cfg.Sandbox.Ptrace.Performance.MaxTracees = 100
	cfg.Sandbox.Ptrace.Performance.MaxHoldMs = 5000
	cfg.Sandbox.Ptrace.OnAttachFailure = "fail_open"

	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	app := NewApp(cfg, mgr, store, nil, broker, nil, nil, nil, nil, nil, nil, nil)
	t.Cleanup(func() { app.closePtraceTracer() })
	return app
}

// TestInitPtraceTracer_DegradesWhenNotInjectable verifies that when the probe
// reports injection is unreliable, initPtraceTracer does NOT start the tracer,
// sets ptraceDegraded, and does NOT set ptraceFailed (degrade, not fail-closed).
func TestInitPtraceTracer_DegradesWhenNotInjectable(t *testing.T) {
	orig := ptraceInjectProbe
	t.Cleanup(func() { ptraceInjectProbe = orig })
	ptraceInjectProbe = func() bool { return false } // injection unreliable

	a := newProbeTestApp(t)

	if a.ptraceTracer != nil {
		t.Fatal("tracer must NOT start when injection is unreliable")
	}
	if !a.ptraceDegraded.Load() {
		t.Fatal("ptraceDegraded must be set on degrade")
	}
	if a.ptraceFailed.Load() {
		t.Fatal("must NOT fail-closed on degrade (ptraceFailed must stay false)")
	}
}

// TestInitPtraceTracer_StartsWhenInjectable verifies that when the probe reports
// injection is reliable, initPtraceTracer proceeds normally and does NOT set
// ptraceDegraded.
//
// Full assertion of ptraceTracer != nil requires CAP_SYS_PTRACE and is handled
// by the existing tests in app_ptrace_init_linux_test.go. Here we only assert
// that the degraded flag is not set (the gate passed), which works without
// privilege and avoids flaking on restricted CI runners.
func TestInitPtraceTracer_StartsWhenInjectable(t *testing.T) {
	orig := ptraceInjectProbe
	t.Cleanup(func() { ptraceInjectProbe = orig })
	ptraceInjectProbe = func() bool { return true }

	a := newProbeTestApp(t)

	if a.ptraceDegraded.Load() {
		t.Fatal("ptraceDegraded must NOT be set when injection is reliable")
	}
	if a.ptraceFailed.Load() {
		t.Fatal("ptraceFailed must NOT be set by the gate path")
	}
	// Note: ptraceTracer may be nil here if the runner lacks CAP_SYS_PTRACE
	// (NewTracer succeeds but Run fails immediately). The strong assertion
	// (ptraceTracer != nil) is covered by requirePtrace-gated tests in
	// app_ptrace_init_linux_test.go. The gate-specific concern is that
	// ptraceDegraded is false, which we've verified above.
}
