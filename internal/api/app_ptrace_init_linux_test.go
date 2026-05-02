//go:build linux

package api

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/ptrace"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"golang.org/x/sys/unix"
)

// requirePtrace skips the test if the runner cannot PTRACE_SEIZE a child
// (no CAP_SYS_PTRACE, restrictive Yama, container without privilege).
func requirePtrace(t *testing.T) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "0.01")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start child process")
	}
	pid := cmd.Process.Pid
	err := unix.PtraceSeize(pid)
	cmd.Process.Kill()
	cmd.Wait()
	if err != nil {
		t.Skipf("PTRACE_SEIZE unavailable on this runner: %v", err)
	}
}

// waitForTraceeCount polls the App's ptrace tracer until TraceeCount > 0 or
// the deadline passes. Returns true when the tracee was registered.
func waitForTraceeCount(t *testing.T, app *App, timeout time.Duration) bool {
	t.Helper()
	tr, ok := app.ptraceTracer.(*ptrace.Tracer)
	if !ok || tr == nil {
		t.Fatalf("app.ptraceTracer is nil or wrong type: %T", app.ptraceTracer)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tr.TraceeCount() > 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// newPtraceTestApp constructs a minimal App with ptrace.enabled and the given
// attach_mode/target. It spins up the App's ptrace tracer goroutine; caller
// must call closePtraceTracer when done.
func newPtraceTestApp(t *testing.T, mutate func(*config.Config)) *App {
	t.Helper()
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Sandbox.Ptrace.Enabled = true
	cfg.Sandbox.Ptrace.Trace.Execve = true
	cfg.Sandbox.Ptrace.Trace.File = false
	cfg.Sandbox.Ptrace.Trace.Network = false
	cfg.Sandbox.Ptrace.Trace.Signal = false
	cfg.Sandbox.Ptrace.Performance.MaxTracees = 100
	cfg.Sandbox.Ptrace.Performance.MaxHoldMs = 5000
	cfg.Sandbox.Ptrace.OnAttachFailure = "fail_open"
	mutate(cfg)

	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	app := NewApp(cfg, mgr, store, nil, broker, nil, nil, nil, nil, nil, nil)
	t.Cleanup(func() { app.closePtraceTracer() })
	return app
}

// TestInitPtraceTracer_AttachModePidFromTargetPID verifies the runtime path
// for `sandbox.ptrace.attach_mode: "pid"` with `target_pid: N` actually
// attaches to the configured pid.
//
// Regression test for the bug where TargetPID was parsed/validated but never
// reached the tracer (initPtraceTracer started Run() and returned without
// calling AttachPID), causing all enforcement to silently no-op on hosts
// where commands aren't children of the agentsh server.
func TestInitPtraceTracer_AttachModePidFromTargetPID(t *testing.T) {
	requirePtrace(t)

	// Spawn a sleep child as the attach target.
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	pid := cmd.Process.Pid

	// Release Go's child-tracking so it doesn't compete with the tracer's
	// Wait4(-1) for events. (Same pattern used in ptrace integration tests.)
	cmd.Process.Release()

	app := newPtraceTestApp(t, func(c *config.Config) {
		c.Sandbox.Ptrace.AttachMode = "pid"
		c.Sandbox.Ptrace.TargetPID = pid
	})

	if !waitForTraceeCount(t, app, 3*time.Second) {
		t.Fatalf("tracer did not register a tracee within 3s — initPtraceTracer is not wiring TargetPID")
	}
}

// TestInitPtraceTracer_AttachModePidFromTargetPIDFile verifies the runtime
// path for `target_pid_file` (alternative to inline target_pid).
func TestInitPtraceTracer_AttachModePidFromTargetPIDFile(t *testing.T) {
	requirePtrace(t)

	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	pid := cmd.Process.Pid
	cmd.Process.Release()

	pidFile := filepath.Join(t.TempDir(), "target.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	app := newPtraceTestApp(t, func(c *config.Config) {
		c.Sandbox.Ptrace.AttachMode = "pid"
		c.Sandbox.Ptrace.TargetPIDFile = pidFile
	})

	if !waitForTraceeCount(t, app, 3*time.Second) {
		t.Fatalf("tracer did not register a tracee within 3s — TargetPIDFile path not wired")
	}
}

// TestInitPtraceTracer_AttachModePidFailsClosedOnBadPID verifies fail_closed
// semantics: when AttachPID fails (e.g. the target doesn't exist), the App's
// ptraceFailed flag is set so subsequent commands are rejected.
func TestInitPtraceTracer_AttachModePidFailsClosedOnBadPID(t *testing.T) {
	requirePtrace(t)

	app := newPtraceTestApp(t, func(c *config.Config) {
		c.Sandbox.Ptrace.AttachMode = "pid"
		c.Sandbox.Ptrace.TargetPID = 0x7fffffff // unlikely to exist
		c.Sandbox.Ptrace.OnAttachFailure = "fail_closed"
	})

	// Give the goroutine time to fail.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// Defensive: ptraceFailed is sync/atomic.Bool in the App struct.
		if v, ok := any(&app.ptraceFailed).(*atomic.Bool); ok && v.Load() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected ptraceFailed to be set after AttachPID(non-existent pid) under fail_closed")
}
