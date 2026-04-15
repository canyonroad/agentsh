//go:build linux && cgo

package unix

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestServeNotify_RoutesExecve(t *testing.T) {
	// Verify the routing logic is correct
	assert.True(t, IsExecveSyscall(unix.SYS_EXECVE))
	assert.True(t, IsExecveSyscall(unix.SYS_EXECVEAT))
	assert.False(t, IsExecveSyscall(unix.SYS_CONNECT))
	assert.False(t, IsExecveSyscall(unix.SYS_SOCKET))
}

func TestGetParentPID(t *testing.T) {
	// Test with current process - parent should be non-zero
	ppid := getParentPID(unix.Getpid())
	assert.Greater(t, ppid, 0, "parent PID should be non-zero for current process")

	// Test with invalid PID - should return 0
	ppid = getParentPID(-1)
	assert.Equal(t, 0, ppid, "parent PID should be 0 for invalid PID")

	// Test with non-existent PID - should return 0
	ppid = getParentPID(999999999)
	assert.Equal(t, 0, ppid, "parent PID should be 0 for non-existent PID")
}

func TestServeNotify_RoutesFileSyscalls(t *testing.T) {
	assert.True(t, isFileSyscall(unix.SYS_OPENAT))
	assert.True(t, isFileSyscall(unix.SYS_UNLINKAT))
	assert.True(t, isFileSyscall(unix.SYS_MKDIRAT))
	assert.True(t, isFileSyscall(unix.SYS_RENAMEAT2))
	assert.False(t, isFileSyscall(unix.SYS_EXECVE))
	assert.False(t, isFileSyscall(unix.SYS_CONNECT))
}

func TestServeNotify_RoutesNewFileSyscalls(t *testing.T) {
	assert.True(t, isFileSyscall(unix.SYS_STATX))
	assert.True(t, isFileSyscall(unix.SYS_NEWFSTATAT))
	assert.True(t, isFileSyscall(unix.SYS_FACCESSAT2))
	assert.True(t, isFileSyscall(unix.SYS_READLINKAT))
	assert.True(t, isFileSyscall(unix.SYS_MKNODAT))
}

// handlerTestEmitter is a no-op emitter for handler lifecycle tests.
type handlerTestEmitter struct{}

func (e *handlerTestEmitter) AppendEvent(_ context.Context, _ types.Event) error { return nil }
func (e *handlerTestEmitter) Publish(_ types.Event)                              {}

func TestServeNotifyWithExecve_DoesNotHangOnCancelledContext(t *testing.T) {
	// Verify the serve loop does not hang when given a pre-cancelled context.
	// Note: with pipe FDs, NotifReceive returns an ioctl error immediately,
	// so this also exits via the error branch. Testing the ctx.Done() select
	// path specifically requires real seccomp notify FDs (privileged integration test).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before calling

	done := make(chan struct{})
	go func() {
		ServeNotifyWithExecve(ctx, r, "test-cancelled", nil, &handlerTestEmitter{}, nil, nil, nil)
		close(done)
	}()

	select {
	case <-done:
		// Good — exited promptly.
	case <-time.After(1 * time.Second):
		t.Fatal("ServeNotifyWithExecve did not exit with cancelled context")
	}
}

func TestServeNotifyWithExecve_DoesNotHangOnNonSeccompFD(t *testing.T) {
	// When given a pipe FD (not a real seccomp notify FD), NotifReceive
	// returns an error. The handler should exit via the error branch,
	// not spin forever.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		ServeNotifyWithExecve(ctx, r, "test-bad-fd", nil, &handlerTestEmitter{}, nil, nil, nil)
		close(done)
	}()

	select {
	case <-done:
		// Good — exited on ioctl error.
	case <-time.After(1 * time.Second):
		t.Fatal("ServeNotifyWithExecve did not exit with non-seccomp FD")
	}
}

// TestServeNotifyWithExecve_NilEmitterAllowed is a regression guard against
// reintroducing the emit==nil short-circuit that roborev flagged HIGH on
// commit 8f641891. The notify loop MUST keep serving notifications even
// without an emitter so block-list enforcement (SIGKILL under log_and_kill)
// still runs; only audit event emission should be conditional. If anyone
// re-adds `|| emit == nil` to the entry guard, block-list enforcement
// silently stops working in production.
//
// The test distinguishes the fixed path from the broken path by capturing
// slog output and asserting that seccomp.NotifReceive was actually invoked
// (which produces a "NotifReceive error" warning when called on a non-seccomp
// pipe fd). If the short-circuit is reintroduced, that log is absent because
// the function returns before reaching the loop, and the test fails.
func TestServeNotifyWithExecve_NilEmitterAllowed(t *testing.T) {
	var logBuf bytes.Buffer
	origLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(origLogger)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		// nil emit must be accepted — NotifReceive will still error on the
		// pipe fd and exit via the error branch, but the function must not
		// panic or return before attempting the receive.
		ServeNotifyWithExecve(ctx, r, "test-nil-emit", nil, nil, nil, nil, nil)
		close(done)
	}()

	select {
	case <-done:
		// Good — exited cleanly (via NotifReceive error on pipe fd).
	case <-time.After(1 * time.Second):
		t.Fatal("ServeNotifyWithExecve did not exit with nil emitter")
	}

	// Prove NotifReceive was actually called. The fixed path emits this warn;
	// the broken path (emit==nil short-circuit) returns before the loop and
	// never logs it. A timing-only check cannot distinguish the two.
	logs := logBuf.String()
	if !strings.Contains(logs, "NotifReceive error") {
		t.Fatalf("expected NotifReceive error log (proves loop was entered despite nil emitter), got logs: %s", logs)
	}
}

func TestServeNotify_DoesNotHangOnCancelledContext(t *testing.T) {
	// Same as above for the non-execve ServeNotify variant.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		ServeNotify(ctx, r, "test-cancelled", nil, &handlerTestEmitter{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("ServeNotify did not exit with cancelled context")
	}
}
