//go:build linux && cgo

package unix

import (
	"context"
	"os"
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

func TestServeNotifyWithExecve_ExitsOnCancelledContext(t *testing.T) {
	// With a pre-cancelled context, the select { case <-ctx.Done(): return }
	// at the top of the first loop iteration should fire immediately,
	// BEFORE NotifReceive is ever called. We verify this by checking the
	// function returns in < 50ms (the EAGAIN retry path sleeps 10ms).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before calling

	start := time.Now()
	done := make(chan struct{})
	go func() {
		ServeNotifyWithExecve(ctx, r, "test-cancelled", nil, &handlerTestEmitter{}, nil, nil)
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed > 50*time.Millisecond {
			t.Errorf("took %v — likely went through NotifReceive instead of ctx.Done() path", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("ServeNotifyWithExecve did not exit with cancelled context")
	}
}

func TestServeNotifyWithExecve_ExitsOnNonSeccompFD(t *testing.T) {
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
		ServeNotifyWithExecve(ctx, r, "test-bad-fd", nil, &handlerTestEmitter{}, nil, nil)
		close(done)
	}()

	select {
	case <-done:
		// Good — exited on ioctl error.
	case <-time.After(1 * time.Second):
		t.Fatal("ServeNotifyWithExecve did not exit with non-seccomp FD")
	}
}

func TestServeNotify_ExitsOnCancelledContext(t *testing.T) {
	// Same pre-cancelled context test for the non-execve ServeNotify variant.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		ServeNotify(ctx, r, "test-cancelled", nil, &handlerTestEmitter{})
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed > 50*time.Millisecond {
			t.Errorf("took %v — likely went through NotifReceive instead of ctx.Done() path", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("ServeNotify did not exit with cancelled context")
	}
}
