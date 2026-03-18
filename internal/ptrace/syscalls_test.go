//go:build linux

package ptrace

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

// mockNetworkHandler is a minimal NetworkHandler implementation for testing.
type mockNetworkHandler struct{}

func (m *mockNetworkHandler) HandleNetwork(_ context.Context, _ NetworkContext) NetworkResult {
	return NetworkResult{Allow: true}
}

// allFeaturesConfig returns a TracerConfig with every feature enabled and a
// NetworkHandler set, suitable for testing that all syscalls appear.
func allFeaturesConfig() *TracerConfig {
	return &TracerConfig{
		TraceExecve:    true,
		TraceFile:      true,
		TraceNetwork:   true,
		TraceSignal:    true,
		MaskTracerPid:  true,
		NetworkHandler: &mockNetworkHandler{},
	}
}

func TestIsExecveSyscall(t *testing.T) {
	if !isExecveSyscall(unix.SYS_EXECVE) {
		t.Error("SYS_EXECVE should be classified as execve")
	}
	if !isExecveSyscall(unix.SYS_EXECVEAT) {
		t.Error("SYS_EXECVEAT should be classified as execve")
	}
	if isExecveSyscall(unix.SYS_READ) {
		t.Error("SYS_READ should not be classified as execve")
	}
}

func TestIsFileSyscall(t *testing.T) {
	if !isFileSyscall(unix.SYS_OPENAT) {
		t.Error("SYS_OPENAT should be a file syscall")
	}
	if !isFileSyscall(unix.SYS_UNLINKAT) {
		t.Error("SYS_UNLINKAT should be a file syscall")
	}
	if isFileSyscall(unix.SYS_READ) {
		t.Error("SYS_READ should not be a file syscall")
	}
}

func TestIsNetworkSyscall(t *testing.T) {
	if !isNetworkSyscall(unix.SYS_CONNECT) {
		t.Error("SYS_CONNECT should be a network syscall")
	}
	if !isNetworkSyscall(unix.SYS_SOCKET) {
		t.Error("SYS_SOCKET should be a network syscall")
	}
	if isNetworkSyscall(unix.SYS_READ) {
		t.Error("SYS_READ should not be a network syscall")
	}
}

func TestIsSignalSyscall(t *testing.T) {
	if !isSignalSyscall(unix.SYS_KILL) {
		t.Error("SYS_KILL should be a signal syscall")
	}
	if !isSignalSyscall(unix.SYS_TGKILL) {
		t.Error("SYS_TGKILL should be a signal syscall")
	}
	if isSignalSyscall(unix.SYS_READ) {
		t.Error("SYS_READ should not be a signal syscall")
	}
}

func TestTracedSyscallNumbers(t *testing.T) {
	cfg := allFeaturesConfig()
	nums := tracedSyscallNumbers(cfg)
	if len(nums) < 10 {
		t.Errorf("expected at least 10 traced syscalls, got %d", len(nums))
	}
	found := false
	for _, n := range nums {
		if n == unix.SYS_EXECVE {
			found = true
			break
		}
	}
	if !found {
		t.Error("SYS_EXECVE missing from traced syscalls")
	}
	// read/write must be present in the full set
	contains := func(nr int) bool {
		for _, n := range nums {
			if n == nr {
				return true
			}
		}
		return false
	}
	for _, nr := range []int{unix.SYS_READ, unix.SYS_PREAD64, unix.SYS_WRITE} {
		if !contains(nr) {
			t.Errorf("syscall %d missing from full traced set", nr)
		}
	}
}

func TestNarrowTracedSyscallNumbers_AllFeatures(t *testing.T) {
	cfg := allFeaturesConfig()
	nums := narrowTracedSyscallNumbers(cfg)

	contains := func(nr int) bool {
		for _, n := range nums {
			if n == nr {
				return true
			}
		}
		return false
	}

	// execve group
	if !contains(unix.SYS_EXECVE) {
		t.Error("SYS_EXECVE missing with TraceExecve=true")
	}
	// file group
	if !contains(unix.SYS_OPENAT) {
		t.Error("SYS_OPENAT missing with TraceFile=true")
	}
	// network group
	if !contains(unix.SYS_CONNECT) {
		t.Error("SYS_CONNECT missing with TraceNetwork=true")
	}
	if !contains(unix.SYS_BIND) {
		t.Error("SYS_BIND missing with TraceNetwork=true")
	}
	if !contains(unix.SYS_SENDTO) {
		t.Error("SYS_SENDTO missing with NetworkHandler set")
	}
	// signal group
	if !contains(unix.SYS_KILL) {
		t.Error("SYS_KILL missing with TraceSignal=true")
	}
	// close (MaskTracerPid=true)
	if !contains(unix.SYS_CLOSE) {
		t.Error("SYS_CLOSE missing with MaskTracerPid=true")
	}
	// read/write must NOT be in narrow set
	for _, nr := range []int{unix.SYS_READ, unix.SYS_PREAD64, unix.SYS_WRITE} {
		if contains(nr) {
			t.Errorf("syscall %d should not be in narrow set", nr)
		}
	}
	// socket and listen removed from narrow set
	if contains(unix.SYS_SOCKET) {
		t.Error("SYS_SOCKET must not appear in narrow set (always allowed by handleNetwork)")
	}
	if contains(unix.SYS_LISTEN) {
		t.Error("SYS_LISTEN must not appear in narrow set (always allowed by handleNetwork)")
	}
}

func TestNarrowTracedSyscallNumbers_NoFeatures(t *testing.T) {
	cfg := &TracerConfig{}
	nums := narrowTracedSyscallNumbers(cfg)
	if len(nums) != 0 {
		t.Errorf("expected empty list with no features enabled, got %d syscalls", len(nums))
	}
}

func TestNarrowTracedSyscallNumbers_NetworkWithoutHandler(t *testing.T) {
	cfg := &TracerConfig{
		TraceNetwork:   true,
		NetworkHandler: nil, // no DNS proxy
	}
	nums := narrowTracedSyscallNumbers(cfg)

	contains := func(nr int) bool {
		for _, n := range nums {
			if n == nr {
				return true
			}
		}
		return false
	}

	if !contains(unix.SYS_CONNECT) {
		t.Error("SYS_CONNECT missing with TraceNetwork=true")
	}
	if !contains(unix.SYS_BIND) {
		t.Error("SYS_BIND missing with TraceNetwork=true")
	}
	// sendto only with handler
	if contains(unix.SYS_SENDTO) {
		t.Error("SYS_SENDTO must not appear when NetworkHandler is nil")
	}
	// close not needed without MaskTracerPid and without NetworkHandler
	if contains(unix.SYS_CLOSE) {
		t.Error("SYS_CLOSE must not appear when MaskTracerPid=false and NetworkHandler=nil")
	}
}

func TestNarrowTracedSyscallNumbers_CloseWithMaskTracerPid(t *testing.T) {
	cfg := &TracerConfig{
		MaskTracerPid:  true,
		TraceNetwork:   false,
		NetworkHandler: nil,
	}
	nums := narrowTracedSyscallNumbers(cfg)

	for _, n := range nums {
		if n == unix.SYS_CLOSE {
			return
		}
	}
	t.Error("SYS_CLOSE missing when MaskTracerPid=true")
}

func TestNarrowTracedSyscallNumbers_CloseWithNetworkHandler(t *testing.T) {
	cfg := &TracerConfig{
		TraceNetwork:   true,
		NetworkHandler: &mockNetworkHandler{},
		MaskTracerPid:  false,
	}
	nums := narrowTracedSyscallNumbers(cfg)

	for _, n := range nums {
		if n == unix.SYS_CLOSE {
			return
		}
	}
	t.Error("SYS_CLOSE missing when TraceNetwork=true and NetworkHandler is set")
}
