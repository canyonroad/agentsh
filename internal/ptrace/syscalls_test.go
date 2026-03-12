//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

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
	nums := tracedSyscallNumbers()
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
}
