//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsWriteSyscall(t *testing.T) {
	tests := []struct {
		nr   int
		want bool
	}{
		{unix.SYS_WRITE, true},
		{unix.SYS_READ, false},
		{unix.SYS_OPENAT, false},
	}
	for _, tt := range tests {
		if got := isWriteSyscall(tt.nr); got != tt.want {
			t.Errorf("isWriteSyscall(%d) = %v, want %v", tt.nr, got, tt.want)
		}
	}
}

func TestIsReadSyscall(t *testing.T) {
	tests := []struct {
		nr   int
		want bool
	}{
		{unix.SYS_READ, true},
		{unix.SYS_PREAD64, true},
		{unix.SYS_WRITE, false},
	}
	for _, tt := range tests {
		if got := isReadSyscall(tt.nr); got != tt.want {
			t.Errorf("isReadSyscall(%d) = %v, want %v", tt.nr, got, tt.want)
		}
	}
}

func TestIsCloseSyscall(t *testing.T) {
	if !isCloseSyscall(unix.SYS_CLOSE) {
		t.Error("SYS_CLOSE should be classified as close syscall")
	}
	if isCloseSyscall(unix.SYS_OPENAT) {
		t.Error("SYS_OPENAT should not be classified as close syscall")
	}
}
