//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSyscallToOperation(t *testing.T) {
	tests := []struct {
		name  string
		nr    int
		flags int
		want  string
	}{
		{"openat read-only", unix.SYS_OPENAT, unix.O_RDONLY, "read"},
		{"openat write-only", unix.SYS_OPENAT, unix.O_WRONLY, "write"},
		{"openat read-write", unix.SYS_OPENAT, unix.O_RDWR, "write"},
		{"openat create", unix.SYS_OPENAT, unix.O_WRONLY | unix.O_CREAT, "create"},
		{"openat create rdwr", unix.SYS_OPENAT, unix.O_RDWR | unix.O_CREAT, "create"},
		{"openat trunc", unix.SYS_OPENAT, unix.O_WRONLY | unix.O_TRUNC, "write"},
		{"openat tmpfile", unix.SYS_OPENAT, unix.O_TMPFILE | unix.O_RDWR, "create"},
		{"unlinkat", unix.SYS_UNLINKAT, 0, "delete"},
		{"unlinkat removedir", unix.SYS_UNLINKAT, unix.AT_REMOVEDIR, "rmdir"},
		{"mkdirat", unix.SYS_MKDIRAT, 0, "mkdir"},
		{"renameat2", unix.SYS_RENAMEAT2, 0, "rename"},
		{"linkat", unix.SYS_LINKAT, 0, "link"},
		{"symlinkat", unix.SYS_SYMLINKAT, 0, "symlink"},
		{"fchmodat", unix.SYS_FCHMODAT, 0, "chmod"},
		{"fchownat", unix.SYS_FCHOWNAT, 0, "chown"},
		{"unknown", 99999, 0, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := syscallToOperation(tt.nr, tt.flags)
			if got != tt.want {
				t.Errorf("syscallToOperation(%d, %d) = %q, want %q", tt.nr, tt.flags, got, tt.want)
			}
		})
	}
}
