//go:build linux && amd64

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSyscallToOperation_LegacyAmd64(t *testing.T) {
	tests := []struct {
		name  string
		nr    int
		flags int
		want  string
	}{
		{"legacy open rdonly", unix.SYS_OPEN, unix.O_RDONLY, "read"},
		{"legacy open wronly", unix.SYS_OPEN, unix.O_WRONLY, "write"},
		{"legacy open creat", unix.SYS_OPEN, unix.O_WRONLY | unix.O_CREAT, "create"},
		{"legacy unlink", unix.SYS_UNLINK, 0, "delete"},
		{"legacy rename", unix.SYS_RENAME, 0, "rename"},
		{"legacy mkdir", unix.SYS_MKDIR, 0, "create"},
		{"legacy rmdir", unix.SYS_RMDIR, 0, "delete"},
		{"legacy link", unix.SYS_LINK, 0, "link"},
		{"legacy symlink", unix.SYS_SYMLINK, 0, "symlink"},
		{"legacy chmod", unix.SYS_CHMOD, 0, "chmod"},
		{"legacy chown", unix.SYS_CHOWN, 0, "chown"},
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
