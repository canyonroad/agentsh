//go:build linux && amd64

package ptrace

import "golang.org/x/sys/unix"

func isLegacyFileSyscall(nr int) bool {
	switch nr {
	case unix.SYS_OPEN, unix.SYS_CREAT, unix.SYS_UNLINK, unix.SYS_RENAME,
		unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_LINK,
		unix.SYS_SYMLINK, unix.SYS_CHMOD, unix.SYS_CHOWN:
		return true
	}
	return false
}

func legacyFileSyscalls() []int {
	return []int{
		unix.SYS_OPEN, unix.SYS_CREAT, unix.SYS_UNLINK, unix.SYS_RENAME,
		unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_LINK,
		unix.SYS_SYMLINK, unix.SYS_CHMOD, unix.SYS_CHOWN,
	}
}
