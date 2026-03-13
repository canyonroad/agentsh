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

// legacyFilePathArgIndex returns the register index containing the path pointer
// for legacy (non-at) file syscalls on amd64. Returns -1 if unsupported.
func legacyFilePathArgIndex(nr int) int {
	switch nr {
	case unix.SYS_OPEN, unix.SYS_CREAT, unix.SYS_UNLINK,
		unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_CHMOD, unix.SYS_CHOWN:
		return 0
	case unix.SYS_RENAME:
		return 0 // oldpath; newpath is arg1
	case unix.SYS_LINK:
		return 0 // oldpath; newpath is arg1
	case unix.SYS_SYMLINK:
		return 0 // target; linkpath is arg1
	}
	return -1
}

// isLegacyUnlink returns true if nr is the legacy SYS_UNLINK syscall.
func isLegacyUnlink(nr int) bool {
	return nr == unix.SYS_UNLINK
}
