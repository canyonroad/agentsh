//go:build linux && amd64

package ptrace

import "golang.org/x/sys/unix"

func syscallToOperationLegacy(nr int, flags int) string {
	switch nr {
	case unix.SYS_OPEN:
		return openatOperation(flags)
	case unix.SYS_UNLINK:
		return "delete"
	case unix.SYS_RMDIR:
		return "rmdir"
	case unix.SYS_RENAME:
		return "rename"
	case unix.SYS_MKDIR:
		return "mkdir"
	case unix.SYS_LINK:
		return "link"
	case unix.SYS_SYMLINK:
		return "symlink"
	case unix.SYS_CHMOD:
		return "chmod"
	case unix.SYS_CHOWN:
		return "chown"
	default:
		return "unknown"
	}
}

func isLegacyOpenSyscall(nr int) bool {
	return nr == unix.SYS_OPEN
}

func isLegacyTwoPathSyscall(nr int) bool {
	return nr == unix.SYS_RENAME || nr == unix.SYS_LINK
}

func isLegacySymlinkSyscall(nr int) bool {
	return nr == unix.SYS_SYMLINK
}
