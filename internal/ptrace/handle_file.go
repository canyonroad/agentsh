//go:build linux

package ptrace

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// syscallToOperation maps a file syscall number and flags to an operation string.
func syscallToOperation(nr int, flags int) string {
	switch nr {
	case unix.SYS_OPENAT:
		return openatOperation(flags)
	case unix.SYS_UNLINKAT:
		return "delete"
	case unix.SYS_MKDIRAT:
		return "create"
	case unix.SYS_RENAMEAT2:
		return "rename"
	case unix.SYS_LINKAT:
		return "link"
	case unix.SYS_SYMLINKAT:
		return "symlink"
	case unix.SYS_FCHMODAT:
		return "chmod"
	case unix.SYS_FCHOWNAT:
		return "chown"
	default:
		return syscallToOperationLegacy(nr, flags)
	}
}

func openatOperation(flags int) string {
	if flags&unix.O_CREAT != 0 {
		return "create"
	}
	if flags&(unix.O_WRONLY|unix.O_RDWR) != 0 {
		return "write"
	}
	return "read"
}

// resolveDirFD resolves the base directory for a *at syscall.
// AT_FDCWD (-100) returns the tracee's cwd. Otherwise reads /proc/<tid>/fd/<dirfd>.
func resolveDirFD(tid int, dirfd int) (string, error) {
	if dirfd == unix.AT_FDCWD {
		return os.Readlink(fmt.Sprintf("/proc/%d/cwd", tid))
	}
	return os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, dirfd))
}

// resolvePath resolves a path from a *at syscall to an absolute canonical path.
func resolvePath(tid int, dirfd int, path string) (string, error) {
	if filepath.IsAbs(path) {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return path, nil // Use original if symlink resolution fails
		}
		return resolved, nil
	}

	base, err := resolveDirFD(tid, dirfd)
	if err != nil {
		return "", fmt.Errorf("resolve dirfd %d: %w", dirfd, err)
	}

	full := filepath.Join(base, path)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return full, nil // Use joined path if symlink resolution fails
	}
	return resolved, nil
}
