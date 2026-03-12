//go:build linux

package ptrace

import (
	"context"
	"fmt"
	"log/slog"
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
		if flags&unix.AT_REMOVEDIR != 0 {
			return "rmdir"
		}
		return "delete"
	case unix.SYS_MKDIRAT:
		return "mkdir"
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
	if flags&unix.O_TMPFILE == unix.O_TMPFILE {
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
// For nonexistent files (e.g. create operations), resolves the parent directory
// and appends the basename.
func resolvePath(tid int, dirfd int, path string) (string, error) {
	var full string
	if filepath.IsAbs(path) {
		full = path
	} else {
		base, err := resolveDirFD(tid, dirfd)
		if err != nil {
			return "", fmt.Errorf("resolve dirfd %d: %w", dirfd, err)
		}
		full = filepath.Join(base, path)
	}

	resolved, err := filepath.EvalSymlinks(full)
	if err == nil {
		return resolved, nil
	}

	// Only fall back for nonexistent files (e.g. create operations).
	// For other errors (EACCES, ELOOP, ENOTDIR), propagate them so
	// callers can fail closed rather than operating on an unresolved path.
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("resolve path %q: %w", full, err)
	}

	// File doesn't exist yet — resolve the parent directory to
	// canonicalize any symlinked path components.
	dir := filepath.Dir(full)
	base := filepath.Base(full)
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return full, nil // Parent doesn't exist either; use best-effort path
		}
		return "", fmt.Errorf("resolve parent %q: %w", dir, err)
	}
	return filepath.Join(resolvedDir, base), nil
}

// handleFile intercepts file syscalls for policy evaluation.
func (t *Tracer) handleFile(ctx context.Context, tid int, regs Regs) {
	if t.cfg.FileHandler == nil || !t.cfg.TraceFile {
		t.allowSyscall(tid)
		return
	}

	nr := regs.SyscallNr()

	path, path2, flags, err := t.extractFileArgs(tid, nr, regs)
	if err != nil {
		slog.Warn("handleFile: cannot extract args, denying", "tid", tid, "nr", nr, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	operation := syscallToOperation(nr, flags)

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	result := t.cfg.FileHandler.HandleFile(ctx, FileContext{
		PID:       tgid,
		SessionID: sessionID,
		Syscall:   nr,
		Path:      path,
		Path2:     path2,
		Operation: operation,
		Flags:     flags,
	})

	if !result.Allow {
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EACCES)
		}
		t.denySyscall(tid, int(errno))
	} else {
		t.allowSyscall(tid)
	}
}

// extractFileArgs reads file syscall arguments from registers and tracee memory.
func (t *Tracer) extractFileArgs(tid int, nr int, regs Regs) (path, path2 string, flags int, err error) {
	switch nr {
	case unix.SYS_OPENAT:
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		flags = int(int32(regs.Arg(2)))
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, dirfd, rawPath)
		return path, "", flags, err

	case unix.SYS_UNLINKAT, unix.SYS_MKDIRAT:
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		flags = int(int32(regs.Arg(2))) // AT_REMOVEDIR for unlinkat
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, dirfd, rawPath)
		return path, "", flags, err

	case unix.SYS_FCHMODAT, unix.SYS_FCHOWNAT:
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, dirfd, rawPath)
		return path, "", 0, err

	case unix.SYS_RENAMEAT2:
		oldDirfd := int(int32(regs.Arg(0)))
		oldPathPtr := regs.Arg(1)
		newDirfd := int(int32(regs.Arg(2)))
		newPathPtr := regs.Arg(3)

		rawOld, err := t.readString(tid, oldPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		rawNew, err := t.readString(tid, newPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, oldDirfd, rawOld)
		if err != nil {
			return "", "", 0, err
		}
		path2, err = resolvePath(tid, newDirfd, rawNew)
		return path, path2, 0, err

	case unix.SYS_LINKAT:
		oldDirfd := int(int32(regs.Arg(0)))
		oldPathPtr := regs.Arg(1)
		newDirfd := int(int32(regs.Arg(2)))
		newPathPtr := regs.Arg(3)

		rawOld, err := t.readString(tid, oldPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		rawNew, err := t.readString(tid, newPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, oldDirfd, rawOld)
		if err != nil {
			return "", "", 0, err
		}
		path2, err = resolvePath(tid, newDirfd, rawNew)
		return path, path2, 0, err

	case unix.SYS_SYMLINKAT:
		targetPtr := regs.Arg(0)
		newDirfd := int(int32(regs.Arg(1)))
		linkPathPtr := regs.Arg(2)

		target, err := t.readString(tid, targetPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		rawLink, err := t.readString(tid, linkPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, newDirfd, rawLink)
		return path, target, 0, err

	default:
		return t.extractLegacyFileArgs(tid, nr, regs)
	}
}

// extractLegacyFileArgs handles legacy (non-at) file syscalls.
// On arm64 this is never called because isLegacyFileSyscall returns false.
func (t *Tracer) extractLegacyFileArgs(tid int, nr int, regs Regs) (path, path2 string, flags int, err error) {
	pathPtr := regs.Arg(0)
	rawPath, err := t.readString(tid, pathPtr, 4096)
	if err != nil {
		return "", "", 0, err
	}
	path, err = resolvePath(tid, unix.AT_FDCWD, rawPath)
	if err != nil {
		return "", "", 0, err
	}

	switch {
	case isLegacyOpenSyscall(nr):
		flags = int(int32(regs.Arg(1)))
		return path, "", flags, nil
	case isLegacySymlinkSyscall(nr):
		// symlink(target, linkpath): arg0=target, arg1=linkpath
		// Path should be the link path (arg1), Path2 should be the target (arg0)
		linkPathPtr := regs.Arg(1)
		rawLinkPath, err := t.readString(tid, linkPathPtr, 4096)
		if err != nil {
			return path, "", 0, err
		}
		linkPath, err := resolvePath(tid, unix.AT_FDCWD, rawLinkPath)
		if err != nil {
			return path, "", 0, err
		}
		// path (from arg0) is the target string, linkPath is the resolved link path
		return linkPath, rawPath, 0, nil
	case isLegacyTwoPathSyscall(nr):
		// rename(old, new), link(old, new)
		path2Ptr := regs.Arg(1)
		rawPath2, err := t.readString(tid, path2Ptr, 4096)
		if err != nil {
			return path, "", 0, err
		}
		path2, err = resolvePath(tid, unix.AT_FDCWD, rawPath2)
		return path, path2, 0, err
	default:
		return path, "", 0, nil
	}
}
