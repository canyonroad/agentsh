//go:build linux

package ptrace

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// syscallToOperation maps a file syscall number and flags to an operation string.
func syscallToOperation(nr int, flags int) string {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
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
	case unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2:
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
	return "open"
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
// This follows symlinks on the final component (suitable for openat, fchmodat
// without AT_SYMLINK_NOFOLLOW, etc.). For nonexistent files (e.g. create
// operations), resolves the parent directory and appends the basename.
func resolvePath(tid int, dirfd int, path string) (string, error) {
	full, err := resolveToAbsolute(tid, dirfd, path)
	if err != nil {
		return "", err
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

	// Guard against dangling symlinks: if the leaf itself exists as a symlink
	// but its target doesn't, Lstat will succeed. The kernel would follow the
	// symlink on O_CREAT, potentially creating a file in a forbidden directory.
	// Fail closed because we can't determine the real target path.
	if fi, lstatErr := os.Lstat(full); lstatErr == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("resolve path %q: dangling symlink", full)
	}

	return resolveParentFallback(full)
}

// resolvePathNoFollow resolves a path without following the final symlink
// component. Used for syscalls that operate on directory entries rather than
// their targets (e.g. unlinkat, renameat2, linkat newpath).
func resolvePathNoFollow(tid int, dirfd int, path string) (string, error) {
	full, err := resolveToAbsolute(tid, dirfd, path)
	if err != nil {
		return "", err
	}
	return resolveParentFallback(full)
}

// resolveToAbsolute converts a potentially relative path to an absolute path
// using the dirfd for resolution. Does NOT clean the path (no filepath.Join)
// to preserve ".." components for correct symlink traversal semantics.
func resolveToAbsolute(tid int, dirfd int, path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	base, err := resolveDirFD(tid, dirfd)
	if err != nil {
		return "", fmt.Errorf("resolve dirfd %d: %w", dirfd, err)
	}
	return base + "/" + path, nil
}

// resolveParentFallback resolves the parent directory with EvalSymlinks and
// joins the leaf basename. This canonicalizes parent components without
// following the final component.
func resolveParentFallback(full string) (string, error) {
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

	// Dispatch based on Action field (new path) or Allow field (legacy path).
	action := result.Action
	if action == "" {
		if result.Allow {
			action = "allow"
		} else {
			action = "deny"
		}
	}

	switch action {
	case "allow", "continue":
		t.allowSyscall(tid)
	case "deny":
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EACCES)
		}
		t.denySyscall(tid, int(errno))
	case "redirect":
		t.redirectFile(ctx, tid, regs, nr, result)
	case "soft-delete":
		t.softDeleteFile(ctx, tid, regs, result)
	default:
		slog.Warn("handleFile: unknown action, denying", "tid", tid, "action", action)
		t.denySyscall(tid, int(unix.EACCES))
	}
}

// redirectFile redirects a file syscall to a different path.
func (t *Tracer) redirectFile(ctx context.Context, tid int, regs Regs, nr int, result FileResult) {
	slog.Warn("redirectFile: not yet implemented, denying", "tid", tid)
	t.denySyscall(tid, int(unix.EACCES))
}

// softDeleteFile performs a soft-delete by moving the file to trash.
func (t *Tracer) softDeleteFile(ctx context.Context, tid int, regs Regs, result FileResult) {
	slog.Warn("softDeleteFile: not yet implemented, denying", "tid", tid)
	t.denySyscall(tid, int(unix.EACCES))
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
		if flags&unix.O_NOFOLLOW != 0 {
			path, err = resolvePathNoFollow(tid, dirfd, rawPath)
		} else {
			path, err = resolvePath(tid, dirfd, rawPath)
		}
		return path, "", flags, err

	case unix.SYS_OPENAT2:
		// openat2(dirfd, path, how, size): how is a pointer to struct open_how
		// struct open_how { __u64 flags; __u64 mode; __u64 resolve; }
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		howPtr := regs.Arg(2)
		howSize := regs.Arg(3)
		// The kernel requires at least 24 bytes (OPEN_HOW_SIZE_VER0).
		// Future kernels may extend the struct, so allow larger sizes.
		if howSize < 24 {
			return "", "", 0, fmt.Errorf("openat2 size too small: %d", howSize)
		}
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		// Read at least the first 24 bytes (flags + mode + resolve).
		readSize := howSize
		if readSize > 64 {
			readSize = 64 // Cap read to avoid excessive memory allocation
		}
		howBuf := make([]byte, readSize)
		if err := t.readBytes(tid, howPtr, howBuf); err != nil {
			return "", "", 0, fmt.Errorf("read open_how: %w", err)
		}
		flags = int(binary.NativeEndian.Uint64(howBuf[0:8]))
		// If resolve flags are set, the kernel applies restricted path
		// resolution (RESOLVE_IN_ROOT, RESOLVE_BENEATH, etc.) that we
		// cannot replicate. Fail closed.
		resolve := binary.NativeEndian.Uint64(howBuf[16:24])
		if resolve != 0 {
			return "", "", 0, fmt.Errorf("openat2 resolve flags 0x%x not supported", resolve)
		}
		if flags&unix.O_NOFOLLOW != 0 {
			path, err = resolvePathNoFollow(tid, dirfd, rawPath)
		} else {
			path, err = resolvePath(tid, dirfd, rawPath)
		}
		return path, "", flags, err

	case unix.SYS_UNLINKAT, unix.SYS_MKDIRAT:
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		flags = int(int32(regs.Arg(2))) // AT_REMOVEDIR for unlinkat
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		// These syscalls operate on directory entries, not symlink targets.
		path, err = resolvePathNoFollow(tid, dirfd, rawPath)
		return path, "", flags, err

	case unix.SYS_FCHMODAT:
		// fchmodat(dirfd, path, mode) — 3-arg syscall, always follows symlinks.
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, dirfd, rawPath)
		return path, "", 0, err

	case unix.SYS_FCHMODAT2:
		// fchmodat2(dirfd, path, mode, flags) — 4-arg syscall with flag support.
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		atFlags := int(int32(regs.Arg(3)))
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		if rawPath == "" && atFlags&unix.AT_EMPTY_PATH != 0 {
			path, err = resolveDirFD(tid, dirfd)
			return path, "", 0, err
		}
		if atFlags&unix.AT_SYMLINK_NOFOLLOW != 0 {
			path, err = resolvePathNoFollow(tid, dirfd, rawPath)
		} else {
			path, err = resolvePath(tid, dirfd, rawPath)
		}
		return path, "", 0, err

	case unix.SYS_FCHOWNAT:
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		// fchownat(dirfd, path, owner, group, flags): flags in arg4
		atFlags := int(int32(regs.Arg(4)))
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		if rawPath == "" && atFlags&unix.AT_EMPTY_PATH != 0 {
			path, err = resolveDirFD(tid, dirfd)
			return path, "", 0, err
		}
		if atFlags&unix.AT_SYMLINK_NOFOLLOW != 0 {
			path, err = resolvePathNoFollow(tid, dirfd, rawPath)
		} else {
			path, err = resolvePath(tid, dirfd, rawPath)
		}
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
		// rename operates on directory entries, not symlink targets.
		path, err = resolvePathNoFollow(tid, oldDirfd, rawOld)
		if err != nil {
			return "", "", 0, err
		}
		path2, err = resolvePathNoFollow(tid, newDirfd, rawNew)
		return path, path2, 0, err

	case unix.SYS_LINKAT:
		oldDirfd := int(int32(regs.Arg(0)))
		oldPathPtr := regs.Arg(1)
		newDirfd := int(int32(regs.Arg(2)))
		newPathPtr := regs.Arg(3)
		linkFlags := int(int32(regs.Arg(4)))

		rawOld, err := t.readString(tid, oldPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		rawNew, err := t.readString(tid, newPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		// AT_EMPTY_PATH: old path is "" and references the inode via olddirfd.
		if rawOld == "" && linkFlags&unix.AT_EMPTY_PATH != 0 {
			path, err = resolveDirFD(tid, oldDirfd)
		} else if linkFlags&unix.AT_SYMLINK_FOLLOW != 0 {
			path, err = resolvePath(tid, oldDirfd, rawOld)
		} else {
			path, err = resolvePathNoFollow(tid, oldDirfd, rawOld)
		}
		if err != nil {
			return "", "", 0, err
		}
		// New path is always a directory entry.
		path2, err = resolvePathNoFollow(tid, newDirfd, rawNew)
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
		// The link path is a new directory entry.
		path, err = resolvePathNoFollow(tid, newDirfd, rawLink)
		return path, target, 0, err

	default:
		return t.extractLegacyFileArgs(tid, nr, regs)
	}
}

// extractLegacyFileArgs handles legacy (non-at) file syscalls.
// On arm64 this is never called because isLegacyFileSyscall returns false.
func (t *Tracer) extractLegacyFileArgs(tid int, nr int, regs Regs) (path, path2 string, flags int, err error) {
	// For symlink(target, linkpath), arg0 is the raw target string which
	// should NOT be resolved — it can be an arbitrary string including
	// nonexistent or unresolvable paths. Handle it before resolving arg0.
	if isLegacySymlinkSyscall(nr) {
		targetPtr := regs.Arg(0)
		target, err := t.readString(tid, targetPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		linkPathPtr := regs.Arg(1)
		rawLinkPath, err := t.readString(tid, linkPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		// The link path is a new directory entry.
		linkPath, err := resolvePathNoFollow(tid, unix.AT_FDCWD, rawLinkPath)
		if err != nil {
			return "", "", 0, err
		}
		return linkPath, target, 0, nil
	}

	pathPtr := regs.Arg(0)
	rawPath, err := t.readString(tid, pathPtr, 4096)
	if err != nil {
		return "", "", 0, err
	}

	switch {
	case isLegacyOpenSyscall(nr):
		flags = int(int32(regs.Arg(1)))
		if flags&unix.O_NOFOLLOW != 0 {
			path, err = resolvePathNoFollow(tid, unix.AT_FDCWD, rawPath)
		} else {
			path, err = resolvePath(tid, unix.AT_FDCWD, rawPath)
		}
		if err != nil {
			return "", "", 0, err
		}
		return path, "", flags, nil
	case isLegacyCreatSyscall(nr):
		// creat(path, mode) is O_CREAT|O_WRONLY|O_TRUNC — always creates.
		path, err = resolvePath(tid, unix.AT_FDCWD, rawPath)
		if err != nil {
			return "", "", 0, err
		}
		return path, "", unix.O_CREAT | unix.O_WRONLY | unix.O_TRUNC, nil
	case isLegacyTwoPathSyscall(nr):
		// rename(old, new), link(old, new) — operate on entries, not targets.
		path, err = resolvePathNoFollow(tid, unix.AT_FDCWD, rawPath)
		if err != nil {
			return "", "", 0, err
		}
		path2Ptr := regs.Arg(1)
		rawPath2, err := t.readString(tid, path2Ptr, 4096)
		if err != nil {
			return path, "", 0, err
		}
		path2, err = resolvePathNoFollow(tid, unix.AT_FDCWD, rawPath2)
		return path, path2, 0, err
	case isLegacyChmodChownSyscall(nr):
		// chmod/chown follow symlinks on the final component.
		path, err = resolvePath(tid, unix.AT_FDCWD, rawPath)
		if err != nil {
			return "", "", 0, err
		}
		return path, "", 0, nil
	default:
		// unlink, rmdir, mkdir — operate on directory entries.
		path, err = resolvePathNoFollow(tid, unix.AT_FDCWD, rawPath)
		if err != nil {
			return "", "", 0, err
		}
		return path, "", 0, nil
	}
}
