//go:build linux && cgo

package unix

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// isOpenSyscall returns true if nr is an open-family syscall that returns a
// file descriptor. These are the syscalls eligible for AddFD emulation.
func isOpenSyscall(nr int32) bool {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
		return true
	default:
		return isLegacyOpenSyscallNr(nr)
	}
}

// isFileSyscall returns true if nr is a file I/O syscall we monitor.
func isFileSyscall(nr int32) bool {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2,
		unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHOWNAT,
		unix.SYS_STATX, unix.SYS_NEWFSTATAT, unix.SYS_FACCESSAT2,
		unix.SYS_READLINKAT, unix.SYS_MKNODAT:
		return true
	default:
		return isLegacyFileSyscall(nr)
	}
}

// shouldFallbackToContinue returns true when an open-family syscall should
// use CONTINUE instead of AddFD emulation. This applies when:
//   - openat2 has non-zero RESOLVE_* flags (the supervisor cannot replicate
//     these resolution semantics).
//   - O_TMPFILE is used (file has no path to open via /proc/<pid>/root).
func shouldFallbackToContinue(nr int32, flags uint32, resolveFlags uint64) bool {
	if resolveFlags != 0 {
		return true
	}
	if flags&unix.O_TMPFILE == unix.O_TMPFILE {
		return true
	}
	return false
}

// FileArgs holds parsed file syscall arguments.
type FileArgs struct {
	Dirfd   int32
	PathPtr uint64
	Flags   uint32
	Mode    uint32

	// For rename/link syscalls that operate on two paths.
	HasSecondPath bool
	Dirfd2        int32
	PathPtr2      uint64

	// For openat2: pointer to open_how struct in tracee memory.
	HowPtr uint64
}

// extractFileArgs extracts file arguments based on syscall number.
func extractFileArgs(args SyscallArgs) FileArgs {
	switch args.Nr {
	case unix.SYS_OPENAT:
		// openat(dirfd, path, flags, mode)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Flags:   uint32(args.Arg2),
			Mode:    uint32(args.Arg3),
		}

	case unix.SYS_OPENAT2:
		// openat2(dirfd, path, how, size)
		// Arg2 is a pointer to struct open_how in tracee memory.
		// Actual flags/mode must be read at runtime via ProcessVMReadv.
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			HowPtr:  args.Arg2,
		}

	case unix.SYS_UNLINKAT:
		// unlinkat(dirfd, path, flags)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Flags:   uint32(args.Arg2),
		}

	case unix.SYS_MKDIRAT:
		// mkdirat(dirfd, path, mode)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Mode:    uint32(args.Arg2),
		}

	case unix.SYS_RENAMEAT2:
		// renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
		return FileArgs{
			Dirfd:         int32(args.Arg0),
			PathPtr:       args.Arg1,
			Flags:         uint32(args.Arg4),
			HasSecondPath: true,
			Dirfd2:        int32(args.Arg2),
			PathPtr2:      args.Arg3,
		}

	case unix.SYS_LINKAT:
		// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
		return FileArgs{
			Dirfd:         int32(args.Arg0),
			PathPtr:       args.Arg1,
			Flags:         uint32(args.Arg4),
			HasSecondPath: true,
			Dirfd2:        int32(args.Arg2),
			PathPtr2:      args.Arg3,
		}

	case unix.SYS_SYMLINKAT:
		// symlinkat(target, newdirfd, linkpath)
		// Primary path is the linkpath (where the symlink is created).
		return FileArgs{
			Dirfd:   int32(args.Arg1), // newdirfd
			PathPtr: args.Arg2,        // linkpath
		}

	case unix.SYS_FCHMODAT:
		// fchmodat(dirfd, path, mode, flags)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Mode:    uint32(args.Arg2),
			Flags:   uint32(args.Arg3),
		}

	case unix.SYS_FCHOWNAT:
		// fchownat(dirfd, path, owner, group, flags)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Flags:   uint32(args.Arg4),
		}

	case unix.SYS_STATX:
		return FileArgs{Dirfd: int32(args.Arg0), PathPtr: args.Arg1, Flags: uint32(args.Arg2)}
	case unix.SYS_NEWFSTATAT:
		return FileArgs{Dirfd: int32(args.Arg0), PathPtr: args.Arg1, Flags: uint32(args.Arg3)}
	case unix.SYS_FACCESSAT2:
		return FileArgs{Dirfd: int32(args.Arg0), PathPtr: args.Arg1, Flags: uint32(args.Arg3)}
	case unix.SYS_READLINKAT:
		return FileArgs{Dirfd: int32(args.Arg0), PathPtr: args.Arg1}
	case unix.SYS_MKNODAT:
		return FileArgs{Dirfd: int32(args.Arg0), PathPtr: args.Arg1, Mode: uint32(args.Arg2)}

	default:
		return extractLegacyFileArgs(args)
	}
}

// readOpenHow reads the open_how struct from tracee memory for openat2 syscalls.
// struct open_how { __u64 flags; __u64 mode; __u64 resolve; }
func readOpenHow(pid int, howPtr uint64) (flags uint64, mode uint64, err error) {
	if howPtr == 0 {
		return 0, 0, ErrNullPtr
	}

	// open_how is 24 bytes: flags(8) + mode(8) + resolve(8)
	var buf [24]byte
	liov := unix.Iovec{Base: &buf[0], Len: 24}
	riov := unix.RemoteIovec{Base: uintptr(howPtr), Len: 24}

	_, err = unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: open_how: %v", ErrReadMemory, err)
	}

	// Parse little-endian uint64s
	flags = *(*uint64)(unsafe.Pointer(&buf[0]))
	mode = *(*uint64)(unsafe.Pointer(&buf[8]))
	return flags, mode, nil
}

// readOpenHowResolve reads only the resolve field (offset 16) from the
// openat2 open_how struct in tracee memory. Returns the resolve flags and
// an error. On error, the caller must force CONTINUE fallback — never
// emulate when resolve flags are unknown.
func readOpenHowResolve(pid int, howPtr uint64) (uint64, error) {
	if howPtr == 0 {
		return 0, nil
	}
	var buf [8]byte
	liov := unix.Iovec{Base: &buf[0], Len: 8}
	riov := unix.RemoteIovec{Base: uintptr(howPtr + 16), Len: 8}
	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err != nil {
		return 0, fmt.Errorf("read open_how resolve: %w", err)
	}
	return *(*uint64)(unsafe.Pointer(&buf[0])), nil
}

// syscallToOperation maps a file syscall number and flags to a policy operation string.
func syscallToOperation(nr int32, flags uint32) string {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
		// Create takes precedence over write
		if flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE {
			return "create"
		}
		if flags&(unix.O_WRONLY|unix.O_RDWR|unix.O_APPEND|unix.O_TRUNC) != 0 {
			return "write"
		}
		return "open"

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
	case unix.SYS_STATX, unix.SYS_NEWFSTATAT:
		return "stat"
	case unix.SYS_FACCESSAT2:
		return "access"
	case unix.SYS_READLINKAT:
		return "readlink"
	case unix.SYS_MKNODAT:
		return "mknod"
	default:
		return legacySyscallToOperation(nr, flags)
	}
}

// fileSyscallName returns the human-readable name for a file syscall number.
func fileSyscallName(nr int32) string {
	switch nr {
	case unix.SYS_OPENAT:
		return "openat"
	case unix.SYS_OPENAT2:
		return "openat2"
	case unix.SYS_UNLINKAT:
		return "unlinkat"
	case unix.SYS_MKDIRAT:
		return "mkdirat"
	case unix.SYS_RENAMEAT2:
		return "renameat2"
	case unix.SYS_LINKAT:
		return "linkat"
	case unix.SYS_SYMLINKAT:
		return "symlinkat"
	case unix.SYS_FCHMODAT:
		return "fchmodat"
	case unix.SYS_FCHOWNAT:
		return "fchownat"
	case unix.SYS_STATX:
		return "statx"
	case unix.SYS_NEWFSTATAT:
		return "newfstatat"
	case unix.SYS_FACCESSAT2:
		return "faccessat2"
	case unix.SYS_READLINKAT:
		return "readlinkat"
	case unix.SYS_MKNODAT:
		return "mknodat"
	default:
		return legacyFileSyscallName(nr)
	}
}

// resolvePathAt reads a path string from tracee memory and resolves it
// relative to the given dirfd. If the path is absolute, it is cleaned
// and returned directly. If relative, it is resolved against:
//   - /proc/<pid>/cwd when dirfd == AT_FDCWD (-100)
//   - /proc/<pid>/fd/<dirfd> otherwise
func resolvePathAt(pid int, dirfd int32, pathPtr uint64) (string, error) {
	path, err := readString(pid, pathPtr, 4096)
	if err != nil {
		return "", fmt.Errorf("read path from tracee: %w", err)
	}

	// Absolute path: clean and return
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}

	// Relative path: resolve against dirfd
	const atFDCWD = -100
	if dirfd == atFDCWD {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return "", fmt.Errorf("resolve cwd for pid %d: %w", pid, err)
		}
		return filepath.Clean(filepath.Join(cwd, path)), nil
	}

	// Resolve relative to dirfd
	dirPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
	if err != nil {
		return "", fmt.Errorf("resolve fd %d for pid %d: %w", dirfd, pid, err)
	}
	return filepath.Clean(filepath.Join(dirPath, path)), nil
}

// resolveProcFD detects and resolves /proc/self/fd/N, /proc/thread-self/fd/N,
// /proc/<pid>/fd/N, /dev/fd/N, and /dev/stdin|stdout|stderr paths to their
// actual targets. This prevents policy bypass by re-deriving paths from file
// descriptors.
//
// For /proc/<pid>/fd/N, accepts both the TID (task ID from seccomp notify)
// and the TGID (thread-group leader PID), since multi-threaded processes may
// reference either.
//
// Only substitutes the path when the resolved target is an absolute filesystem
// path. Pseudo-paths (pipe:[...], socket:[...], anon_inode:[...]) are left
// as-is since they are not subject to file policy.
func resolveProcFD(pid int, path string) (string, bool) {
	var fdStr string

	switch {
	case strings.HasPrefix(path, "/proc/self/fd/"):
		fdStr = path[len("/proc/self/fd/"):]
	case strings.HasPrefix(path, "/proc/thread-self/fd/"):
		fdStr = path[len("/proc/thread-self/fd/"):]
	case strings.HasPrefix(path, "/dev/fd/"):
		fdStr = path[len("/dev/fd/"):]
	case path == "/dev/stdin":
		fdStr = "0"
	case path == "/dev/stdout":
		fdStr = "1"
	case path == "/dev/stderr":
		fdStr = "2"
	default:
		if !matchesProcPidFD(pid, path, &fdStr) {
			return path, false
		}
	}

	if _, err := strconv.Atoi(fdStr); err != nil {
		return path, false
	}

	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fdStr))
	if err != nil {
		return path, false
	}

	// Only substitute when the resolved target is an absolute filesystem path.
	// Pseudo-paths like pipe:[12345], socket:[...], anon_inode:[...] are not
	// subject to file policy evaluation.
	if !strings.HasPrefix(target, "/") {
		return path, false
	}
	return target, true
}

// matchesProcPidFD checks if path matches /proc/<N>/fd/<M> where N is either
// the given pid (TID) or the thread-group leader (TGID) of that pid.
func matchesProcPidFD(pid int, path string, fdStr *string) bool {
	// Try exact TID match first.
	prefix := fmt.Sprintf("/proc/%d/fd/", pid)
	if strings.HasPrefix(path, prefix) {
		*fdStr = path[len(prefix):]
		return true
	}

	// Try TGID match — in multi-threaded processes, the TID from seccomp
	// notify may differ from the process-level PID (TGID).
	tgid := readTGID(pid)
	if tgid > 0 && tgid != pid {
		prefix = fmt.Sprintf("/proc/%d/fd/", tgid)
		if strings.HasPrefix(path, prefix) {
			*fdStr = path[len(prefix):]
			return true
		}
	}

	return false
}

// readTGID reads the thread group ID (Tgid) from /proc/<tid>/status.
func readTGID(tid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.Atoi(fields[1])
				if err == nil {
					return v
				}
			}
			break
		}
	}
	return 0
}
