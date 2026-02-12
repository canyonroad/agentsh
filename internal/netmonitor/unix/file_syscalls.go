//go:build linux && cgo

package unix

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// isFileSyscall returns true if nr is a file I/O syscall we monitor.
func isFileSyscall(nr int32) bool {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2,
		unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHOWNAT:
		return true
	default:
		return false
	}
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
		// openat2(dirfd, path, how, size) -- flags at Arg2 (how struct pointer)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Flags:   uint32(args.Arg2),
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

	default:
		return FileArgs{}
	}
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
	default:
		return ""
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
	default:
		return ""
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
