//go:build linux

package ptrace

import "golang.org/x/sys/unix"

func isExecveSyscall(nr int) bool {
	return nr == unix.SYS_EXECVE || nr == unix.SYS_EXECVEAT
}

func isFileSyscall(nr int) bool {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2, unix.SYS_FCHOWNAT:
		return true
	}
	return isLegacyFileSyscall(nr)
}

func isNetworkSyscall(nr int) bool {
	switch nr {
	case unix.SYS_CONNECT, unix.SYS_SOCKET, unix.SYS_BIND,
		unix.SYS_SENDTO, unix.SYS_LISTEN:
		return true
	}
	return false
}

func isWriteSyscall(nr int) bool {
	return nr == unix.SYS_WRITE
}

func isReadSyscall(nr int) bool {
	return nr == unix.SYS_READ || nr == unix.SYS_PREAD64
}

func isCloseSyscall(nr int) bool {
	return nr == unix.SYS_CLOSE
}

func isSignalSyscall(nr int) bool {
	switch nr {
	case unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
		unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO:
		return true
	}
	return false
}

func tracedSyscallNumbers(cfg *TracerConfig) []int {
	nums := narrowTracedSyscallNumbers(cfg)
	// Full set includes read/write for TRACESYSGOOD fallback mode
	nums = append(nums, unix.SYS_READ, unix.SYS_PREAD64, unix.SYS_WRITE)
	return nums
}

// narrowTracedSyscallNumbers returns the syscalls for the initial narrow
// BPF filter, excluding read/pread64/write which are lazily escalated.
// The set is driven by cfg to avoid tracing syscalls for disabled features.
func narrowTracedSyscallNumbers(cfg *TracerConfig) []int {
	var nums []int

	if cfg.TraceExecve {
		nums = append(nums, unix.SYS_EXECVE, unix.SYS_EXECVEAT)
	}
	if cfg.TraceFile {
		nums = append(nums,
			unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
			unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
			unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2, unix.SYS_FCHOWNAT,
		)
		nums = append(nums, legacyFileSyscalls()...)
	}
	if cfg.TraceNetwork {
		nums = append(nums, unix.SYS_CONNECT, unix.SYS_BIND)
		if cfg.NetworkHandler != nil {
			nums = append(nums, unix.SYS_SENDTO)
		}
		// socket, listen: removed — always allowed by handleNetwork
	}
	if cfg.TraceSignal {
		nums = append(nums,
			unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
			unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO,
		)
	}
	if cfg.MaskTracerPid || (cfg.TraceNetwork && cfg.NetworkHandler != nil) {
		nums = append(nums, unix.SYS_CLOSE)
	}

	return nums
}

// AllFileSyscalls returns all file-related syscall numbers that the tracer
// intercepts. Exported for use by StaticAllowChecker implementations.
func AllFileSyscalls() []int {
	nums := []int{
		unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2, unix.SYS_FCHOWNAT,
	}
	nums = append(nums, legacyFileSyscalls()...)
	return nums
}

// isVforkSafeSyscall returns true for syscalls that are safe to allow without
// policy evaluation in a vfork child. These are async-signal-safe operations
// used by subprocess setup (close, dup2, sigaction, etc.). Anything not in
// this allowlist goes through normal policy evaluation.
func isVforkSafeSyscall(nr int) bool {
	switch nr {
	case unix.SYS_CLOSE,
		unix.SYS_DUP2, unix.SYS_DUP3,
		unix.SYS_FCNTL,
		unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN,
		unix.SYS_SETSID, unix.SYS_SETPGID, unix.SYS_GETPID, unix.SYS_GETPPID,
		unix.SYS_EXIT_GROUP, unix.SYS_EXIT,
		unix.SYS_CLOSE_RANGE:
		return true
	}
	return false
}

// AllNetworkSyscalls returns all network-related syscall numbers that the
// tracer intercepts (connect, bind, sendto). Exported for use by
// StaticAllowChecker implementations.
func AllNetworkSyscalls() []int {
	return []int{unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_SENDTO}
}
