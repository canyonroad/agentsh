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

func tracedSyscallNumbers() []int {
	nums := []int{
		unix.SYS_EXECVE, unix.SYS_EXECVEAT,
		unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2, unix.SYS_FCHOWNAT,
		unix.SYS_CONNECT, unix.SYS_SOCKET, unix.SYS_BIND,
		unix.SYS_SENDTO, unix.SYS_LISTEN,
		unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
		unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO,
	}
	nums = append(nums, legacyFileSyscalls()...)
	return nums
}
