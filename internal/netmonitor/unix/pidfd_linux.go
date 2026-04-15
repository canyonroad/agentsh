//go:build linux

package unix

import (
	gounix "golang.org/x/sys/unix"
)

// Test seams. Production code goes through these indirections so tests
// can inject ESRCH/EPERM/EINVAL without spawning real processes.
var (
	pidfdOpenFn       = pidfdOpen
	pidfdSendSignalFn = pidfdSendSignal
)

// pidfdOpen calls the pidfd_open syscall. Requires Linux 5.3+.
func pidfdOpen(pid int) (int, error) {
	r, _, errno := gounix.Syscall(gounix.SYS_PIDFD_OPEN, uintptr(pid), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// pidfdSendSignal sends a signal via pidfd_send_signal. Requires Linux 5.1+.
// Passing 0 for info means "use the default siginfo" (kernel builds it).
func pidfdSendSignal(pidfd int, sig gounix.Signal) error {
	_, _, errno := gounix.Syscall6(gounix.SYS_PIDFD_SEND_SIGNAL,
		uintptr(pidfd), uintptr(sig), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
