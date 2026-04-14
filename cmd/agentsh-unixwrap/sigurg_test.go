//go:build linux && cgo

package main

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// readSigmask reads the current thread's signal mask via rt_sigprocmask.
func readSigmask() (uint64, error) {
	var oldset [1]uint64
	_, _, errno := unix.RawSyscall6(
		unix.SYS_RT_SIGPROCMASK,
		uintptr(unix.SIG_SETMASK),
		0, // nset = nil (read-only)
		uintptr(unsafe.Pointer(&oldset[0])),
		8,
		0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return oldset[0], nil
}

func TestBlockSIGURG(t *testing.T) {
	// Pin goroutine to OS thread — signal masks are per-thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Read mask before.
	before, err := readSigmask()
	require.NoError(t, err)
	sigurgBit := uint64(1) << (unix.SIGURG - 1)
	require.Zero(t, before&sigurgBit, "SIGURG should not be blocked before test")

	// Block SIGURG.
	blockSIGURG()

	// Read mask after.
	after, err := readSigmask()
	require.NoError(t, err)
	require.NotZero(t, after&sigurgBit, "SIGURG should be blocked after blockSIGURG()")

	// Clean up: unblock SIGURG so the thread is returned cleanly.
	var unset [1]uint64
	unset[0] = sigurgBit
	_, _, errno := unix.RawSyscall6(
		unix.SYS_RT_SIGPROCMASK,
		uintptr(unix.SIG_UNBLOCK),
		uintptr(unsafe.Pointer(&unset[0])),
		0, 8, 0, 0,
	)
	require.Zero(t, errno, "failed to unblock SIGURG in cleanup")
}
