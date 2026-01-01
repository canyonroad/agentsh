//go:build darwin

package api

import (
	"syscall"
)

// getSysProcAttrStopped returns SysProcAttr for process creation.
// On macOS, ptrace-based stopped start is not supported, so we just
// return the regular SysProcAttr with Setpgid.
func getSysProcAttrStopped() *syscall.SysProcAttr {
	// macOS doesn't support Ptrace field in SysProcAttr the same way Linux does
	return &syscall.SysProcAttr{Setpgid: true}
}

// resumeTracedProcess is a no-op on macOS since we don't use ptrace.
func resumeTracedProcess(pid int) error {
	// No-op on macOS - process is not started in stopped state
	return nil
}
