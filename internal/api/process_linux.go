//go:build linux

package api

import (
	"fmt"
	"syscall"
)

// getSysProcAttrStopped returns SysProcAttr that starts the process in a stopped
// state using ptrace. This allows attaching eBPF/cgroups before the process
// executes any instructions, closing the race condition window.
func getSysProcAttrStopped() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
		Ptrace:  true, // Process will stop at first instruction
	}
}

// resumeTracedProcess resumes a process that was started with Ptrace=true.
// The process is stopped at the first instruction; this detaches ptrace
// and allows it to continue execution.
func resumeTracedProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	// Wait for the traced process to be in stopped state
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(pid, &ws, syscall.WALL, nil)
	if err != nil {
		return fmt.Errorf("wait for traced process: %w", err)
	}
	// Detach from the process, allowing it to continue
	if err := syscall.PtraceDetach(pid); err != nil {
		return fmt.Errorf("ptrace detach: %w", err)
	}
	return nil
}
