//go:build linux

package api

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
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

// SIGSYSInfo contains information about a process killed by SIGSYS (seccomp).
type SIGSYSInfo struct {
	PID    int
	Signal syscall.Signal
	Comm   string
}

// checkSIGSYS checks if an exec.ExitError indicates the process was killed by SIGSYS.
// SIGSYS is sent when seccomp kills a process for making a blocked syscall.
// Returns SIGSYSInfo if the process was killed by SIGSYS, nil otherwise.
func checkSIGSYS(err error) *SIGSYSInfo {
	if err == nil {
		return nil
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return nil
	}
	ps := ee.ProcessState
	if ps == nil {
		return nil
	}
	ws, ok := ps.Sys().(syscall.WaitStatus)
	if !ok {
		return nil
	}
	if !ws.Signaled() {
		return nil
	}
	sig := ws.Signal()
	if sig != unix.SIGSYS {
		return nil
	}
	return &SIGSYSInfo{
		PID:    ps.Pid(),
		Signal: sig,
		Comm:   getProcessComm(ps.Pid()),
	}
}

// getProcessComm attempts to get the command name for a process.
// Returns empty string if not available (process may have already exited).
func getProcessComm(pid int) string {
	if pid <= 0 {
		return ""
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	// comm file includes trailing newline
	comm := string(data)
	if len(comm) > 0 && comm[len(comm)-1] == '\n' {
		comm = comm[:len(comm)-1]
	}
	return comm
}
