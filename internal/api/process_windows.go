//go:build windows

package api

import (
	"os"
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/windows"
)

// killProcess terminates a process on Windows.
// Windows doesn't have process groups in the Unix sense, so we terminate the process directly.
func killProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.TerminateProcess(handle, 1)
}

// killProcessHard terminates a process forcefully on Windows.
// On Windows, TerminateProcess is always immediate (like SIGKILL).
func killProcessHard(pid int) error {
	return killProcess(pid)
}

// killProcessGroup terminates a process on Windows.
// Windows doesn't have Unix-style process groups. Job Objects are used instead,
// but for simple cases we just terminate the main process.
func killProcessGroup(pgid int) error {
	if pgid <= 0 {
		return nil
	}
	return killProcess(pgid)
}

// getSysProcAttr returns platform-specific SysProcAttr for process creation.
// On Windows, we use CREATE_NEW_PROCESS_GROUP for similar behavior to Unix Setpgid.
func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// getSysProcAttrStopped returns SysProcAttr for starting a process in stopped state.
// On Windows, ptrace is not available, so this returns the same as getSysProcAttr.
// The race condition mitigation is not available on Windows.
func getSysProcAttrStopped() *syscall.SysProcAttr {
	return getSysProcAttr()
}

// resumeTracedProcess resumes a process started with ptrace.
// On Windows, ptrace is not available, so this is a no-op.
func resumeTracedProcess(pid int) error {
	return nil
}

// getProcessGroupID returns the process ID on Windows.
// Windows doesn't have process groups like Unix, so we return the PID itself.
func getProcessGroupID(pid int) int {
	return pid
}

// resourcesFromProcessState extracts resource usage from process state.
// On Windows, we use GetProcessTimes for CPU time. Peak memory requires
// additional API calls that aren't available through ProcessState.
func resourcesFromProcessState(ps *os.ProcessState) types.ExecResources {
	if ps == nil {
		return types.ExecResources{}
	}

	// On Windows, SysUsage returns *syscall.Rusage but fields differ from Unix.
	// We need to use GetProcessTimes for accurate data.
	// For now, return empty - the Windows ProcessState doesn't expose Rusage properly.
	// TODO: Use GetProcessTimes and GetProcessMemoryInfo for accurate Windows stats.

	return types.ExecResources{}
}
