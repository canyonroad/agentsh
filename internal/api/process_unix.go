//go:build !windows

package api

import (
	"fmt"
	"os"
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
)

// killProcess sends SIGTERM then SIGKILL to a process and its process group.
func killProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	// Send to process group (negative pid)
	return syscall.Kill(-pid, syscall.SIGTERM)
}

// killProcessHard sends SIGKILL to a process and its process group.
func killProcessHard(pid int) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(-pid, syscall.SIGKILL)
}

// killProcessGroup kills an entire process group.
func killProcessGroup(pgid int) error {
	if pgid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
		fmt.Fprintf(os.Stderr, "exec: failed to kill process group %d: %v\n", pgid, err)
		return err
	}
	return nil
}

// getSysProcAttr returns platform-specific SysProcAttr for process creation.
// On Unix, this sets Setpgid to create a new process group.
func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// getProcessGroupID returns the process group ID for a given process.
func getProcessGroupID(pid int) int {
	if pid <= 0 {
		return 0
	}
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		return 0
	}
	return pgid
}

// resourcesFromProcessState extracts resource usage from process state.
func resourcesFromProcessState(ps *os.ProcessState) types.ExecResources {
	if ps == nil {
		return types.ExecResources{}
	}
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return types.ExecResources{}
	}
	return types.ExecResources{
		CPUUserMs:    int64(ru.Utime.Sec)*1000 + int64(ru.Utime.Usec)/1000,
		CPUSystemMs:  int64(ru.Stime.Sec)*1000 + int64(ru.Stime.Usec)/1000,
		MemoryPeakKB: int64(ru.Maxrss),
	}
}
