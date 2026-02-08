// internal/platform/windows/ntdll_stub.go
//go:build !windows

package windows

import "fmt"

// ResumeProcessByPID is only available on Windows.
func ResumeProcessByPID(pid uint32) error {
	return fmt.Errorf("ResumeProcessByPID: not available on this platform")
}

// SuspendProcessByPID is only available on Windows.
func SuspendProcessByPID(pid uint32) error {
	return fmt.Errorf("SuspendProcessByPID: not available on this platform")
}

// TerminateProcessByPID is only available on Windows.
func TerminateProcessByPID(pid uint32, exitCode uint32) error {
	return fmt.Errorf("TerminateProcessByPID: not available on this platform")
}

// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is the attribute key for specifying
// a parent process when creating a new process.
const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000

// CreateProcessAsChild is only available on Windows.
func CreateProcessAsChild(parentPID uint32, appName, cmdLine string, env []string, workDir string, inheritHandles bool, extraHandles []uintptr) (uint32, error) {
	return 0, fmt.Errorf("CreateProcessAsChild: not available on this platform")
}
