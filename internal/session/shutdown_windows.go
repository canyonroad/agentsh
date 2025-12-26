//go:build windows

package session

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// signalProcess sends a signal to a process.
// On Windows, only SIGKILL/SIGTERM are supported via TerminateProcess.
func signalProcess(pid int, sig syscall.Signal) error {
	// On Windows, we can only terminate processes, not send signals
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	// Use exit code based on signal
	exitCode := uint32(1)
	if sig == syscall.SIGKILL {
		exitCode = 137 // 128 + 9
	} else if sig == syscall.SIGTERM {
		exitCode = 143 // 128 + 15
	}

	return windows.TerminateProcess(handle, exitCode)
}

// processExists checks if a process is still running.
func processExists(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	var exitCode uint32
	err = windows.GetExitCodeProcess(handle, &exitCode)
	if err != nil {
		return false
	}

	// STILL_ACTIVE means the process is still running
	return exitCode == 259 // STILL_ACTIVE
}
