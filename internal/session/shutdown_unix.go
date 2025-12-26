//go:build !windows

package session

import "syscall"

// signalProcess sends a signal to a process.
func signalProcess(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

// processExists checks if a process is still running.
func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}
