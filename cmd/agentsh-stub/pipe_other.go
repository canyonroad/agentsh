//go:build !windows

package main

// runWithPipe returns -1 on non-Windows to signal the caller to fall back to fd.
func runWithPipe(pipeName string) int {
	return -1
}
