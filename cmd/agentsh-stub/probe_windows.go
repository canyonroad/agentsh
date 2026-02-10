//go:build windows

package main

// probeSocket on Windows always returns false.
// The well-known fd mechanism is only used on Linux where seccomp redirect
// injects the socket at fd 100. Windows uses named pipes instead.
func probeSocket(fd int) bool {
	return false
}
