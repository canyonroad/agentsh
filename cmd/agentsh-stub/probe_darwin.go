//go:build darwin

package main

// probeSocket on macOS always returns false.
// The well-known fd mechanism is only used on Linux where seccomp redirect
// injects the socket at fd 100.
func probeSocket(fd int) bool {
	return false
}
