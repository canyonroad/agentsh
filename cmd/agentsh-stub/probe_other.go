//go:build linux

package main

import "syscall"

// probeSocket checks if the given fd is open by calling Fstat on it.
// It does NOT close the fd — the caller will use it later.
func probeSocket(fd int) bool {
	var stat syscall.Stat_t
	return syscall.Fstat(fd, &stat) == nil
}
