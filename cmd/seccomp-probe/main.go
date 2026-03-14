//go:build linux

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Minimal BPF program: allow all syscalls (RET_ALLOW).
// We only care whether seccomp(SECCOMP_SET_MODE_FILTER) is permitted,
// not whether the filter itself does anything useful.
var bpfProg = []unix.SockFilter{
	{Code: 0x06, K: 0x7fff0000}, // BPF_RET | BPF_K, SECCOMP_RET_ALLOW
}

func main() {
	// Step 1: PR_SET_NO_NEW_PRIVS is required before installing a seccomp filter.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "prctl(PR_SET_NO_NEW_PRIVS): %v\n", err)
		os.Exit(1)
	}

	// Step 2: Install a trivial BPF filter via seccomp(SECCOMP_SET_MODE_FILTER).
	prog := unix.SockFprog{
		Len:    uint16(len(bpfProg)),
		Filter: &bpfProg[0],
	}
	_, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		2, // SECCOMP_SET_MODE_FILTER
		0, // flags
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "seccomp(SECCOMP_SET_MODE_FILTER): %v (errno %d)\n", errno, errno)
		os.Exit(1)
	}

	fmt.Println("seccomp_filter: available")
}
