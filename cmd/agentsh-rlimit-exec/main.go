//go:build darwin || linux

// agentsh-rlimit-exec is a wrapper that applies resource limits before exec'ing a command.
//
// Usage:
//
//	AGENTSH_RLIMIT_AS=<bytes> agentsh-rlimit-exec <command> [args...]
//
// This wrapper is needed on macOS because:
// - Go's exec.Cmd doesn't support setting rlimits via SysProcAttr on darwin
// - macOS lacks prlimit() which would allow setting limits from the parent
// - setrlimit() only affects the calling process
//
// The wrapper sets rlimit on itself, then exec's the target command.
// The target inherits the rlimit.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentsh-rlimit-exec <command> [args...]")
		os.Exit(1)
	}

	// Apply RLIMIT_AS if set
	if limitStr := os.Getenv("AGENTSH_RLIMIT_AS"); limitStr != "" {
		limit, err := strconv.ParseUint(limitStr, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentsh-rlimit-exec: invalid AGENTSH_RLIMIT_AS: %v\n", err)
			os.Exit(1)
		}
		rlimit := unix.Rlimit{Cur: limit, Max: limit}
		if err := unix.Setrlimit(unix.RLIMIT_AS, &rlimit); err != nil {
			fmt.Fprintf(os.Stderr, "agentsh-rlimit-exec: setrlimit failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Look up command path
	cmd := os.Args[1]
	path, err := exec.LookPath(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-rlimit-exec: command not found: %s\n", cmd)
		os.Exit(127)
	}

	// Exec replaces this process with the target command
	args := os.Args[1:] // includes cmd as args[0]
	if err := unix.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-rlimit-exec: exec failed: %v\n", err)
		os.Exit(126)
	}
}
