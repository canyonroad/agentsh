//go:build !windows

package main

import (
	"fmt"
	"os"
)

func runWithPipe(pipeName string) int {
	fmt.Fprintf(os.Stderr, "agentsh-stub: named pipe transport not available on this platform\n")
	return 126
}
