//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "seccomp-probe: only supported on Linux")
	os.Exit(1)
}
