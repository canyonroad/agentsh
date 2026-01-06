//go:build darwin && !cgo

// Stub for cross-compilation without cgo.
// The real implementation requires cgo for sandbox_init_with_parameters.

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "agentsh-macwrap: this binary was built without cgo support")
	fmt.Fprintln(os.Stderr, "rebuild with CGO_ENABLED=1 on macOS to enable sandbox functionality")
	os.Exit(1)
}
