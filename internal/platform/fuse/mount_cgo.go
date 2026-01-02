// internal/platform/fuse/mount_cgo.go
//go:build cgo

package fuse

import (
	"fmt"
	"runtime"

	"github.com/agentsh/agentsh/internal/platform"
)

// cgoEnabled reports whether CGO is available.
const cgoEnabled = true

// Available checks if FUSE is available on this platform.
func Available() bool {
	return checkAvailable()
}

// Implementation returns the FUSE implementation name.
func Implementation() string {
	return detectImplementation()
}

// Mount creates a FUSE mount using cgofuse.
func Mount(cfg Config) (platform.FSMount, error) {
	if !Available() {
		return nil, fmt.Errorf("FUSE not available: %s", InstallInstructions())
	}
	// TODO: Implement actual mounting
	return nil, fmt.Errorf("FUSE mounting not yet implemented on %s", runtime.GOOS)
}
