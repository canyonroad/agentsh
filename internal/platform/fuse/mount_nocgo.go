// internal/platform/fuse/mount_nocgo.go
//go:build !cgo

package fuse

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// Mount returns an error when CGO is disabled.
func Mount(cfg Config) (platform.FSMount, error) {
	return nil, fmt.Errorf("FUSE mounting requires CGO; build with CGO_ENABLED=1. %s", InstallInstructions())
}

// Available returns false when CGO is disabled.
func Available() bool {
	return false
}

// Implementation returns "none" when CGO is disabled.
func Implementation() string {
	return "none"
}

// cgoEnabled reports whether CGO is available.
const cgoEnabled = false
