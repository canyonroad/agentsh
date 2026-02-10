//go:build linux && cgo

package unix

import (
	"fmt"
	"os"
)

// CreateStubSymlink creates a short-path symlink pointing to the agentsh-stub binary.
// The symlink is placed in a private temp directory with 0700 permissions.
// Returns (symlink path, cleanup function, error).
// The symlink path is kept short to fit within most execve filename buffers.
func CreateStubSymlink(stubBinaryPath string) (string, func(), error) {
	// Create a private temp directory with a short prefix.
	// MkdirTemp with "as-" prefix gives us /tmp/as-XXXXXXXXXX (~18 chars).
	dir, err := os.MkdirTemp("", "as-")
	if err != nil {
		return "", nil, fmt.Errorf("create stub symlink dir: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("chmod stub symlink dir: %w", err)
	}

	// Use single-char name "s" to keep the total path short.
	symlinkPath := dir + "/s"
	if err := os.Symlink(stubBinaryPath, symlinkPath); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("create stub symlink: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(dir)
	}

	return symlinkPath, cleanup, nil
}
