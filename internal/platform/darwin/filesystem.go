//go:build darwin

package darwin

import (
	"os"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// FUSE-T detection paths
var fuseTpaths = []string{
	"/usr/local/lib/libfuse-t.dylib",
	"/opt/homebrew/lib/libfuse-t.dylib",
	"/Library/Frameworks/FUSE-T.framework",
}

// macFUSE detection paths (fallback)
var macFUSEpaths = []string{
	"/Library/Filesystems/macfuse.fs",
	"/Library/Frameworks/macFUSE.framework",
}

// Filesystem implements platform.FilesystemInterceptor for macOS.
// The actual mount implementation is in filesystem_cgo.go (with CGO)
// or filesystem_nocgo.go (without CGO).
type Filesystem struct {
	available      bool
	implementation string
	mu             sync.Mutex
	mounts         map[string]platform.FSMount
}

// NewFilesystem creates a new macOS filesystem interceptor.
func NewFilesystem() *Filesystem {
	fs := &Filesystem{
		mounts: make(map[string]platform.FSMount),
	}
	fs.available = fs.checkAvailable()
	fs.implementation = fs.detectImplementation()
	return fs
}

// checkAvailable checks if FUSE is available on macOS.
func (fs *Filesystem) checkAvailable() bool {
	// Check for FUSE-T
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check for macFUSE as fallback
	for _, path := range macFUSEpaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

// detectImplementation returns the FUSE implementation name.
func (fs *Filesystem) detectImplementation() string {
	// Check for FUSE-T first (preferred)
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			return "fuse-t"
		}
	}

	// Check for macFUSE
	for _, path := range macFUSEpaths {
		if _, err := os.Stat(path); err == nil {
			return "macfuse"
		}
	}

	return "none"
}

// Available returns whether FUSE is available.
func (fs *Filesystem) Available() bool {
	return fs.available
}

// Implementation returns the FUSE implementation name.
func (fs *Filesystem) Implementation() string {
	return fs.implementation
}

// Unmount removes a FUSE mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, mount.Path())
	return mount.Close()
}

// Compile-time interface check
var _ platform.FilesystemInterceptor = (*Filesystem)(nil)
