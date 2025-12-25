//go:build darwin

package darwin

import (
	"fmt"
	"os"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// Filesystem implements platform.FilesystemInterceptor for macOS using FUSE-T.
type Filesystem struct {
	available      bool
	implementation string
	mu             sync.Mutex
	mounts         map[string]*Mount
}

// NewFilesystem creates a new macOS filesystem interceptor.
func NewFilesystem() *Filesystem {
	fs := &Filesystem{
		mounts: make(map[string]*Mount),
	}
	fs.available = fs.checkAvailable()
	fs.implementation = fs.detectImplementation()
	return fs
}

// checkAvailable checks if FUSE is available on macOS.
func (fs *Filesystem) checkAvailable() bool {
	// Check for FUSE-T
	fuseTpaths := []string{
		"/usr/local/lib/libfuse-t.dylib",
		"/opt/homebrew/lib/libfuse-t.dylib",
		"/Library/Frameworks/FUSE-T.framework",
	}
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check for macFUSE as fallback
	macFUSEpaths := []string{
		"/Library/Filesystems/macfuse.fs",
		"/Library/Frameworks/macFUSE.framework",
	}
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
	fuseTpaths := []string{
		"/usr/local/lib/libfuse-t.dylib",
		"/opt/homebrew/lib/libfuse-t.dylib",
		"/Library/Frameworks/FUSE-T.framework",
	}
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			return "fuse-t"
		}
	}

	// Check for macFUSE
	macFUSEpaths := []string{
		"/Library/Filesystems/macfuse.fs",
		"/Library/Frameworks/macFUSE.framework",
	}
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

// Mount creates a FUSE mount. Currently returns an error as the full
// FUSE implementation requires CGO and FUSE-T libraries.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.available {
		return nil, fmt.Errorf("FUSE not available: install FUSE-T with 'brew install fuse-t'")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.mounts[cfg.MountPoint]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	// TODO: Implement actual FUSE-T mounting using go-fuse or cgofuse
	// This requires CGO and FUSE-T development libraries
	return nil, fmt.Errorf("FUSE-T mounting not yet implemented; FUSE-T detected: %s", fs.implementation)
}

// Unmount removes a FUSE mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	m, ok := mount.(*Mount)
	if !ok {
		return fmt.Errorf("invalid mount type")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, m.mountPoint)
	return m.Close()
}

// Mount represents a FUSE mount on macOS.
type Mount struct {
	sourcePath string
	mountPoint string
}

// Path returns the mount point path.
func (m *Mount) Path() string {
	return m.mountPoint
}

// SourcePath returns the underlying real filesystem path.
func (m *Mount) SourcePath() string {
	return m.sourcePath
}

// Stats returns current mount statistics.
func (m *Mount) Stats() platform.FSStats {
	return platform.FSStats{}
}

// Close unmounts the filesystem.
func (m *Mount) Close() error {
	// TODO: Implement unmount
	return nil
}

// Compile-time interface checks
var (
	_ platform.FilesystemInterceptor = (*Filesystem)(nil)
	_ platform.FSMount               = (*Mount)(nil)
)
