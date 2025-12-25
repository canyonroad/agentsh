//go:build windows

package windows

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// Filesystem implements platform.FilesystemInterceptor for Windows using WinFsp.
type Filesystem struct {
	available      bool
	implementation string
	mu             sync.Mutex
	mounts         map[string]*Mount
}

// NewFilesystem creates a new Windows filesystem interceptor.
func NewFilesystem() *Filesystem {
	fs := &Filesystem{
		mounts: make(map[string]*Mount),
	}
	fs.available = fs.checkAvailable()
	fs.implementation = fs.detectImplementation()
	return fs
}

// checkAvailable checks if WinFsp is available on Windows.
func (fs *Filesystem) checkAvailable() bool {
	// Check for WinFsp DLL in common locations
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "WinFsp", "bin", "winfsp-x64.dll"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "WinFsp", "bin", "winfsp-x86.dll"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "winfsp-x64.dll"),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check registry for WinFsp installation
	cmd := exec.Command("reg", "query", `HKLM\SOFTWARE\WinFsp`, "/ve")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

// detectImplementation returns the filesystem implementation name.
func (fs *Filesystem) detectImplementation() string {
	if fs.available {
		return "winfsp"
	}
	return "none"
}

// Available returns whether WinFsp is available.
func (fs *Filesystem) Available() bool {
	return fs.available
}

// Implementation returns the WinFsp implementation name.
func (fs *Filesystem) Implementation() string {
	return fs.implementation
}

// Mount creates a WinFsp mount. Currently returns an error as the full
// WinFsp implementation requires CGO and WinFsp libraries.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.available {
		return nil, fmt.Errorf("WinFsp not available: install WinFsp from https://winfsp.dev/")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.mounts[cfg.MountPoint]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	// TODO: Implement actual WinFsp mounting using cgofuse or winfsp-go
	// This requires CGO and WinFsp development libraries
	return nil, fmt.Errorf("WinFsp mounting not yet implemented; WinFsp detected: %s", fs.implementation)
}

// Unmount removes a WinFsp mount.
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

// Mount represents a WinFsp mount on Windows.
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
