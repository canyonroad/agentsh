//go:build windows

package windows

import (
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/platform/fuse"
)

// Filesystem implements platform.FilesystemInterceptor for Windows using WinFsp.
type Filesystem struct {
	mu           sync.Mutex
	mounts       map[string]platform.FSMount
	driverClient *DriverClient
}

// NewFilesystem creates a new Windows filesystem interceptor.
func NewFilesystem() *Filesystem {
	return &Filesystem{
		mounts: make(map[string]platform.FSMount),
	}
}

// Available returns whether WinFsp is available.
func (fs *Filesystem) Available() bool {
	return fuse.Available()
}

// Implementation returns the WinFsp implementation name.
func (fs *Filesystem) Implementation() string {
	return fuse.Implementation()
}

// Mount creates a WinFsp mount.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.Available() {
		return nil, fmt.Errorf("WinFsp not available: %s", fuse.InstallInstructions())
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.mounts[cfg.MountPoint]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	// Tell minifilter to exclude our process to avoid double-interception
	if fs.driverClient != nil && fs.driverClient.Connected() {
		if err := fs.driverClient.ExcludeSelf(); err != nil {
			// Log warning but continue - WinFsp will still work
			// just might have duplicate events
			_ = err
		}
	}

	mount, err := fuse.Mount(fuse.Config{
		FSConfig:   cfg,
		VolumeName: "agentsh",
	})
	if err != nil {
		return nil, err
	}

	fs.mounts[cfg.MountPoint] = mount
	return mount, nil
}

// Unmount removes a WinFsp mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, mount.Path())
	return mount.Close()
}

// SetDriverClient sets the driver client for process exclusion.
// Call this before Mount() to enable automatic process exclusion
// which prevents double-interception of file operations.
func (fs *Filesystem) SetDriverClient(client *DriverClient) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.driverClient = client
}

var _ platform.FilesystemInterceptor = (*Filesystem)(nil)
