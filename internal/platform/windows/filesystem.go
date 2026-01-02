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
	mu     sync.Mutex
	mounts map[string]platform.FSMount
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

var _ platform.FilesystemInterceptor = (*Filesystem)(nil)
