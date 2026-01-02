//go:build darwin

package darwin

import (
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/platform/fuse"
)

// Filesystem implements platform.FilesystemInterceptor for macOS.
type Filesystem struct {
	mu     sync.Mutex
	mounts map[string]platform.FSMount
}

// NewFilesystem creates a new macOS filesystem interceptor.
func NewFilesystem() *Filesystem {
	return &Filesystem{
		mounts: make(map[string]platform.FSMount),
	}
}

// Available returns whether FUSE is available.
func (fs *Filesystem) Available() bool {
	return fuse.Available()
}

// Implementation returns the FUSE implementation name.
func (fs *Filesystem) Implementation() string {
	return fuse.Implementation()
}

// Unmount removes a FUSE mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, mount.Path())
	return mount.Close()
}

var _ platform.FilesystemInterceptor = (*Filesystem)(nil)
