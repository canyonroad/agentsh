// internal/platform/fuse/mount.go
//go:build cgo

package fuse

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	cgofuse "github.com/winfsp/cgofuse/fuse"
)

// FuseMount represents an active FUSE mount.
type FuseMount struct {
	host      *cgofuse.FileSystemHost
	fuseFS    *fuseFS
	path      string
	source    string
	mountedAt time.Time
	done      chan struct{}
	closed    atomic.Bool
}

// Path returns the mount point path.
func (m *FuseMount) Path() string {
	return m.path
}

// SourcePath returns the underlying real filesystem path.
func (m *FuseMount) SourcePath() string {
	return m.source
}

// Stats returns current mount statistics.
func (m *FuseMount) Stats() platform.FSStats {
	if m.fuseFS == nil {
		return platform.FSStats{}
	}
	return m.fuseFS.stats()
}

// Close unmounts the filesystem.
func (m *FuseMount) Close() error {
	if m.closed.Swap(true) {
		return nil // Already closed
	}

	ok := m.host.Unmount()

	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		if !ok {
			return fmt.Errorf("unmount failed for %s", m.path)
		}
	}

	return nil
}

var _ platform.FSMount = (*FuseMount)(nil)
