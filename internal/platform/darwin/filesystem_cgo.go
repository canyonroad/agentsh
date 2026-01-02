//go:build darwin && cgo

package darwin

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/platform/fuse"
)

// Mount creates a FUSE mount.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
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

const cgoEnabled = true
