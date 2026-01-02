//go:build darwin && !cgo

package darwin

import (
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/platform/fuse"
)

// Mount delegates to the shared fuse package, which returns an error when CGO is disabled.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	return fuse.Mount(fuse.Config{FSConfig: cfg})
}

const cgoEnabled = false
