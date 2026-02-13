// internal/platform/fuse/fs.go
//go:build cgo

package fuse

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/winfsp/cgofuse/fuse"
)

// fuseFS implements fuse.FileSystemInterface with policy enforcement.
type fuseFS struct {
	fuse.FileSystemBase
	realRoot  string
	cfg       Config
	openFiles sync.Map   // uint64 -> *openFile
	nextFh    atomic.Uint64
	mountedAt time.Time

	// Stats
	totalOps      atomic.Int64
	allowedOps    atomic.Int64
	deniedOps     atomic.Int64
	redirectedOps atomic.Int64
}

// openFile tracks an open file handle.
type openFile struct {
	realPath string
	virtPath string
	fusePath string // raw FUSE path (for policy evaluation via source path)
	flags    int
	file     *os.File
}

func newFuseFS(cfg Config) *fuseFS {
	return &fuseFS{
		realRoot:  cfg.SourcePath,
		cfg:       cfg,
		mountedAt: time.Now(),
	}
}

func (f *fuseFS) stats() platform.FSStats {
	return platform.FSStats{
		MountedAt:     f.mountedAt,
		TotalOps:      f.totalOps.Load(),
		AllowedOps:    f.allowedOps.Load(),
		DeniedOps:     f.deniedOps.Load(),
		RedirectedOps: f.redirectedOps.Load(),
	}
}

func (f *fuseFS) allocHandle() uint64 {
	return f.nextFh.Add(1)
}
