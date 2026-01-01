//go:build darwin && cgo

package darwin

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/winfsp/cgofuse/fuse"
)

// cgoEnabled reports whether CGO is available.
const cgoEnabled = true

// Mount creates a FUSE-T mount using cgofuse.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.available {
		return nil, fmt.Errorf("FUSE not available: install FUSE-T with 'brew install fuse-t'")
	}

	// Verify source path exists
	info, err := os.Stat(cfg.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("source path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("source path must be a directory: %s", cfg.SourcePath)
	}

	// Create mount point if needed
	if err := os.MkdirAll(cfg.MountPoint, 0755); err != nil {
		return nil, fmt.Errorf("create mount point: %w", err)
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.mounts[cfg.MountPoint]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	// Create the policy-enforcing filesystem
	fuseFS := newFuseFS(cfg)

	// Create cgofuse host
	host := fuse.NewFileSystemHost(fuseFS)

	// Mount in background goroutine (cgofuse Mount blocks)
	mountErr := make(chan error, 1)
	mountDone := make(chan struct{})

	go func() {
		defer close(mountDone)
		// Mount options for FUSE-T
		opts := []string{
			"-o", "volname=agentsh",
			"-o", "local",
			"-o", "allow_other",
		}
		ok := host.Mount(cfg.MountPoint, opts)
		if !ok {
			mountErr <- fmt.Errorf("cgofuse mount failed at %s", cfg.MountPoint)
		}
	}()

	// Wait for mount to complete or timeout
	select {
	case err := <-mountErr:
		return nil, err
	case <-time.After(5 * time.Second):
		// Check if mount succeeded by testing if path is accessible
		if _, err := os.Stat(cfg.MountPoint); err != nil {
			host.Unmount()
			return nil, fmt.Errorf("mount timeout: %s", cfg.MountPoint)
		}
	}

	mount := &FuseMount{
		host:      host,
		fuseFS:    fuseFS,
		path:      cfg.MountPoint,
		source:    cfg.SourcePath,
		mountedAt: time.Now(),
		done:      mountDone,
	}

	fs.mounts[cfg.MountPoint] = mount
	return mount, nil
}

// FuseMount represents an active FUSE-T mount.
type FuseMount struct {
	host      *fuse.FileSystemHost
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

	// Unmount
	m.host.Unmount()

	// Wait for mount goroutine to finish
	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		// Force unmount timed out, continue anyway
	}

	return nil
}

// fuseFS implements fuse.FileSystemInterface with policy enforcement.
type fuseFS struct {
	fuse.FileSystemBase
	realRoot  string
	cfg       platform.FSConfig
	openFiles sync.Map   // uint64 -> *openFile
	nextFh    uint64     // Atomic counter for file handles

	// Stats
	totalOps      atomic.Int64
	allowedOps    atomic.Int64
	deniedOps     atomic.Int64
	redirectedOps atomic.Int64
	mountedAt     time.Time
}

// openFile tracks an open file handle for Read/Write operations.
type openFile struct {
	realPath string
	virtPath string
	flags    int
	file     *os.File
}

func newFuseFS(cfg platform.FSConfig) *fuseFS {
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

// allocHandle allocates a new file handle ID.
func (f *fuseFS) allocHandle() uint64 {
	return atomic.AddUint64(&f.nextFh, 1)
}

// Compile-time interface check
var _ platform.FSMount = (*FuseMount)(nil)
