//go:build windows

package wsl2

import (
	"fmt"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
)

// Filesystem implements platform.FilesystemInterceptor for WSL2.
// It delegates to the Linux FUSE3 implementation running inside WSL2.
type Filesystem struct {
	platform       *Platform
	available      bool
	implementation string
	mu             sync.Mutex
	mounts         map[string]*Mount
}

// NewFilesystem creates a new WSL2 filesystem interceptor.
func NewFilesystem(p *Platform) *Filesystem {
	fs := &Filesystem{
		platform: p,
		mounts:   make(map[string]*Mount),
	}
	fs.available = fs.checkAvailable()
	fs.implementation = "fuse3"
	return fs
}

// checkAvailable checks if FUSE is available in WSL2.
func (fs *Filesystem) checkAvailable() bool {
	_, err := fs.platform.RunInWSL("test", "-e", "/dev/fuse")
	return err == nil
}

// Available returns whether filesystem interception is available.
func (fs *Filesystem) Available() bool {
	return fs.available
}

// Recheck re-probes FUSE availability inside WSL2.
func (fs *Filesystem) Recheck() {
	fs.available = fs.checkAvailable()
}

// Implementation returns the filesystem implementation name.
func (fs *Filesystem) Implementation() string {
	return fs.implementation
}

// Mount creates a FUSE mount inside WSL2.
// The Windows path is translated to WSL path before mounting.
// This uses bindfs for a passthrough mount that makes the source directory
// accessible at the mount point inside WSL2.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.available {
		return nil, fmt.Errorf("FUSE not available in WSL2; install fuse3: sudo apt install fuse3")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Translate Windows paths to WSL paths
	wslSource := WindowsToWSLPath(cfg.SourcePath)
	wslMount := WindowsToWSLPath(cfg.MountPoint)

	// Check if already mounted
	if _, exists := fs.mounts[wslMount]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	// Create mount point directory inside WSL2
	_, err := fs.platform.RunInWSL("mkdir", "-p", wslMount)
	if err != nil {
		return nil, fmt.Errorf("failed to create mount point in WSL2: %w", err)
	}

	// Check if bindfs is available, if not try to install it
	_, err = fs.platform.RunInWSL("which", "bindfs")
	if err != nil {
		// Try to install bindfs
		_, installErr := fs.platform.RunInWSL("sudo", "apt-get", "install", "-y", "bindfs")
		if installErr != nil {
			// Try with apt instead
			_, installErr = fs.platform.RunInWSL("sudo", "apt", "install", "-y", "bindfs")
			if installErr != nil {
				return nil, fmt.Errorf("bindfs not available and could not be installed in WSL2; install manually: sudo apt install bindfs")
			}
		}
	}

	// Mount using bindfs (FUSE-based bind mount)
	// bindfs allows mounting a directory to another location with optional permission changes
	_, err = fs.platform.RunInWSL("bindfs", wslSource, wslMount)
	if err != nil {
		return nil, fmt.Errorf("failed to mount bindfs in WSL2: %w", err)
	}

	mount := &Mount{
		filesystem: fs,
		sourcePath: wslSource,
		mountPoint: wslMount,
		winSource:  cfg.SourcePath,
		winMount:   cfg.MountPoint,
		mountedAt:  time.Now(),
	}

	fs.mounts[wslMount] = mount

	return mount, nil
}

// Unmount removes a FUSE mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	m, ok := mount.(*Mount)
	if !ok {
		return fmt.Errorf("invalid mount type: expected *wsl2.Mount")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, m.mountPoint)

	return m.Close()
}

// Mount represents a FUSE mount in WSL2.
type Mount struct {
	filesystem *Filesystem
	sourcePath string    // WSL path
	mountPoint string    // WSL path
	winSource  string    // Original Windows path
	winMount   string    // Original Windows path
	mountedAt  time.Time // When the mount was created
}

// Path returns the mount point path (Windows format).
func (m *Mount) Path() string {
	return m.winMount
}

// SourcePath returns the source path (Windows format).
func (m *Mount) SourcePath() string {
	return m.winSource
}

// WSLPath returns the mount point in WSL format.
func (m *Mount) WSLPath() string {
	return m.mountPoint
}

// WSLSourcePath returns the source path in WSL format.
func (m *Mount) WSLSourcePath() string {
	return m.sourcePath
}

// Stats returns current mount statistics.
func (m *Mount) Stats() platform.FSStats {
	return platform.FSStats{
		MountedAt: m.mountedAt,
	}
}

// Close unmounts the filesystem.
func (m *Mount) Close() error {
	if m.filesystem == nil || m.filesystem.platform == nil {
		return nil
	}

	// Use fusermount to unmount the bindfs mount
	_, err := m.filesystem.platform.RunInWSL("fusermount", "-u", m.mountPoint)
	if err != nil {
		// Try sudo umount as fallback
		_, err = m.filesystem.platform.RunInWSL("sudo", "umount", m.mountPoint)
		if err != nil {
			return fmt.Errorf("failed to unmount %s in WSL2: %w", m.mountPoint, err)
		}
	}

	return nil
}

// Compile-time interface checks
var (
	_ platform.FilesystemInterceptor = (*Filesystem)(nil)
	_ platform.FSMount               = (*Mount)(nil)
)
