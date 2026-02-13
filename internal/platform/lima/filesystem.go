//go:build darwin

package lima

import (
	"fmt"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
)

// Filesystem implements platform.FilesystemInterceptor for Lima.
// It delegates to the Linux FUSE3 implementation running inside the Lima VM.
type Filesystem struct {
	platform       *Platform
	available      bool
	implementation string
	mu             sync.Mutex
	mounts         map[string]*Mount
}

// NewFilesystem creates a new Lima filesystem interceptor.
func NewFilesystem(p *Platform) *Filesystem {
	fs := &Filesystem{
		platform: p,
		mounts:   make(map[string]*Mount),
	}
	fs.available = fs.checkAvailable()
	fs.implementation = "fuse3"
	return fs
}

// checkAvailable checks if FUSE is available in the Lima VM.
func (fs *Filesystem) checkAvailable() bool {
	_, err := fs.platform.RunInLima("test", "-e", "/dev/fuse")
	return err == nil
}

// Available returns whether filesystem interception is available.
func (fs *Filesystem) Available() bool {
	return fs.available
}

// Recheck re-probes FUSE availability inside the Lima VM.
func (fs *Filesystem) Recheck() {
	fs.available = fs.checkAvailable()
}

// Implementation returns the filesystem implementation name.
func (fs *Filesystem) Implementation() string {
	return fs.implementation
}

// Mount creates a FUSE mount inside the Lima VM.
// The macOS path is translated to Lima VM path before mounting.
// This uses bindfs for a passthrough mount that makes the source directory
// accessible at the mount point inside the VM.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.available {
		return nil, fmt.Errorf("FUSE not available in Lima VM; install fuse3: sudo apt install fuse3")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Lima mounts /Users by default via virtiofs, so paths should work directly
	limaSource := MacOSToLimaPath(cfg.SourcePath)
	limaMount := MacOSToLimaPath(cfg.MountPoint)

	// Check if already mounted
	if _, exists := fs.mounts[limaMount]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	// Create mount point directory inside Lima VM
	_, err := fs.platform.RunInLima("mkdir", "-p", limaMount)
	if err != nil {
		return nil, fmt.Errorf("failed to create mount point in Lima VM: %w", err)
	}

	// Check if bindfs is available, if not try to install it
	_, err = fs.platform.RunInLima("which", "bindfs")
	if err != nil {
		// Try to install bindfs
		_, installErr := fs.platform.RunInLima("sudo", "apt-get", "install", "-y", "bindfs")
		if installErr != nil {
			// Try with apt instead
			_, installErr = fs.platform.RunInLima("sudo", "apt", "install", "-y", "bindfs")
			if installErr != nil {
				return nil, fmt.Errorf("bindfs not available and could not be installed in Lima VM; install manually: sudo apt install bindfs")
			}
		}
	}

	// Mount using bindfs (FUSE-based bind mount)
	// bindfs allows mounting a directory to another location with optional permission changes
	_, err = fs.platform.RunInLima("bindfs", limaSource, limaMount)
	if err != nil {
		return nil, fmt.Errorf("failed to mount bindfs in Lima VM: %w", err)
	}

	mount := &Mount{
		filesystem: fs,
		sourcePath: limaSource,
		mountPoint: limaMount,
		macSource:  cfg.SourcePath,
		macMount:   cfg.MountPoint,
		mountedAt:  time.Now(),
	}

	fs.mounts[limaMount] = mount

	return mount, nil
}

// Unmount removes a FUSE mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	m, ok := mount.(*Mount)
	if !ok {
		return fmt.Errorf("invalid mount type: expected *lima.Mount")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, m.mountPoint)

	return m.Close()
}

// Mount represents a FUSE mount in the Lima VM.
type Mount struct {
	filesystem *Filesystem
	sourcePath string    // Lima VM path
	mountPoint string    // Lima VM path
	macSource  string    // Original macOS path
	macMount   string    // Original macOS path
	mountedAt  time.Time // When the mount was created
}

// Path returns the mount point path (macOS format).
func (m *Mount) Path() string {
	return m.macMount
}

// SourcePath returns the source path (macOS format).
func (m *Mount) SourcePath() string {
	return m.macSource
}

// LimaPath returns the mount point in Lima VM format.
func (m *Mount) LimaPath() string {
	return m.mountPoint
}

// LimaSourcePath returns the source path in Lima VM format.
func (m *Mount) LimaSourcePath() string {
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
	_, err := m.filesystem.platform.RunInLima("fusermount", "-u", m.mountPoint)
	if err != nil {
		// Try sudo umount as fallback
		_, err = m.filesystem.platform.RunInLima("sudo", "umount", m.mountPoint)
		if err != nil {
			return fmt.Errorf("failed to unmount %s in Lima VM: %w", m.mountPoint, err)
		}
	}

	return nil
}

// Compile-time interface checks
var (
	_ platform.FilesystemInterceptor = (*Filesystem)(nil)
	_ platform.FSMount               = (*Mount)(nil)
)
