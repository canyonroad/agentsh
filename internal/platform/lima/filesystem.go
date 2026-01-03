//go:build darwin

package lima

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// Filesystem implements platform.FilesystemInterceptor for Lima.
// It delegates to the Linux FUSE3 implementation running inside the Lima VM.
type Filesystem struct {
	platform       *Platform
	available      bool
	implementation string
}

// NewFilesystem creates a new Lima filesystem interceptor.
func NewFilesystem(p *Platform) *Filesystem {
	fs := &Filesystem{
		platform: p,
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

// Implementation returns the filesystem implementation name.
func (fs *Filesystem) Implementation() string {
	return fs.implementation
}

// Mount creates a FUSE mount inside the Lima VM.
// The macOS path is translated to Lima VM path before mounting.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.available {
		return nil, fmt.Errorf("FUSE not available in Lima VM; install fuse3: sudo apt install fuse3")
	}

	// Lima mounts /Users by default, so paths should work directly
	limaSource := MacOSToLimaPath(cfg.SourcePath)
	limaMount := MacOSToLimaPath(cfg.MountPoint)

	// TODO: Execute agentsh mount command inside Lima VM
	// This would coordinate with the Linux FUSE implementation
	return nil, fmt.Errorf("Lima FUSE mounting not yet implemented; source=%s mount=%s", limaSource, limaMount)
}

// Unmount removes a FUSE mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	m, ok := mount.(*Mount)
	if !ok {
		return fmt.Errorf("invalid mount type")
	}
	return m.Close()
}

// Mount represents a FUSE mount in the Lima VM.
type Mount struct {
	sourcePath string // Lima VM path
	mountPoint string // Lima VM path
	macSource  string // Original macOS path
	macMount   string // Original macOS path
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
	return platform.FSStats{}
}

// Close unmounts the filesystem.
func (m *Mount) Close() error {
	// TODO: Execute unmount inside Lima VM
	return nil
}

// Compile-time interface checks
var (
	_ platform.FilesystemInterceptor = (*Filesystem)(nil)
	_ platform.FSMount               = (*Mount)(nil)
)
