//go:build windows

package wsl2

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// Filesystem implements platform.FilesystemInterceptor for WSL2.
// It delegates to the Linux FUSE3 implementation running inside WSL2.
type Filesystem struct {
	platform       *Platform
	available      bool
	implementation string
}

// NewFilesystem creates a new WSL2 filesystem interceptor.
func NewFilesystem(p *Platform) *Filesystem {
	fs := &Filesystem{
		platform: p,
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

// Implementation returns the filesystem implementation name.
func (fs *Filesystem) Implementation() string {
	return fs.implementation
}

// Mount creates a FUSE mount inside WSL2.
// The Windows path is translated to WSL path before mounting.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.available {
		return nil, fmt.Errorf("FUSE not available in WSL2; install fuse3: sudo apt install fuse3")
	}

	// Translate Windows paths to WSL paths
	wslSource := WindowsToWSLPath(cfg.SourcePath)
	wslMount := WindowsToWSLPath(cfg.MountPoint)

	// TODO: Execute agentsh mount command inside WSL2
	// This would coordinate with the Linux FUSE implementation
	return nil, fmt.Errorf("WSL2 FUSE mounting not yet implemented; source=%s mount=%s", wslSource, wslMount)
}

// Unmount removes a FUSE mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	m, ok := mount.(*Mount)
	if !ok {
		return fmt.Errorf("invalid mount type")
	}
	return m.Close()
}

// Mount represents a FUSE mount in WSL2.
type Mount struct {
	sourcePath string // WSL path
	mountPoint string // WSL path
	winSource  string // Original Windows path
	winMount   string // Original Windows path
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
	return platform.FSStats{}
}

// Close unmounts the filesystem.
func (m *Mount) Close() error {
	// TODO: Execute unmount inside WSL2
	return nil
}

// Compile-time interface checks
var (
	_ platform.FilesystemInterceptor = (*Filesystem)(nil)
	_ platform.FSMount               = (*Mount)(nil)
)
