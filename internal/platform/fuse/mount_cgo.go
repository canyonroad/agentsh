// internal/platform/fuse/mount_cgo.go
//go:build cgo && !nofuse

package fuse

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	cgofuse "github.com/winfsp/cgofuse/fuse"
)

const cgoEnabled = true

func Available() bool {
	return checkAvailable()
}

func Implementation() string {
	return detectImplementation()
}

// Mount creates a FUSE mount using cgofuse.
func Mount(cfg Config) (platform.FSMount, error) {
	if !Available() {
		return nil, fmt.Errorf("FUSE not available: %s", InstallInstructions())
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
	if err := os.MkdirAll(cfg.MountPoint, 0o755); err != nil {
		return nil, fmt.Errorf("create mount point: %w", err)
	}
	// Explicitly chmod the per-session directory and mount point to 0755
	// regardless of the process umask, so unprivileged clients (e.g. agentsh
	// exec running as the agent user) can traverse these root-created paths.
	_ = os.Chmod(filepath.Dir(cfg.MountPoint), 0o755)
	_ = os.Chmod(cfg.MountPoint, 0o755)

	// Create the policy-enforcing filesystem
	fuseFS := newFuseFS(cfg)

	// Create cgofuse host
	host := cgofuse.NewFileSystemHost(fuseFS)

	// Mount in background goroutine (cgofuse Mount blocks)
	mountErr := make(chan error, 1)
	mountDone := make(chan struct{})

	go func() {
		defer close(mountDone)
		opts := mountOptions(cfg)
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
		if _, err := os.Stat(cfg.MountPoint); err != nil {
			host.Unmount()
			return nil, fmt.Errorf("mount timeout: %s", cfg.MountPoint)
		}
	}

	return &FuseMount{
		host:      host,
		fuseFS:    fuseFS,
		path:      cfg.MountPoint,
		source:    cfg.SourcePath,
		mountedAt: time.Now(),
		done:      mountDone,
	}, nil
}

// mountOptions returns platform-specific mount options.
func mountOptions(cfg Config) []string {
	volname := cfg.VolumeName
	if volname == "" {
		volname = "agentsh"
	}

	switch runtime.GOOS {
	case "darwin":
		opts := []string{
			"-o", "volname=" + volname,
			"-o", "local",
		}
		if cfg.Debug {
			opts = append(opts, "-d")
		}
		return opts
	case "windows":
		opts := []string{
			"--VolumePrefix=" + volname,
		}
		if cfg.Debug {
			opts = append(opts, "-d")
		}
		return opts
	default:
		// On Linux, allow_other lets unprivileged users (the agent user running
		// agentsh exec) access a FUSE mount created by root. Without it, only
		// the mounting process can traverse the mount point.
		return []string{"-o", "allow_other"}
	}
}
