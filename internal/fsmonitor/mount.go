package fsmonitor

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type Mount struct {
	MountPoint string
	Server     *fuse.Server
}

type Options struct {
	EntryTimeout time.Duration
	AttrTimeout  time.Duration
}

func MountWorkspace(backingDir string, mountPoint string, hooks *Hooks) (*Mount, error) {
	if backingDir == "" {
		return nil, fmt.Errorf("backingDir is empty")
	}
	if mountPoint == "" {
		return nil, fmt.Errorf("mountPoint is empty")
	}
	if err := os.MkdirAll(filepath.Dir(mountPoint), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir mount parent: %w", err)
	}
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir mount: %w", err)
	}

	root, err := NewMonitoredLoopbackRoot(backingDir, hooks)
	if err != nil {
		return nil, err
	}

	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			FsName:      "agentsh-workspace",
			Name:        "agentsh",
			DisableXAttrs: false,
		},
	}

	server, err := fs.Mount(mountPoint, root, opts)
	if err != nil {
		return nil, err
	}
	if err := server.WaitMount(); err != nil {
		return nil, err
	}

	return &Mount{MountPoint: mountPoint, Server: server}, nil
}

func (m *Mount) Unmount() error {
	if m == nil || m.Server == nil {
		return nil
	}
	return m.Server.Unmount()
}

