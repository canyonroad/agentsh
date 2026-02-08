//go:build !windows

package fsmonitor

import (
	"context"
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

func MountWorkspace(ctx context.Context, backingDir string, mountPoint string, hooks *Hooks) (*Mount, error) {
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
			FsName:        "agentsh-workspace",
			Name:          "agentsh",
			DisableXAttrs: false,
			AllowOther:    true,
		},
	}

	type mountResult struct {
		server *fuse.Server
		err    error
	}
	ch := make(chan mountResult, 1)
	go func() {
		server, err := fs.Mount(mountPoint, root, opts)
		if err != nil {
			ch <- mountResult{nil, err}
			return
		}
		if err := server.WaitMount(); err != nil {
			ch <- mountResult{nil, err}
			return
		}
		ch <- mountResult{server, nil}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		return &Mount{MountPoint: mountPoint, Server: res.server}, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("FUSE mount timed out at %s (likely blocked by container runtime)", mountPoint)
	}
}

func (m *Mount) Unmount() error {
	if m == nil || m.Server == nil {
		return nil
	}
	return m.Server.Unmount()
}
