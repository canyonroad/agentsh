//go:build !windows

package fsmonitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type Mount struct {
	MountPoint string
	Server     *fuse.Server
}

func MountWorkspace(ctx context.Context, backingDir string, mountPoint string, hooks *Hooks) (*Mount, error) {
	if backingDir == "" {
		return nil, fmt.Errorf("backingDir is empty")
	}
	if mountPoint == "" {
		return nil, fmt.Errorf("mountPoint is empty")
	}
	// Skip MkdirAll for /dev/fd/N magic mountpoints (pre-mounted FUSE fd)
	if !strings.HasPrefix(mountPoint, "/dev/fd/") {
		if err := os.MkdirAll(filepath.Dir(mountPoint), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir mount parent: %w", err)
		}
		if err := os.MkdirAll(mountPoint, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir mount: %w", err)
		}
	}

	root, err := NewMonitoredLoopbackRoot(backingDir, hooks)
	if err != nil {
		return nil, err
	}

	opts := buildMountOptions(hooks)

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

// buildMountOptions assembles the go-fuse mount options for the workspace.
//
// #369 #2 -- default_permissions + attribute/entry caching are a matched pair
// that together close a FUSE<->clone deadlock on kernel 6.12.x under sustained
// FUSE-on load:
//
//   - An exec child chdir()s into this workspace mount during Go's forkExec
//     (between clone and execve). The kernel's path-walk permission check on
//     the workspace directory issues a FUSE request that blocks in
//     request_wait_answer waiting on a go-fuse reader goroutine. The Go runtime
//     cannot schedule that reader while a sibling thread is stuck D-state in
//     kernel_clone (spawning a new M also needs clone), so the request is never
//     answered and the exec wedges until the client-side timeout.
//
//   - default_permissions makes the kernel perform the standard unix-mode
//     permission check LOCALLY rather than round-tripping FUSE_ACCESS to this
//     in-process daemon. That is exactly what go-fuse's default Access op did
//     (Getattr + HasAccess, a pure unix-mode test); agentsh enforces policy on
//     open/read/write/create/delete/rename/etc. in the node ops, never on
//     access(), so policy enforcement is unchanged.
//
//   - The local check still needs the directory's cached attributes and
//     dentries. agentsh otherwise runs with attr/entry timeout 0 (go-fuse only
//     defaults these to 1s when opts==nil, and we pass non-nil opts), so the
//     kernel would treat them as always-stale and re-issue GETATTR/LOOKUP in
//     the same forkExec window -- the same deadlock, differently named. A 1s
//     EntryTimeout/AttrTimeout lets the kernel serve the chdir permission check
//     from cache with no FUSE round-trip. Entry/lookup caching has no audit or
//     policy cost (there is no Lookup node op); attr caching only coalesces
//     repeat stat()s of the same file within 1s -- distinct-file stats, and all
//     content operations, are still forwarded and audited.
func buildMountOptions(hooks *Hooks) *fs.Options {
	attrTimeout := time.Second
	entryTimeout := time.Second
	opts := &fs.Options{
		EntryTimeout: &entryTimeout,
		AttrTimeout:  &attrTimeout,
		MountOptions: fuse.MountOptions{
			FsName:        "agentsh-workspace",
			Name:          "agentsh",
			DisableXAttrs: false,
			AllowOther:    true,
			Options:       []string{"default_permissions"},
		},
	}

	// Optional kernel-side async request queue tuning
	// (sandbox.fuse.max_background). When 0, leave go-fuse's default in
	// place -- go-fuse uses 12, matching the kernel default.
	// Running one daemon with many mounts under heavy ptrace+seccomp
	// syscall traffic can raise this knob to give the kernel more headroom.
	if hooks != nil && hooks.MaxBackground > 0 {
		opts.MountOptions.MaxBackground = hooks.MaxBackground
	}

	return opts
}

func (m *Mount) Unmount() error {
	if m == nil || m.Server == nil {
		return nil
	}
	return m.Server.Unmount()
}
