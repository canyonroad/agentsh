//go:build linux

package fsmonitor

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

type typeCaptureEmitter struct {
	mu    sync.Mutex
	types []string
}

func (c *typeCaptureEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	c.mu.Lock()
	c.types = append(c.types, ev.Type)
	c.mu.Unlock()
	return nil
}

func (c *typeCaptureEmitter) Publish(ev types.Event) {}

func (c *typeCaptureEmitter) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.types...)
}

func fuseBackingAllowPolicy(backing string) *policy.Policy {
	return &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{
				Name:       "allow-backing-workspace",
				Paths:      []string{backing, filepath.Join(backing, "**")},
				Operations: []string{"*"},
				Decision:   "allow",
			},
		},
	}
}

func TestFUSEBackingAllowPolicyAllowsResolvedPath(t *testing.T) {
	backing := t.TempDir()
	engine, err := policy.NewEngine(fuseBackingAllowPolicy(backing), false, true)
	if err != nil {
		t.Fatal(err)
	}

	resolvedPath := filepath.Join(backing, "a.txt")
	dec := engine.CheckFile(resolvedPath, "write")
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("FUSE test policy denied resolved backing path %q: decision=%s rule=%s",
			resolvedPath, dec.EffectiveDecision, dec.Rule)
	}
}

// NOTE: this test mounts a real FUSE filesystem; it will skip if /dev/fuse is unavailable.
func TestFUSE_InterceptsExtraOps(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("fuse not available: %v", err)
	}

	backing := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	engine, err := policy.NewEngine(fuseBackingAllowPolicy(backing), false, true)
	if err != nil {
		t.Fatal(err)
	}

	em := &typeCaptureEmitter{}
	hooks := &Hooks{
		SessionID: "session-test",
		Policy:    engine,
		Emit:      em,
	}

	m, err := MountWorkspace(context.Background(), backing, mountPoint, hooks)
	if err != nil {
		t.Skipf("mount failed (skipping): %v", err)
	}
	defer func() { _ = m.Unmount() }()

	// file_stat
	if err := os.WriteFile(filepath.Join(mountPoint, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(mountPoint, "a.txt")); err != nil {
		t.Fatal(err)
	}

	// dir_list
	if _, err := os.ReadDir(mountPoint); err != nil {
		t.Fatal(err)
	}

	// symlink_create + symlink_read (best-effort)
	if err := os.Symlink("a.txt", filepath.Join(mountPoint, "ln")); err == nil {
		if _, err := os.Readlink(filepath.Join(mountPoint, "ln")); err != nil {
			t.Fatal(err)
		}
	}

	// file_chmod (setattr)
	if err := os.Chmod(filepath.Join(mountPoint, "a.txt"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := em.snapshot()
	wantAny := map[string]bool{
		"dir_list":       false,
		"file_stat":      false,
		"file_chmod":     false,
		"symlink_create": false,
		"symlink_read":   false,
	}
	for _, tpe := range got {
		if _, ok := wantAny[tpe]; ok {
			wantAny[tpe] = true
		}
	}
	for k, ok := range wantAny {
		if !ok {
			t.Fatalf("expected to observe %s in events; got %v", k, got)
		}
	}
}

// TestFUSE_FsyncFlushLseekPassthrough verifies that fsync(2), implicit flush
// on close, and lseek(2) on a file opened through the agentsh FUSE mount
// succeed instead of returning ENOTSUP. Without explicit Fsync/Flush/Lseek
// pass-throughs on fileHandle, go-fuse falls back to ENOTSUP, which libuv-
// based runtimes surface as "operation not supported on socket, fsync".
func TestFUSE_FsyncFlushLseekPassthrough(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("fuse not available: %v", err)
	}

	backing := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow-workspace", Paths: []string{"/workspace", "/workspace/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}

	hooks := &Hooks{
		SessionID: "session-fsync",
		Policy:    engine,
		Emit:      &typeCaptureEmitter{},
	}

	m, err := MountWorkspace(context.Background(), backing, mountPoint, hooks)
	if err != nil {
		t.Skipf("mount failed (skipping): %v", err)
	}
	defer func() { _ = m.Unmount() }()

	path := filepath.Join(mountPoint, "data.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// fsync should succeed (was ENOTSUP without pass-through).
	if err := f.Sync(); err != nil {
		t.Fatalf("fsync returned %v; expected nil (ENOTSUP regression)", err)
	}

	// lseek(SEEK_SET, 0) should succeed.
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("lseek returned %v; expected nil", err)
	}

	// Close exercises the flush path; must not surface ENOTSUP either.
	if err := f.Close(); err != nil {
		t.Fatalf("close (flush) returned %v; expected nil", err)
	}
}
