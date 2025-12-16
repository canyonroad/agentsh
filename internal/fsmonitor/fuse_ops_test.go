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

// NOTE: this test mounts a real FUSE filesystem; it will skip if /dev/fuse is unavailable.
func TestFUSE_InterceptsExtraOps(t *testing.T) {
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
	engine, err := policy.NewEngine(pol, false)
	if err != nil {
		t.Fatal(err)
	}

	em := &typeCaptureEmitter{}
	hooks := &Hooks{
		SessionID: "session-test",
		Policy:    engine,
		Emit:      em,
	}

	m, err := MountWorkspace(backing, mountPoint, hooks)
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
