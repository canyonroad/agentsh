//go:build linux

package fsmonitor

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// Verifies outside->inside rename emits a create event with metadata.
func TestFUSE_CrossMountIntoWorkspaceEmitsCreate(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("fuse not available")
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

	em := &captureEmitter{}
	hooks := &Hooks{
		SessionID: "sess",
		Policy:    engine,
		Emit:      em,
		FUSEAudit: &FUSEAuditHooks{},
	}

	m, err := MountWorkspace(backing, mountPoint, hooks)
	if err != nil {
		t.Skipf("mount failed: %v", err)
	}
	defer func() { _ = m.Unmount() }()

	// Create file outside and rename into workspace mount.
	outsideDir := t.TempDir()
	src := filepath.Join(outsideDir, "a.txt")
	if err := os.WriteFile(src, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(mountPoint, "a.txt")
	if err := os.Rename(src, dest); err != nil {
		if linkErr, ok := err.(*os.LinkError); ok && linkErr.Err == syscall.EXDEV {
			data, readErr := os.ReadFile(src)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if writeErr := os.WriteFile(dest, data, 0o644); writeErr != nil {
				t.Fatal(writeErr)
			}
			_ = os.Remove(src)
		} else {
			t.Fatal(err)
		}
	}

	found := false
	for _, ev := range em.events {
		if ev.Type == "file_create" && ev.Path == "/workspace/a.txt" {
			found = true
			if _, ok := ev.Fields["size"]; !ok {
				t.Fatalf("expected size in create event")
			}
			break
		}
	}
	if !found {
		t.Fatalf("file_create event not emitted for cross-mount rename")
	}
}

type captureEmitter struct {
	events []types.Event
}

func (c *captureEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	c.events = append(c.events, ev)
	return nil
}
func (c *captureEmitter) Publish(ev types.Event) { c.events = append(c.events, ev) }
