//go:build linux

package fsmonitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

// TestFUSE_PerPathSoftDelete_UnderMonitorMode is the regression test for #417:
// a per-path `decision: soft_delete` policy rule must route unlink to trash even
// when the global audit mode is the default "monitor".
func TestFUSE_PerPathSoftDelete_UnderMonitorMode(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("fuse not available: %v", err)
	}

	workspace := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	target := filepath.Join(workspace, "testfile.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	// checkWithExist resolves /workspace/... to the real backing path before
	// CheckFile, so use "/**" so the rule matches the resolved temp-dir path.
	pol := &policy.Policy{
		Version: 1,
		Name:    "per-path-soft-delete",
		FileRules: []policy.FileRule{
			{Name: "sd", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "soft_delete"},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}

	var notifiedPath, notifiedToken string
	enabled := true
	hooks := &Hooks{
		SessionID: "session-perpath",
		Policy:    engine,
		Emit:      &typeCaptureEmitter{},
		FUSEAudit: &FUSEAuditHooks{
			// Global mode is monitor; only the per-path policy decision
			// should trigger the divert.
			Config: config.FUSEAuditConfig{
				Enabled:   &enabled,
				Mode:      "monitor",
				TrashPath: ".agentsh_trash",
			},
			NotifySoftDelete: func(path, token string) {
				notifiedPath, notifiedToken = path, token
			},
		},
	}

	m, err := MountWorkspace(context.Background(), workspace, mountPoint, hooks)
	if err != nil {
		t.Skipf("mount failed (skipping): %v", err)
	}
	defer func() { _ = m.Unmount() }()

	mountTarget := filepath.Join(mountPoint, "testfile.txt")
	if err := os.Remove(mountTarget); err != nil {
		t.Fatalf("os.Remove returned %v; expected nil (soft-delete should succeed)", err)
	}

	// The original backing file must be gone (moved), not present.
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("expected backing file to be moved out; stat err=%v", err)
	}

	// The trash directory must now contain the diverted file.
	trashDir := filepath.Join(workspace, ".agentsh_trash")
	entries, err := os.ReadDir(trashDir)
	if err != nil {
		t.Fatalf("read trash dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected trash dir to contain the soft-deleted file, found none")
	}

	if notifiedPath == "" || notifiedToken == "" {
		t.Fatalf("expected NotifySoftDelete to fire; got path=%q token=%q", notifiedPath, notifiedToken)
	}
}

// TestFUSE_PerPathAllow_UnderMonitorMode is the negative case: with global mode
// monitor and an allow decision, unlink is a real delete and trash stays empty.
func TestFUSE_PerPathAllow_UnderMonitorMode(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("fuse not available: %v", err)
	}

	workspace := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	target := filepath.Join(workspace, "testfile.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}

	enabled := true
	hooks := &Hooks{
		SessionID: "session-allow",
		Policy:    engine,
		Emit:      &typeCaptureEmitter{},
		FUSEAudit: &FUSEAuditHooks{
			Config: config.FUSEAuditConfig{Enabled: &enabled, Mode: "monitor", TrashPath: ".agentsh_trash"},
		},
	}

	m, err := MountWorkspace(context.Background(), workspace, mountPoint, hooks)
	if err != nil {
		t.Skipf("mount failed (skipping): %v", err)
	}
	defer func() { _ = m.Unmount() }()

	if err := os.Remove(filepath.Join(mountPoint, "testfile.txt")); err != nil {
		t.Fatalf("os.Remove returned %v; expected nil", err)
	}

	trashDir := filepath.Join(workspace, ".agentsh_trash")
	if entries, err := os.ReadDir(trashDir); err == nil && len(entries) > 0 {
		t.Fatalf("expected no trash under allow+monitor, found %d entries", len(entries))
	}
}
