//go:build linux

package fsmonitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

// Integration: requires /dev/fuse. Verifies soft-delete diversion hashes small files.
func TestFUSE_SoftDeleteHashesSmallFile(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("fuse not available: %v", err)
	}

	workspace := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	// create file to delete
	src := filepath.Join(mountPoint, "tiny.txt")
	backingPath := filepath.Join(workspace, "tiny.txt")
	if err := os.WriteFile(backingPath, []byte("abcd"), 0o644); err != nil {
		t.Fatal(err)
	}

	trashDir := ".agentsh_trash"
	enabled := true
	hooks := &Hooks{
		FUSEAudit: &FUSEAuditHooks{
			Config: config.FUSEAuditConfig{
				Enabled:   &enabled,
				Mode:      "soft_delete",
				TrashPath: trashDir,
			},
			HashLimitBytes: 1 << 20,
		},
	}

	m, err := MountWorkspace(workspace, mountPoint, hooks)
	if err != nil {
		t.Skipf("mount failed (skipping): %v", err)
	}
	defer func() { _ = m.Unmount() }()

	if err := os.Remove(src); err != nil {
		t.Fatalf("remove via mount: %v", err)
	}

	manPath := filepath.Join(workspace, trashDir, "manifest")
	entries, err := os.ReadDir(manPath)
	if err != nil {
		t.Fatalf("read manifest dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected manifest entry for diverted file")
	}
	b, err := os.ReadFile(filepath.Join(manPath, entries[0].Name()))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var entry struct {
		Hash     string `json:"hash"`
		HashAlgo string `json:"hash_algo"`
	}
	if err := json.Unmarshal(b, &entry); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if entry.Hash == "" || entry.HashAlgo != "sha256" {
		t.Fatalf("hash not recorded correctly: %+v", entry)
	}
}
