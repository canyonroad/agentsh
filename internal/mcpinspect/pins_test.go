package mcpinspect

import (
	"path/filepath"
	"testing"
)

func TestPinStore_TrustAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewPinStore(filepath.Join(tmpDir, "pins.db"))
	if err != nil {
		t.Fatalf("NewPinStore: %v", err)
	}
	defer store.Close()

	serverID := "github"
	toolName := "create_issue"
	hash := "sha256:abc123def456"

	// Trust a tool
	err = store.Trust(serverID, toolName, hash)
	if err != nil {
		t.Fatalf("Trust: %v", err)
	}

	// Verify same hash
	result, err := store.Verify(serverID, toolName, hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Status != PinStatusMatch {
		t.Errorf("Expected PinStatusMatch, got %v", result.Status)
	}

	// Verify different hash
	result, err = store.Verify(serverID, toolName, "sha256:different")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Status != PinStatusMismatch {
		t.Errorf("Expected PinStatusMismatch, got %v", result.Status)
	}
	if result.PinnedHash != hash {
		t.Errorf("Expected pinned hash %q, got %q", hash, result.PinnedHash)
	}
}

func TestPinStore_List(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewPinStore(filepath.Join(tmpDir, "pins.db"))
	if err != nil {
		t.Fatalf("NewPinStore: %v", err)
	}
	defer store.Close()

	// Trust multiple tools
	store.Trust("github", "create_issue", "sha256:aaa")
	store.Trust("github", "list_repos", "sha256:bbb")
	store.Trust("filesystem", "read_file", "sha256:ccc")

	// List all
	pins, err := store.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pins) != 3 {
		t.Errorf("Expected 3 pins, got %d", len(pins))
	}

	// List by server
	pins, err = store.List("github")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pins) != 2 {
		t.Errorf("Expected 2 pins for github, got %d", len(pins))
	}
}

func TestPinStore_Reset(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewPinStore(filepath.Join(tmpDir, "pins.db"))
	if err != nil {
		t.Fatalf("NewPinStore: %v", err)
	}
	defer store.Close()

	store.Trust("github", "create_issue", "sha256:aaa")

	// Reset
	err = store.Reset("github", "create_issue")
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}

	// Verify not pinned
	result, _ := store.Verify("github", "create_issue", "sha256:bbb")
	if result.Status != PinStatusNotPinned {
		t.Errorf("Expected PinStatusNotPinned after reset, got %v", result.Status)
	}
}
