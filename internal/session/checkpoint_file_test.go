package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileCheckpointStorage_CreateAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(tmpDir, 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	cp := &Checkpoint{
		ID:            "cp-123",
		SessionID:     "sess-456",
		CreatedAt:     time.Now().UTC(),
		Reason:        "test checkpoint",
		WorkspaceHash: "abc123",
		ModifiedFiles: []string{"file1.txt", "file2.txt"},
		CanRollback:   true,
	}

	// Save
	if err := storage.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load
	loaded, err := storage.Load(cp.SessionID, cp.ID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.ID != cp.ID {
		t.Errorf("ID = %q, want %q", loaded.ID, cp.ID)
	}
	if loaded.SessionID != cp.SessionID {
		t.Errorf("SessionID = %q, want %q", loaded.SessionID, cp.SessionID)
	}
	if loaded.Reason != cp.Reason {
		t.Errorf("Reason = %q, want %q", loaded.Reason, cp.Reason)
	}
}

func TestFileCheckpointStorage_List(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(tmpDir, 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	sessionID := "sess-list"

	// Create multiple checkpoints
	for i := 0; i < 3; i++ {
		cp := &Checkpoint{
			ID:        "cp-" + string(rune('a'+i)),
			SessionID: sessionID,
			CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Minute),
			Reason:    "checkpoint " + string(rune('a'+i)),
		}
		if err := storage.Save(cp); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	// List
	checkpoints, err := storage.List(sessionID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(checkpoints) != 3 {
		t.Errorf("len(checkpoints) = %d, want 3", len(checkpoints))
	}

	// Should be sorted by creation time (oldest first)
	for i := 0; i < len(checkpoints)-1; i++ {
		if checkpoints[i].CreatedAt.After(checkpoints[i+1].CreatedAt) {
			t.Errorf("checkpoints not sorted by creation time")
		}
	}
}

func TestFileCheckpointStorage_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(tmpDir, 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	cp := &Checkpoint{
		ID:        "cp-delete",
		SessionID: "sess-delete",
		CreatedAt: time.Now().UTC(),
		Reason:    "to be deleted",
	}

	if err := storage.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Delete
	if err := storage.Delete(cp.SessionID, cp.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Should not be loadable
	_, err = storage.Load(cp.SessionID, cp.ID)
	if err != ErrCheckpointNotFound {
		t.Errorf("Load after delete: got %v, want ErrCheckpointNotFound", err)
	}
}

func TestFileCheckpointStorage_CreateSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(filepath.Join(tmpDir, "checkpoints"), 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	// Create workspace with files
	workspace := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	// Create test files
	files := map[string]string{
		"file1.txt":     "content 1",
		"dir/file2.txt": "content 2",
	}
	for path, content := range files {
		fullPath := filepath.Join(workspace, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	// Create checkpoint
	cp := &Checkpoint{
		ID:        "cp-snapshot",
		SessionID: "sess-snapshot",
		CreatedAt: time.Now().UTC(),
		Reason:    "snapshot test",
	}
	if err := storage.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Create snapshot
	if err := storage.CreateSnapshot(cp.SessionID, cp.ID, nil, workspace); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	// Load metadata and verify files
	meta, err := storage.LoadMetadata(cp.SessionID, cp.ID)
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}

	if len(meta.Files) != 2 {
		t.Errorf("len(Files) = %d, want 2", len(meta.Files))
	}

	if !meta.CanRollback {
		t.Error("CanRollback = false, want true")
	}
}

func TestFileCheckpointStorage_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(filepath.Join(tmpDir, "checkpoints"), 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	// Create workspace with initial file
	workspace := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	file1 := filepath.Join(workspace, "file1.txt")
	originalContent := "original content"
	if err := os.WriteFile(file1, []byte(originalContent), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Create checkpoint
	cp := &Checkpoint{
		ID:        "cp-rollback",
		SessionID: "sess-rollback",
		CreatedAt: time.Now().UTC(),
		Reason:    "rollback test",
	}
	if err := storage.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Create snapshot
	if err := storage.CreateSnapshot(cp.SessionID, cp.ID, nil, workspace); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	// Modify file
	modifiedContent := "modified content"
	if err := os.WriteFile(file1, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("modify file: %v", err)
	}

	// Verify file was modified
	data, _ := os.ReadFile(file1)
	if string(data) != modifiedContent {
		t.Fatalf("file not modified")
	}

	// Rollback
	restored, err := storage.Rollback(cp.SessionID, cp.ID, workspace)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if len(restored) != 1 {
		t.Errorf("len(restored) = %d, want 1", len(restored))
	}

	// Verify file was restored
	data, _ = os.ReadFile(file1)
	if string(data) != originalContent {
		t.Errorf("file content = %q, want %q", string(data), originalContent)
	}
}

func TestFileCheckpointStorage_Diff(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(filepath.Join(tmpDir, "checkpoints"), 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	// Create workspace with file
	workspace := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	file1 := filepath.Join(workspace, "file1.txt")
	if err := os.WriteFile(file1, []byte("original"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Create checkpoint
	cp := &Checkpoint{
		ID:        "cp-diff",
		SessionID: "sess-diff",
		CreatedAt: time.Now().UTC(),
		Reason:    "diff test",
	}
	if err := storage.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Create snapshot
	if err := storage.CreateSnapshot(cp.SessionID, cp.ID, nil, workspace); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	// Modify file
	if err := os.WriteFile(file1, []byte("modified"), 0644); err != nil {
		t.Fatalf("modify file: %v", err)
	}

	// Add new file
	file2 := filepath.Join(workspace, "file2.txt")
	if err := os.WriteFile(file2, []byte("new file"), 0644); err != nil {
		t.Fatalf("write new file: %v", err)
	}

	// Get diff
	diffs, err := storage.Diff(cp.SessionID, cp.ID, workspace)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	// Should have 2 diffs: modified and added
	if len(diffs) != 2 {
		t.Errorf("len(diffs) = %d, want 2", len(diffs))
	}

	// Find modified file
	var modified, added *FileDiff
	for i := range diffs {
		switch diffs[i].Status {
		case "modified":
			modified = &diffs[i]
		case "added":
			added = &diffs[i]
		}
	}

	if modified == nil || modified.Path != "file1.txt" {
		t.Errorf("missing or wrong modified file diff")
	}

	if added == nil || added.Path != "file2.txt" {
		t.Errorf("missing or wrong added file diff")
	}
}

func TestFileCheckpointStorage_Diff_DeletedFile(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(filepath.Join(tmpDir, "checkpoints"), 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	// Create workspace with file
	workspace := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	file1 := filepath.Join(workspace, "file1.txt")
	if err := os.WriteFile(file1, []byte("content"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Create checkpoint
	cp := &Checkpoint{
		ID:        "cp-diff-delete",
		SessionID: "sess-diff-delete",
		CreatedAt: time.Now().UTC(),
		Reason:    "diff delete test",
	}
	if err := storage.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := storage.CreateSnapshot(cp.SessionID, cp.ID, nil, workspace); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	// Delete file
	if err := os.Remove(file1); err != nil {
		t.Fatalf("remove file: %v", err)
	}

	// Get diff
	diffs, err := storage.Diff(cp.SessionID, cp.ID, workspace)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(diffs) != 1 {
		t.Fatalf("len(diffs) = %d, want 1", len(diffs))
	}

	if diffs[0].Status != "deleted" {
		t.Errorf("Status = %q, want 'deleted'", diffs[0].Status)
	}
}

func TestFileCheckpointStorage_Purge(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(tmpDir, 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	sessionID := "sess-purge"

	// Create checkpoints with different ages
	now := time.Now().UTC()
	checkpoints := []struct {
		id        string
		createdAt time.Time
	}{
		{"cp-old-1", now.Add(-2 * time.Hour)},
		{"cp-old-2", now.Add(-90 * time.Minute)},
		{"cp-new-1", now.Add(-30 * time.Minute)},
		{"cp-new-2", now.Add(-10 * time.Minute)},
	}

	for _, c := range checkpoints {
		cp := &Checkpoint{
			ID:        c.id,
			SessionID: sessionID,
			CreatedAt: c.createdAt,
			Reason:    "purge test",
		}
		if err := storage.Save(cp); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	// Purge checkpoints older than 1 hour
	deleted, err := storage.Purge(sessionID, time.Hour, 0)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}

	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}

	// Verify remaining checkpoints
	remaining, err := storage.List(sessionID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(remaining) != 2 {
		t.Errorf("remaining = %d, want 2", len(remaining))
	}
}

func TestFileCheckpointStorage_Purge_MaxCount(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(tmpDir, 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	sessionID := "sess-purge-count"

	// Create 5 checkpoints
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		cp := &Checkpoint{
			ID:        "cp-" + string(rune('a'+i)),
			SessionID: sessionID,
			CreatedAt: now.Add(time.Duration(i) * time.Minute),
			Reason:    "purge count test",
		}
		if err := storage.Save(cp); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	// Purge to keep only 2
	deleted, err := storage.Purge(sessionID, 0, 2)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}

	if deleted != 3 {
		t.Errorf("deleted = %d, want 3", deleted)
	}

	// Verify remaining checkpoints
	remaining, err := storage.List(sessionID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(remaining) != 2 {
		t.Errorf("remaining = %d, want 2", len(remaining))
	}

	// Should keep newest ones (d and e)
	for _, cp := range remaining {
		if cp.ID != "cp-d" && cp.ID != "cp-e" {
			t.Errorf("unexpected checkpoint ID: %s", cp.ID)
		}
	}
}

func TestFileCheckpointStorage_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(tmpDir, 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	_, err = storage.Load("nonexistent-session", "nonexistent-cp")
	if err != ErrCheckpointNotFound {
		t.Errorf("Load nonexistent: got %v, want ErrCheckpointNotFound", err)
	}
}

func TestFileCheckpointStorage_SkipHiddenDirs(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileCheckpointStorage(filepath.Join(tmpDir, "checkpoints"), 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}

	// Create workspace with hidden dir
	workspace := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".git"), 0755); err != nil {
		t.Fatalf("create .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".git", "config"), []byte("git config"), 0644); err != nil {
		t.Fatalf("write .git/config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "file.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("write file.txt: %v", err)
	}

	cp := &Checkpoint{
		ID:        "cp-hidden",
		SessionID: "sess-hidden",
		CreatedAt: time.Now().UTC(),
		Reason:    "hidden dir test",
	}
	if err := storage.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := storage.CreateSnapshot(cp.SessionID, cp.ID, nil, workspace); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	meta, err := storage.LoadMetadata(cp.SessionID, cp.ID)
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}

	// Should only have file.txt, not .git/config
	if len(meta.Files) != 1 {
		t.Errorf("len(Files) = %d, want 1", len(meta.Files))
	}

	if len(meta.Files) > 0 && meta.Files[0].Path != "file.txt" {
		t.Errorf("unexpected file: %s", meta.Files[0].Path)
	}
}
