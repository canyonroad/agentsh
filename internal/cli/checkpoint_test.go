package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCheckpointCmd_Create(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "checkpoints")
	workspace := filepath.Join(tmpDir, "workspace")

	// Create workspace with a file
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "test.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cmd := newCheckpointCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"create",
		"--storage-dir", storageDir,
		"--session", "test-session",
		"--workspace", workspace,
		"--reason", "test checkpoint",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Created checkpoint") {
		t.Errorf("expected 'Created checkpoint' in output, got: %s", output)
	}
	if !strings.Contains(output, "Can rollback: true") {
		t.Errorf("expected 'Can rollback: true' in output, got: %s", output)
	}
}

func TestCheckpointCmd_List(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "checkpoints")
	workspace := filepath.Join(tmpDir, "workspace")

	// Create workspace
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "test.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Create a checkpoint first
	createCmd := newCheckpointCmd()
	createCmd.SetArgs([]string{
		"create",
		"--storage-dir", storageDir,
		"--session", "test-session",
		"--workspace", workspace,
	})
	if err := createCmd.Execute(); err != nil {
		t.Fatalf("create: %v", err)
	}

	// List checkpoints
	listCmd := newCheckpointCmd()
	buf := new(bytes.Buffer)
	listCmd.SetOut(buf)
	listCmd.SetErr(buf)
	listCmd.SetArgs([]string{
		"list",
		"--storage-dir", storageDir,
		"--session", "test-session",
	})

	if err := listCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ID") || !strings.Contains(output, "CREATED") {
		t.Errorf("expected table headers in output, got: %s", output)
	}
}

func TestCheckpointCmd_List_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "checkpoints")

	cmd := newCheckpointCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"list",
		"--storage-dir", storageDir,
		"--session", "nonexistent-session",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No checkpoints found") {
		t.Errorf("expected 'No checkpoints found' in output, got: %s", output)
	}
}

func TestCheckpointCmd_Show(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "checkpoints")
	workspace := filepath.Join(tmpDir, "workspace")

	// Create workspace
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "test.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Create checkpoint and capture ID
	createCmd := newCheckpointCmd()
	createBuf := new(bytes.Buffer)
	createCmd.SetOut(createBuf)
	createCmd.SetArgs([]string{
		"create",
		"--storage-dir", storageDir,
		"--session", "test-session",
		"--workspace", workspace,
	})
	if err := createCmd.Execute(); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Extract checkpoint ID from output
	output := createBuf.String()
	lines := strings.Split(output, "\n")
	var cpID string
	for _, line := range lines {
		if strings.HasPrefix(line, "Created checkpoint ") {
			cpID = strings.TrimPrefix(line, "Created checkpoint ")
			break
		}
	}
	if cpID == "" {
		t.Fatalf("could not extract checkpoint ID from: %s", output)
	}

	// Show checkpoint
	showCmd := newCheckpointCmd()
	showBuf := new(bytes.Buffer)
	showCmd.SetOut(showBuf)
	showCmd.SetErr(showBuf)
	showCmd.SetArgs([]string{
		"show", cpID,
		"--storage-dir", storageDir,
		"--session", "test-session",
	})

	if err := showCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	showOutput := showBuf.String()
	if !strings.Contains(showOutput, "Checkpoint:") {
		t.Errorf("expected 'Checkpoint:' in output, got: %s", showOutput)
	}
	if !strings.Contains(showOutput, "test.txt") {
		t.Errorf("expected 'test.txt' in files list, got: %s", showOutput)
	}
}

func TestCheckpointCmd_Rollback_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "checkpoints")
	workspace := filepath.Join(tmpDir, "workspace")

	// Create workspace with file
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	file1 := filepath.Join(workspace, "test.txt")
	if err := os.WriteFile(file1, []byte("original"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Create checkpoint
	createCmd := newCheckpointCmd()
	createBuf := new(bytes.Buffer)
	createCmd.SetOut(createBuf)
	createCmd.SetArgs([]string{
		"create",
		"--storage-dir", storageDir,
		"--session", "test-session",
		"--workspace", workspace,
	})
	if err := createCmd.Execute(); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Extract checkpoint ID
	output := createBuf.String()
	var cpID string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Created checkpoint ") {
			cpID = strings.TrimPrefix(line, "Created checkpoint ")
			break
		}
	}

	// Modify file
	if err := os.WriteFile(file1, []byte("modified"), 0644); err != nil {
		t.Fatalf("modify file: %v", err)
	}

	// Dry-run rollback
	rollbackCmd := newCheckpointCmd()
	rollbackBuf := new(bytes.Buffer)
	rollbackCmd.SetOut(rollbackBuf)
	rollbackCmd.SetErr(rollbackBuf)
	rollbackCmd.SetArgs([]string{
		"rollback", cpID,
		"--storage-dir", storageDir,
		"--session", "test-session",
		"--workspace", workspace,
		"--dry-run",
	})

	if err := rollbackCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	rollbackOutput := rollbackBuf.String()
	if !strings.Contains(rollbackOutput, "dry-run") {
		t.Errorf("expected 'dry-run' in output, got: %s", rollbackOutput)
	}

	// File should still be modified
	data, _ := os.ReadFile(file1)
	if string(data) != "modified" {
		t.Error("file was changed during dry-run")
	}
}

func TestCheckpointCmd_Rollback_Actual(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "checkpoints")
	workspace := filepath.Join(tmpDir, "workspace")

	// Create workspace with file
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	file1 := filepath.Join(workspace, "test.txt")
	if err := os.WriteFile(file1, []byte("original"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Create checkpoint
	createCmd := newCheckpointCmd()
	createBuf := new(bytes.Buffer)
	createCmd.SetOut(createBuf)
	createCmd.SetArgs([]string{
		"create",
		"--storage-dir", storageDir,
		"--session", "test-session",
		"--workspace", workspace,
	})
	if err := createCmd.Execute(); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Extract checkpoint ID
	output := createBuf.String()
	var cpID string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Created checkpoint ") {
			cpID = strings.TrimPrefix(line, "Created checkpoint ")
			break
		}
	}

	// Modify file
	if err := os.WriteFile(file1, []byte("modified"), 0644); err != nil {
		t.Fatalf("modify file: %v", err)
	}

	// Actual rollback
	rollbackCmd := newCheckpointCmd()
	rollbackBuf := new(bytes.Buffer)
	rollbackCmd.SetOut(rollbackBuf)
	rollbackCmd.SetErr(rollbackBuf)
	rollbackCmd.SetArgs([]string{
		"rollback", cpID,
		"--storage-dir", storageDir,
		"--session", "test-session",
		"--workspace", workspace,
	})

	if err := rollbackCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// File should be restored
	data, _ := os.ReadFile(file1)
	if string(data) != "original" {
		t.Errorf("file content = %q, want 'original'", string(data))
	}
}

func TestCheckpointCmd_Purge(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "checkpoints")
	workspace := filepath.Join(tmpDir, "workspace")

	// Create workspace
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "test.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Create multiple checkpoints
	for i := 0; i < 3; i++ {
		createCmd := newCheckpointCmd()
		createCmd.SetArgs([]string{
			"create",
			"--storage-dir", storageDir,
			"--session", "test-session",
			"--workspace", workspace,
		})
		if err := createCmd.Execute(); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	// Purge keeping only 1
	purgeCmd := newCheckpointCmd()
	purgeBuf := new(bytes.Buffer)
	purgeCmd.SetOut(purgeBuf)
	purgeCmd.SetErr(purgeBuf)
	purgeCmd.SetArgs([]string{
		"purge",
		"--storage-dir", storageDir,
		"--session", "test-session",
		"--keep", "1",
	})

	if err := purgeCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	purgeOutput := purgeBuf.String()
	if !strings.Contains(purgeOutput, "Purged 2 checkpoints") {
		t.Errorf("expected 'Purged 2 checkpoints' in output, got: %s", purgeOutput)
	}
}

func TestCheckpointCmd_MissingSession(t *testing.T) {
	cmd := newCheckpointCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing --session")
	}
	if !strings.Contains(err.Error(), "--session is required") {
		t.Errorf("expected '--session is required' error, got: %v", err)
	}
}

// Helper to run a cobra command in tests
func executeCommand(root *cobra.Command, args ...string) (output string, err error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err = root.Execute()
	return buf.String(), err
}
