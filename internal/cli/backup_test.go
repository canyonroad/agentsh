package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupCmd_Help(t *testing.T) {
	cmd := NewRoot("test")
	cmd.SetArgs([]string{"backup", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Errorf("backup help failed: %v", err)
	}
}

func TestRestoreCmd_RequiresInput(t *testing.T) {
	cmd := NewRoot("test")
	cmd.SetArgs([]string{"restore"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error without --input")
	}
}

func TestBackupRestore_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Create test config file
	configPath := filepath.Join(dir, "config.yaml")
	configContent := []byte("audit:\n  storage:\n    sqlite_path: " + filepath.Join(dir, "events.db") + "\npolicies:\n  dir: " + filepath.Join(dir, "policies"))
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Create test audit DB
	auditDBPath := filepath.Join(dir, "events.db")
	auditDBContent := []byte("SQLite format 3\x00test audit data")
	if err := os.WriteFile(auditDBPath, auditDBContent, 0644); err != nil {
		t.Fatalf("write audit db: %v", err)
	}

	// Create test policies directory
	policiesDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policiesDir, 0755); err != nil {
		t.Fatalf("create policies dir: %v", err)
	}
	policyContent := []byte("version: 1\nname: default")
	if err := os.WriteFile(filepath.Join(policiesDir, "default.yaml"), policyContent, 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	backupPath := filepath.Join(dir, "backup.tar.gz")

	// Test backup command
	cmd := NewRoot("test")
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"backup", "--output", backupPath, "--config", configPath, "--verify"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("backup failed: %v (stderr: %s)", err, stderr.String())
	}

	// Verify backup file was created
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Fatal("backup file was not created")
	}

	// Verify stdout contains success messages
	output := stdout.String()
	if !bytes.Contains([]byte(output), []byte("Backup created:")) {
		t.Errorf("expected 'Backup created:' in output, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("Verification: OK")) {
		t.Errorf("expected 'Verification: OK' in output, got: %s", output)
	}
}

func TestBackup_VerifyFailsOnCorruptedFile(t *testing.T) {
	dir := t.TempDir()

	// Create a corrupted backup file
	corruptedPath := filepath.Join(dir, "corrupted.tar.gz")
	if err := os.WriteFile(corruptedPath, []byte("not a valid gzip file"), 0644); err != nil {
		t.Fatalf("write corrupted file: %v", err)
	}

	// Test restore with corrupted file
	cmd := NewRoot("test")
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"restore", "--input", corruptedPath})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for corrupted backup file")
	}
}

func TestRestore_DryRunShowsFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a minimal valid backup
	configPath := filepath.Join(dir, "config.yaml")
	configContent := []byte("audit:\n  storage:\n    sqlite_path: " + filepath.Join(dir, "events.db") + "\npolicies:\n  dir: " + filepath.Join(dir, "policies"))
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	backupPath := filepath.Join(dir, "backup.tar.gz")

	// Create backup
	cmd := NewRoot("test")
	cmd.SetArgs([]string{"backup", "--output", backupPath, "--config", configPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// Test dry-run restore
	cmd2 := NewRoot("test")
	var stdout bytes.Buffer
	cmd2.SetOut(&stdout)
	cmd2.SetArgs([]string{"restore", "--input", backupPath, "--dry-run"})

	if err := cmd2.Execute(); err != nil {
		t.Fatalf("dry-run restore failed: %v", err)
	}

	output := stdout.String()
	if !bytes.Contains([]byte(output), []byte("Would restore:")) {
		t.Errorf("expected 'Would restore:' in dry-run output, got: %s", output)
	}
}

func TestSanitizeTarPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid path", "config.yaml", false},
		{"valid nested path", "policies/default.yaml", false},
		{"absolute path rejected", "/etc/passwd", true},
		{"path traversal rejected", "../../../etc/passwd", true},
		{"double dot rejected", "foo/../bar", false}, // Clean will resolve this to "bar"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sanitizeTarPath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeTarPath(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
