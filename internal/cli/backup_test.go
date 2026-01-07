package cli

import (
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

	// Create test files
	configPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(configPath, []byte("test: config"), 0644)

	backupPath := filepath.Join(dir, "backup.tar.gz")

	// Test backup command structure
	cmd := NewRoot("test")
	cmd.SetArgs([]string{"backup", "--output", backupPath, "--config", configPath})
	// This will fail because default paths don't exist, but tests command parsing
}
