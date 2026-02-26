package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashBinary(t *testing.T) {
	// Create a temp file to hash
	dir := t.TempDir()
	binPath := filepath.Join(dir, "test-binary")
	if err := os.WriteFile(binPath, []byte("hello world"), 0o755); err != nil {
		t.Fatal(err)
	}

	absPath, hash, err := HashBinary(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if absPath != binPath {
		t.Errorf("absPath = %q, want %q", absPath, binPath)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("hash should start with sha256:, got %q", hash)
	}
	if len(hash) != 7+64 { // "sha256:" + 64 hex chars
		t.Errorf("hash length = %d, want %d", len(hash), 7+64)
	}

	// Same content = same hash
	_, hash2, _ := HashBinary(binPath)
	if hash != hash2 {
		t.Error("same file should produce same hash")
	}
}

func TestHashBinary_NotFound(t *testing.T) {
	// Use a path in a temp directory that definitely doesn't exist (portable).
	missing := filepath.Join(t.TempDir(), "nonexistent-binary")
	_, _, err := HashBinary(missing)
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}
