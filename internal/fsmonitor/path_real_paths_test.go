//go:build !windows

package fsmonitor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRealPathUnderRoot_CustomVirtualRoot(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveRealPathUnderRoot(root, root+"/sub", true, root)
	if err != nil {
		t.Fatalf("resolveRealPathUnderRoot: %v", err)
	}
	if got != sub {
		t.Errorf("got %q, want %q", got, sub)
	}
}

func TestResolveRealPathUnderRoot_DefaultWorkspace(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveRealPathUnderRoot(root, "/workspace/sub", true, "/workspace")
	if err != nil {
		t.Fatalf("resolveRealPathUnderRoot: %v", err)
	}
	if got != sub {
		t.Errorf("got %q, want %q", got, sub)
	}
}

func TestResolveRealPathUnderRoot_EscapeBlocked(t *testing.T) {
	root := t.TempDir()

	_, err := resolveRealPathUnderRoot(root, "/workspace/../etc/passwd", true, "/workspace")
	if err == nil {
		t.Error("expected error for path escape")
	}
}
