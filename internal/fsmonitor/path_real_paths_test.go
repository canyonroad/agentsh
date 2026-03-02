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

	// Resolve expected path to handle macOS /var -> /private/var symlink
	wantSub, _ := filepath.EvalSymlinks(sub)
	if wantSub == "" {
		wantSub = sub
	}

	got, err := resolveRealPathUnderRoot(root, root+"/sub", true, root)
	if err != nil {
		t.Fatalf("resolveRealPathUnderRoot: %v", err)
	}
	if got != wantSub {
		t.Errorf("got %q, want %q", got, wantSub)
	}
}

func TestResolveRealPathUnderRoot_DefaultWorkspace(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}

	wantSub, _ := filepath.EvalSymlinks(sub)
	if wantSub == "" {
		wantSub = sub
	}

	got, err := resolveRealPathUnderRoot(root, "/workspace/sub", true, "/workspace")
	if err != nil {
		t.Fatalf("resolveRealPathUnderRoot: %v", err)
	}
	if got != wantSub {
		t.Errorf("got %q, want %q", got, wantSub)
	}
}

func TestResolveRealPathUnderRoot_EscapeBlocked(t *testing.T) {
	root := t.TempDir()

	_, err := resolveRealPathUnderRoot(root, "/workspace/../etc/passwd", true, "/workspace")
	if err == nil {
		t.Error("expected error for path escape")
	}
}

func TestResolveRealPathUnderRoot_SiblingPrefix(t *testing.T) {
	root := t.TempDir()

	// Sibling path like /tmp/ws-extra should NOT match virtualRoot /tmp/ws
	_, err := resolveRealPathUnderRoot(root, root+"-extra/file", true, root)
	if err == nil {
		t.Error("expected error for sibling-prefix path")
	}
}

func TestResolveRealPathUnderRoot_RootVirtualRoot(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "etc")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}

	wantSub, _ := filepath.EvalSymlinks(sub)
	if wantSub == "" {
		wantSub = sub
	}

	// When virtualRoot is "/", paths like "/etc" should be accepted
	got, err := resolveRealPathUnderRoot(root, "/etc", true, "/")
	if err != nil {
		t.Fatalf("resolveRealPathUnderRoot with root /: %v", err)
	}
	if got != wantSub {
		t.Errorf("got %q, want %q", got, wantSub)
	}
}
