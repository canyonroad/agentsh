package fsmonitor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRealPathUnderRoot_BlocksSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	_, err := resolveRealPathUnderRoot(root, "/workspace/link", true)
	if err == nil {
		t.Fatalf("expected escape error")
	}
}

func TestResolveRealPathUnderRoot_AllowsInTreeSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dir", "a.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dir/a.txt", filepath.Join(root, "in")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	p, err := resolveRealPathUnderRoot(root, "/workspace/in", true)
	if err != nil {
		t.Fatal(err)
	}
	// Resolve symlinks on root for comparison (macOS /var -> /private/var)
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		resolvedRoot = root
	}
	if filepath.Clean(p) != filepath.Join(resolvedRoot, "dir", "a.txt") {
		t.Fatalf("unexpected resolved path: %s", p)
	}
}

func TestResolveRealPathUnderRoot_UsesParentForCreate(t *testing.T) {
	root := t.TempDir()
	// Parent is a symlink to /etc, so creating under it should be blocked even though the file doesn't exist yet.
	if err := os.Symlink("/etc", filepath.Join(root, "p")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	_, err := resolveRealPathUnderRoot(root, "/workspace/p/newfile", false)
	if err == nil {
		t.Fatalf("expected escape error")
	}
}
