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
	_, err := resolveRealPathUnderRoot(root, "/workspace/link", true, "/workspace")
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
	p, err := resolveRealPathUnderRoot(root, "/workspace/in", true, "/workspace")
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
	_, err := resolveRealPathUnderRoot(root, "/workspace/p/newfile", false, "/workspace")
	if err == nil {
		t.Fatalf("expected escape error")
	}
}

func TestEvalEscapedSymlink_ResolvesOutsideTarget(t *testing.T) {
	// Simulates a venv-style symlink: workspace/bin/python -> /etc/hostname
	// (using /etc/hostname instead of /usr/bin/python3 so the test runs on
	// systems with arbitrary Python installs).
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(root, "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	// Sanity: resolveRealPathUnderRoot rejects this with a symlink-escape error.
	if _, err := resolveRealPathUnderRoot(root, "/workspace/bin/python", true, "/workspace"); err == nil {
		t.Fatalf("expected resolveRealPathUnderRoot to fail on escaping symlink")
	}

	// evalEscapedSymlink should return the resolved outside path so the
	// caller can policy-check it instead of blanket-denying.
	got := evalEscapedSymlink(root, "/workspace/bin/python", "/workspace")
	want, err := filepath.EvalSymlinks("/etc/hostname")
	if err != nil {
		t.Skipf("/etc/hostname not resolvable: %v", err)
	}
	if got != filepath.Clean(want) {
		t.Fatalf("evalEscapedSymlink = %q; want %q", got, filepath.Clean(want))
	}
}

func TestEvalEscapedSymlink_BrokenLinkReturnsEmpty(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("/no/such/path/anywhere", filepath.Join(root, "broken")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if got := evalEscapedSymlink(root, "/workspace/broken", "/workspace"); got != "" {
		t.Fatalf("broken link should return empty; got %q", got)
	}
}

func TestEvalEscapedSymlink_PathNotUnderRootReturnsEmpty(t *testing.T) {
	root := t.TempDir()
	if got := evalEscapedSymlink(root, "/elsewhere/foo", "/workspace"); got != "" {
		t.Fatalf("non-/workspace path should return empty; got %q", got)
	}
}

// a "..":-style escape whose resolved sibling actually exists on disk
// must NOT fall through to file_rules. pathutil.IsUnderRoot only checks
// the raw virtual prefix (which "/workspace/../sibling/secret" passes),
// but filepath.Join cleans the candidate to a real sibling of the workspace root.
// evalEscapedSymlink must reject it (return "") before resolving so the caller keeps the
// workspace-escape deny -- otherwise a broad allow rule like /** could
// read arbitrary sibling paths.
func TestEvalEscapedSymlink_DotDotEscapeToExistingSiblingReturnsEmpty(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// Real sibling next to the workspace root, with an existing file, so
	// EvalSymlinks would succeed if we ever reached it.
	sibling := filepath.Join(parent, "outside")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := evalEscapedSymlink(root, "/workspace/../outside/secret", "/workspace"); got != "" {
		t.Fatalf("..-escape to existing sibling must return empty (stay workspace-escape); got %q", got)
	}
}
