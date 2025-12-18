package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envGet(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func stringsTrim(s string) string { return strings.TrimSpace(s) }

func TestResolveSessionID_UsesEnvSessionID(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		"AGENTSH_SESSION_ID": "sess-env-123",
	}

	id, path, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:  envGet(env),
		WorkDir: dir,
		BaseDirs: []string{
			filepath.Join(dir, "run"),
			filepath.Join(dir, "tmp"),
		},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID failed: %v", err)
	}
	if id != "sess-env-123" {
		t.Fatalf("expected env session id, got %q", id)
	}
	if path != "" {
		t.Fatalf("expected empty path for env-provided session id, got %q", path)
	}
}

func TestResolveSessionID_EnvSessionIDWinsOverSessionFile(t *testing.T) {
	dir := t.TempDir()
	sessFile := filepath.Join(dir, "sid.txt")
	env := map[string]string{
		"AGENTSH_SESSION_ID":   "sess-env-123",
		"AGENTSH_SESSION_FILE": sessFile,
	}

	id, path, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:  envGet(env),
		WorkDir: dir,
		BaseDirs: []string{
			filepath.Join(dir, "run"),
		},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID failed: %v", err)
	}
	if id != "sess-env-123" {
		t.Fatalf("expected env session id, got %q", id)
	}
	if path != "" {
		t.Fatalf("expected empty path when env session id is set, got %q", path)
	}
	if _, err := os.Stat(sessFile); err == nil {
		t.Fatalf("expected session file not to be created when env session id is set")
	}
}

func TestResolveSessionID_UsesSessionFile(t *testing.T) {
	dir := t.TempDir()
	sessFile := filepath.Join(dir, "sid.txt")
	env := map[string]string{
		"AGENTSH_SESSION_FILE": sessFile,
	}

	id1, path1, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:   envGet(env),
		WorkDir:  dir,
		BaseDirs: []string{filepath.Join(dir, "run")},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID failed: %v", err)
	}
	if stringsTrim(id1) == "" {
		t.Fatalf("expected non-empty session id")
	}
	if path1 != sessFile {
		t.Fatalf("expected path %q, got %q", sessFile, path1)
	}
	b, err := os.ReadFile(sessFile)
	if err != nil {
		t.Fatalf("expected session file to exist: %v", err)
	}
	if stringsTrim(string(b)) != id1 {
		t.Fatalf("expected session file to contain %q, got %q", id1, stringsTrim(string(b)))
	}

	id2, path2, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:   envGet(env),
		WorkDir:  dir,
		BaseDirs: []string{filepath.Join(dir, "run")},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID (2) failed: %v", err)
	}
	if id2 != id1 || path2 != path1 {
		t.Fatalf("expected stable session id from file, got id=%q path=%q", id2, path2)
	}
}

func TestResolveSessionID_WorkspaceScope_UsesGitRoot(t *testing.T) {
	dir := t.TempDir()
	repoRoot := filepath.Join(dir, "repo")
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub1 := filepath.Join(repoRoot, "a", "b")
	sub2 := filepath.Join(repoRoot, "x", "y")
	if err := os.MkdirAll(sub1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub2, 0o755); err != nil {
		t.Fatal(err)
	}

	base := filepath.Join(dir, "run")
	env := map[string]string{
		"AGENTSH_SESSION_SCOPE": "workspace",
	}

	id1, path1, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:  envGet(env),
		WorkDir: sub1,
		BaseDirs: []string{
			base,
		},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID failed: %v", err)
	}
	if stringsTrim(id1) == "" {
		t.Fatalf("expected non-empty session id")
	}
	if stringsTrim(path1) == "" {
		t.Fatalf("expected non-empty path")
	}

	id2, path2, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:  envGet(env),
		WorkDir: sub2,
		BaseDirs: []string{
			base,
		},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID (2) failed: %v", err)
	}
	if id2 != id1 || path2 != path1 {
		t.Fatalf("expected same session for same repo root, got id=%q path=%q vs id=%q path=%q", id1, path1, id2, path2)
	}
}

func TestResolveSessionID_GlobalScope(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "run")
	env := map[string]string{
		"AGENTSH_SESSION_SCOPE": "global",
	}

	id1, path1, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:  envGet(env),
		WorkDir: filepath.Join(dir, "w1"),
		BaseDirs: []string{
			base,
		},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID failed: %v", err)
	}
	id2, path2, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:  envGet(env),
		WorkDir: filepath.Join(dir, "w2"),
		BaseDirs: []string{
			base,
		},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID (2) failed: %v", err)
	}
	if id2 != id1 || path2 != path1 {
		t.Fatalf("expected stable global session, got id=%q path=%q vs id=%q path=%q", id1, path1, id2, path2)
	}
}

func TestResolveSessionID_FallbacksToSessionDefaultWhenAllBaseDirsFail(t *testing.T) {
	dir := t.TempDir()
	// Create a file so MkdirAll(baseDir) fails with "not a directory".
	badBase := filepath.Join(dir, "notadir")
	if err := os.WriteFile(badBase, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"AGENTSH_SESSION_SCOPE": "global",
	}

	id, path, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:   envGet(env),
		WorkDir:  dir,
		BaseDirs: []string{badBase},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID failed: %v", err)
	}
	if id != "session-default" {
		t.Fatalf("expected session-default, got %q", id)
	}
	if path != "" {
		t.Fatalf("expected empty path, got %q", path)
	}
}
