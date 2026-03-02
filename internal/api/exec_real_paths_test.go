package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

// pwdCommand returns a command and args that print the working directory,
// bypassing the session builtin. On Windows uses "cmd /c cd", on POSIX
// uses "/bin/pwd".
func pwdCommand() (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/c", "cd"}
	}
	return "/bin/pwd", nil
}

func TestResolveWorkingDir_RealPaths(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-real", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// Absolute path under workspace
	real, err := resolveWorkingDir(s, ws+"/subdir")
	if err != nil {
		t.Fatalf("resolveWorkingDir: %v", err)
	}
	if real == "" {
		t.Error("expected non-empty resolved path")
	}
}

func TestResolveWorkingDir_RealPaths_OutsideWorkspace(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-outside", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// Use a real outside-workspace path (platform-appropriate absolute path)
	outsideDir := t.TempDir()
	real, err := resolveWorkingDir(s, outsideDir)
	if err != nil {
		t.Fatalf("resolveWorkingDir: %v", err)
	}
	// resolveWorkingDir normalizes to forward slashes
	wantDir := filepath.ToSlash(outsideDir)
	if real != wantDir {
		t.Errorf("real = %q, want %q", real, wantDir)
	}
}

func TestResolveWorkingDir_Default_OutsideReject(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-default", ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	// Default /workspace mode: outside workspace paths should be rejected.
	// Use a real absolute path that's outside /workspace on all platforms.
	outsideDir := t.TempDir()
	_, err = resolveWorkingDir(s, outsideDir)
	if err == nil {
		t.Error("expected error for outside-workspace path in default mode")
	}
}

func TestResolveWorkingDir_RootVirtualRoot(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-rootvr", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate VirtualRoot=="/" — paths like "/etc" should be considered
	// in-root and resolved normally (not passed through as outside)
	s.VirtualRoot = "/"

	_, err = resolveWorkingDir(s, "/etc")
	if err != nil {
		t.Fatalf("resolveWorkingDir with VirtualRoot=/: %v", err)
	}
}

func TestResolveWorkingDir_EmptyVirtualRoot_FailsClosed(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-emptyvr", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate uninitialized/restored session with empty VirtualRoot
	s.VirtualRoot = ""

	// Should fail closed (treat as /workspace mode and reject outside paths)
	_, err = resolveWorkingDir(s, "/etc")
	if err == nil {
		t.Error("expected error for outside-workspace path when VirtualRoot is empty")
	}
}

func TestResolveWorkingDir_WindowsDriveLetter(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-windrive", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a Windows-style VirtualRoot with drive letter
	s.VirtualRoot = "C:/Users/project"

	// Drive-letter absolute path under VirtualRoot should be treated as absolute,
	// not joined to cwd. This tests that filepath.IsAbs handles drive letters.
	if runtime.GOOS == "windows" {
		real, err := resolveWorkingDir(s, "C:/Users/project/sub")
		if err != nil {
			t.Fatalf("resolveWorkingDir with Windows drive path: %v", err)
		}
		if real == "" {
			t.Error("expected non-empty resolved path for Windows drive letter")
		}
	} else {
		// On non-Windows, filepath.IsAbs("C:/...") returns false, so the path
		// gets joined to cwd. This is expected — Windows paths only need to work
		// on Windows. Verify it doesn't panic.
		_, _ = resolveWorkingDir(s, "C:/Users/project/sub")
	}
}

func TestResolveWorkingDir_SymlinkEscape_DefaultMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test is POSIX-specific")
	}
	m := session.NewManager(10)
	ws := t.TempDir()

	// Create a symlink inside workspace pointing outside
	outsideDir := t.TempDir()
	symlinkPath := filepath.Join(ws, "escape-link")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatal(err)
	}

	s, err := m.CreateWithID("test-symlink-default", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Default mode: VirtualRoot == "/workspace", workspace mount == ws
	// The symlink /workspace/escape-link -> outsideDir should be rejected
	_, err = resolveWorkingDir(s, "/workspace/escape-link")
	if err == nil {
		t.Error("expected error for symlink escape in default mode")
	}
	if err != nil && !strings.Contains(err.Error(), "symlink escapes") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveWorkingDir_SymlinkEscape_RealPathsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test is POSIX-specific")
	}
	m := session.NewManager(10)
	ws := t.TempDir()

	// Create a symlink inside workspace pointing outside
	outsideDir := t.TempDir()
	symlinkPath := filepath.Join(ws, "escape-link")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatal(err)
	}

	s, err := m.CreateWithID("test-symlink-real", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// In real-paths mode: VirtualRoot == ws path
	// A path like <ws>/escape-link is "under root" but resolves outside — should be rejected
	wsClean := filepath.ToSlash(filepath.Clean(ws))
	_, err = resolveWorkingDir(s, wsClean+"/escape-link")
	if err == nil {
		t.Error("expected error for symlink escape in real_paths mode")
	}
	if err != nil && !strings.Contains(err.Error(), "symlink escapes") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveWorkingDir_DotDotEscape_RealPaths(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-dotdot-real", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	wsClean := filepath.ToSlash(filepath.Clean(ws))
	// Path with ".." that resolves outside workspace should be treated as
	// outside-workspace (pass through), not rejected as escape.
	real, err := resolveWorkingDir(s, wsClean+"/../tmp")
	if err != nil {
		t.Fatalf("expected pass-through for dotdot outside workspace in real_paths mode, got: %v", err)
	}
	// After normalization, should resolve to the parent's "tmp" sibling
	if strings.Contains(real, "..") {
		t.Errorf("result should not contain '..': %q", real)
	}
}

func TestResolveWorkingDir_DotDotEscape_Default(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-dotdot-default", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Default mode: /workspace/./../etc should be rejected
	_, err = resolveWorkingDir(s, "/workspace/../etc")
	if err == nil {
		t.Error("expected error for dotdot escape outside /workspace in default mode")
	}
}
func TestExec_RealPaths_OutsideWorkspace_Allowed(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	sess.SetRealPaths(true)

	app := newTestApp(t, sessions, store)
	h := app.Router()

	// Execute a non-builtin pwd command in an outside dir — should succeed in real_paths mode.
	cmd, args := pwdCommand()
	outsideDir := t.TempDir() // use a real existing temp dir
	body, _ := json.Marshal(map[string]any{
		"command":        cmd,
		"args":           args,
		"working_dir":    outsideDir,
		"include_events": "none",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp types.ExecResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Result.ExitCode != 0 {
		t.Fatalf("expected exit_code 0, got %d (stderr=%q)", resp.Result.ExitCode, resp.Result.Stderr)
	}
	// pwd output should contain the outside dir path
	if !strings.Contains(resp.Result.Stdout, filepath.Base(outsideDir)) {
		t.Errorf("stdout=%q, expected to contain outside dir %q", resp.Result.Stdout, outsideDir)
	}
}

// Integration test: HTTP exec handler in default mode rejects outside-workspace working_dir.
func TestExec_Default_OutsideWorkspace_Rejected(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Default mode: VirtualRoot == "/workspace"

	app := newTestApp(t, sessions, store)
	h := app.Router()

	cmd, args := pwdCommand()
	outsideDir := t.TempDir()
	body, _ := json.Marshal(map[string]any{
		"command":        cmd,
		"args":           args,
		"working_dir":    outsideDir,
		"include_events": "none",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp types.ExecResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	// Should fail with non-zero exit code (working_dir rejection)
	if resp.Result.ExitCode == 0 {
		t.Error("expected non-zero exit code for outside-workspace working_dir in default mode")
	}
	if !strings.Contains(resp.Result.Stderr, "working_dir must be under /workspace") {
		t.Errorf("stderr=%q, expected working_dir rejection message", resp.Result.Stderr)
	}
}

// Integration test: HTTP exec handler with real_paths mode resolves in-workspace
// commands to real host paths.
func TestExec_RealPaths_InWorkspace_UsesRealPath(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	subdir := filepath.Join(ws, "sub")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	sess.SetRealPaths(true)

	app := newTestApp(t, sessions, store)
	h := app.Router()

	// Execute pwd in a workspace subdirectory using the real path.
	cmd, args := pwdCommand()
	wsClean := filepath.ToSlash(filepath.Clean(ws))
	body, _ := json.Marshal(map[string]any{
		"command":        cmd,
		"args":           args,
		"working_dir":    wsClean + "/sub",
		"include_events": "none",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp types.ExecResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Result.ExitCode != 0 {
		t.Fatalf("expected exit_code 0, got %d (stderr=%q)", resp.Result.ExitCode, resp.Result.Stderr)
	}
	// pwd output should show the real subdirectory path
	if !strings.Contains(resp.Result.Stdout, "sub") {
		t.Errorf("stdout=%q, expected to contain 'sub' subdirectory", resp.Result.Stdout)
	}
}
