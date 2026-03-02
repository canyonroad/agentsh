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

	// Outside workspace should pass through
	real, err := resolveWorkingDir(s, "/tmp")
	if err != nil {
		t.Fatalf("resolveWorkingDir: %v", err)
	}
	if real != "/tmp" {
		t.Errorf("real = %q, want /tmp", real)
	}
}

func TestResolveWorkingDir_Default_OutsideReject(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-default", ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	// Default /workspace mode: outside workspace paths should be rejected
	_, err = resolveWorkingDir(s, "/etc")
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

// Integration test: HTTP exec handler with real_paths=true allows outside-workspace working_dir.
func TestExec_RealPaths_OutsideWorkspace_Allowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("exec integration test is POSIX-specific")
	}
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

	// Execute /bin/pwd in an outside dir — should succeed in real_paths mode.
	// NOTE: Must use /bin/pwd (not "pwd") because "pwd" is a session builtin
	// that returns s.Cwd without going through resolveWorkingDir.
	outsideDir := t.TempDir() // use a real existing temp dir
	body, _ := json.Marshal(map[string]any{
		"command":        "/bin/pwd",
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
	if runtime.GOOS == "windows" {
		t.Skip("exec integration test is POSIX-specific")
	}
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

	body, _ := json.Marshal(map[string]any{
		"command":        "/bin/pwd",
		"working_dir":    "/tmp",
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
	if runtime.GOOS == "windows" {
		t.Skip("exec integration test is POSIX-specific")
	}
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

	// Execute /bin/pwd in a workspace subdirectory using the real path.
	// NOTE: Must use /bin/pwd (not "pwd") to bypass session builtin.
	wsClean := filepath.ToSlash(filepath.Clean(ws))
	body, _ := json.Marshal(map[string]any{
		"command":        "/bin/pwd",
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
