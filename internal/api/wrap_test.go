package api

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func newTestAppForWrap(t *testing.T, cfg *config.Config) (*App, *session.Manager) {
	t.Helper()
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	app := NewApp(cfg, mgr, store, nil, broker, nil, nil, nil, nil, nil)
	return app, mgr
}

func TestWrapInit_SessionNotFound(t *testing.T) {
	cfg := &config.Config{}
	app, _ := newTestAppForWrap(t, cfg)

	_, ok := app.sessions.Get("nonexistent")
	if ok {
		t.Fatal("expected session not found")
	}
}

func TestWrapInit_NotLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this test only runs on non-Linux platforms")
	}
	if runtime.GOOS == "windows" {
		t.Skip("wrap is supported on Windows via driver")
	}

	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)

	// Create a session
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err == nil {
		t.Fatal("expected error on non-Linux")
	}
	if code != 400 {
		t.Errorf("expected status 400, got %d", code)
	}
}

func TestWrapInit_WrapperNotFound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	cfg := &config.Config{}
	// Set a wrapper binary that doesn't exist
	cfg.Sandbox.UnixSockets.WrapperBin = "nonexistent-wrapper-binary-xyz-12345"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err == nil {
		t.Fatal("expected error when wrapper not found")
	}
	if code != 503 {
		t.Errorf("expected status 503, got %d", code)
	}
}

func TestWrapInit_Success(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	// Use /bin/true as a stand-in for the wrapper binary
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}

	// Verify response fields
	if resp.WrapperBinary != "/bin/true" {
		t.Errorf("expected wrapper binary /bin/true, got %q", resp.WrapperBinary)
	}
	if resp.NotifySocket == "" {
		t.Error("expected notify socket path to be set")
	}
	if resp.SeccompConfig == "" {
		t.Error("expected seccomp config to be set")
	}
	if resp.WrapperEnv == nil {
		t.Error("expected wrapper env to be set")
	}
	if _, ok := resp.WrapperEnv["AGENTSH_SECCOMP_CONFIG"]; !ok {
		t.Error("expected AGENTSH_SECCOMP_CONFIG in wrapper env")
	}
}

func TestWrapInit_SeccompConfigContent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.Execve.Enabled = true
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = true
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The seccomp config should contain the expected fields
	cfg_str := resp.SeccompConfig
	if cfg_str == "" {
		t.Fatal("expected non-empty seccomp config")
	}
	// Verify it contains expected JSON fields
	if !contains(cfg_str, "unix_socket_enabled") {
		t.Error("seccomp config should contain unix_socket_enabled")
	}
	if !contains(cfg_str, "execve_enabled") {
		t.Error("seccomp config should contain execve_enabled")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestWrapInit_LongTMPDIR_LongSessionID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	// Use a TMPDIR that simulates macOS /var/folders nesting (~40 chars)
	// while still leaving enough room for the socket path.
	// Budget: 104 - len(TMPDIR) - ~25 (agentsh-wrap-*) - 13 (fixed parts)
	longDir := filepath.Join(t.TempDir(), "deep")
	if err := os.MkdirAll(longDir, 0700); err != nil {
		t.Fatalf("create tmpdir: %v", err)
	}
	t.Setenv("TMPDIR", longDir)

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	// Use a 128-char session ID to exercise the hashing/truncation path
	longSessionID := strings.Repeat("x", 128)
	s, err := mgr.CreateWithID(longSessionID, t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, longSessionID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}
	if resp.NotifySocket == "" {
		t.Error("expected notify socket path to be set")
	}
	// Verify socket path is under the limit
	if len(resp.NotifySocket) > 104 {
		t.Errorf("socket path %d bytes exceeds 104 byte limit: %s", len(resp.NotifySocket), resp.NotifySocket)
	}
}

func TestWrapInit_BudgetExhausted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	// Create a TMPDIR so long that the socket path budget is exhausted (< 1).
	// Socket path limit is 104; fixed parts take ~13 bytes; the temp dir
	// (including "agentsh-wrap-*") must consume the rest.
	base := t.TempDir()
	longDir := filepath.Join(base, strings.Repeat("d", 120))
	if err := os.MkdirAll(longDir, 0700); err != nil {
		t.Fatalf("create tmpdir: %v", err)
	}
	t.Setenv("TMPDIR", longDir)

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err == nil {
		t.Fatal("expected error when TMPDIR is too long")
	}
	if code != 500 {
		t.Errorf("expected status 500, got %d", code)
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected 'too long' in error, got: %v", err)
	}
}
