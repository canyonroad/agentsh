package api

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func newTestAppForWrap(t *testing.T, cfg *config.Config) (*App, *session.Manager) {
	t.Helper()
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	app := NewApp(cfg, mgr, store, nil, broker, nil, nil, nil, nil, nil, nil)
	return app, mgr
}

func nonzeroTestUID() int {
	// UID 0 is the helper's fallback sentinel, so pick any nonzero UID for coverage.
	uid := os.Getuid()
	if uid == 0 {
		return 1
	}
	return uid
}

func TestSecureNotifyDir_ChownSuccess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secureNotifyDir is Linux-only")
	}

	dir := t.TempDir()
	if got := secureNotifyDir(dir, nonzeroTestUID()); !got {
		t.Fatal("expected chown success path")
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Fatalf("expected 0700 permissions, got %04o", got)
	}
}

func TestSecureNotifyDir_CallerUIDZero_Fallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secureNotifyDir is Linux-only")
	}

	dir := t.TempDir()
	if got := secureNotifyDir(dir, 0); got {
		t.Fatal("expected fallback path")
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0711 {
		t.Fatalf("expected 0711 permissions, got %04o", got)
	}
}

func TestSecureSocket_ChownOK(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secureSocket is Linux-only")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "socket.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if err := os.Chmod(sockPath, 0600); err != nil {
		t.Fatalf("chmod socket before helper: %v", err)
	}

	secureSocket(sockPath, nonzeroTestUID(), true)

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("expected socket mode to stay 0600, got %04o", got)
	}
}

func TestSecureSocket_Fallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secureSocket is Linux-only")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "socket.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if err := os.Chmod(sockPath, 0600); err != nil {
		t.Fatalf("chmod socket before helper: %v", err)
	}

	secureSocket(sockPath, os.Getuid(), false)

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := info.Mode().Perm(); got != 0666 {
		t.Fatalf("expected fallback socket mode 0666, got %04o", got)
	}
}

func TestGetConnPeerCreds(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("getConnPeerCreds is Linux-only")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "peercreds.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serverConnCh := make(chan *net.UnixConn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			serverErrCh <- err
			return
		}
		serverConnCh <- unixConn
	}()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	defer clientConn.Close()

	var serverConn *net.UnixConn
	select {
	case err := <-serverErrCh:
		t.Fatalf("accept unix socket: %v", err)
	case serverConn = <-serverConnCh:
	}
	defer serverConn.Close()

	creds := getConnPeerCreds(serverConn)
	if creds.PID <= 0 {
		t.Fatalf("expected peer PID > 0, got %d", creds.PID)
	}
	if creds.UID != uint32(os.Getuid()) {
		t.Fatalf("expected peer UID %d, got %d", os.Getuid(), creds.UID)
	}
}

func TestWrapInit_NotifyDirPermissions_Fallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)
	app.ptraceTracer = struct{}{}

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected status 200, got %d", code)
	}

	notifyDir := filepath.Dir(resp.NotifySocket)
	t.Cleanup(func() { _ = os.RemoveAll(notifyDir) })

	dirInfo, err := os.Stat(notifyDir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0711 {
		t.Fatalf("expected fallback notify dir mode 0711, got %04o", got)
	}

	socketInfo, err := os.Stat(resp.NotifySocket)
	if err != nil {
		t.Fatalf("stat notify socket: %v", err)
	}
	if got := socketInfo.Mode().Perm(); got != 0666 {
		t.Fatalf("expected fallback notify socket mode 0666, got %04o", got)
	}
}

func TestWrapInit_NotifyDirPermissions_CallerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    nonzeroTestUID(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected status 200, got %d", code)
	}

	notifyDir := filepath.Dir(resp.NotifySocket)
	t.Cleanup(func() { _ = os.RemoveAll(notifyDir) })

	dirInfo, err := os.Stat(notifyDir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0700 {
		t.Fatalf("expected caller-owned notify dir mode 0700, got %04o", got)
	}
}

func TestWrapInit_NotifyDirPermissions_ValidationFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	prevChmod := wrapChmod
	wrapChmod = func(string, os.FileMode) error { return nil }
	t.Cleanup(func() { wrapChmod = prevChmod })

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
		CallerUID:    0,
	})
	if err == nil {
		t.Fatal("expected error when notify permissions are not established")
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", code)
	}
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

func TestWrapInit_CallerUIDPassedThrough(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    1000,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected status 200, got %d", code)
	}
	if resp.NotifySocket == "" {
		t.Fatal("expected notify socket path to be set")
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

func newTestAppForWrapWithSignalPolicy(t *testing.T, cfg *config.Config) (*App, *session.Manager) {
	t.Helper()
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	// Create a policy with signal rules so SignalEngine() returns non-nil
	p := &policy.Policy{
		Version: 1,
		Name:    "test-signal",
		SignalRules: []policy.SignalRule{
			{
				Name:     "audit-all",
				Signals:  []string{"SIGKILL"},
				Target:   policy.SignalTargetSpec{Type: "external"},
				Decision: "audit",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("create policy engine: %v", err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil)
	return app, mgr
}

func TestWrapInit_SignalFilterEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrapWithSignalPolicy(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}

	// Verify signal_filter_enabled is true in the seccomp config
	var seccompCfg map[string]interface{}
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &seccompCfg); err != nil {
		t.Fatalf("failed to parse seccomp config: %v", err)
	}
	sigEnabled, ok := seccompCfg["signal_filter_enabled"]
	if !ok {
		t.Fatal("seccomp config missing signal_filter_enabled field")
	}
	if sigEnabled != true {
		t.Errorf("expected signal_filter_enabled=true, got %v", sigEnabled)
	}
}

func TestWrapInit_SignalSocketSet(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrapWithSignalPolicy(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}

	// SignalSocket should be set when policy has signal rules
	if resp.SignalSocket == "" {
		t.Error("expected SignalSocket to be set when signal engine is available")
	}
	// Signal socket should be in the same directory as notify socket
	if filepath.Dir(resp.SignalSocket) != filepath.Dir(resp.NotifySocket) {
		t.Errorf("expected signal and notify sockets in same directory: signal=%s notify=%s",
			resp.SignalSocket, resp.NotifySocket)
	}
	// Signal socket path should be under the limit
	if len(resp.SignalSocket) > 104 {
		t.Errorf("signal socket path %d bytes exceeds 104 byte limit: %s",
			len(resp.SignalSocket), resp.SignalSocket)
	}

	// AGENTSH_SIGNAL_SOCK_FD should be in wrapper env
	if fd, ok := resp.WrapperEnv["AGENTSH_SIGNAL_SOCK_FD"]; !ok {
		t.Error("expected AGENTSH_SIGNAL_SOCK_FD in wrapper env")
	} else if fd != "4" {
		t.Errorf("expected AGENTSH_SIGNAL_SOCK_FD=4, got %q", fd)
	}
}

func TestWrapInit_SignalSocketPermissions_CallerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrapWithSignalPolicy(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    nonzeroTestUID(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", code)
	}
	if resp.SignalSocket == "" {
		t.Fatal("expected signal socket to be created")
	}

	notifyDir := filepath.Dir(resp.NotifySocket)
	t.Cleanup(func() { _ = os.RemoveAll(notifyDir) })

	notifyInfo, err := os.Stat(resp.NotifySocket)
	if err != nil {
		t.Fatalf("stat notify socket: %v", err)
	}
	if got := notifyInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("expected caller-owned notify socket mode 0600, got %04o", got)
	}

	signalInfo, err := os.Stat(resp.SignalSocket)
	if err != nil {
		t.Fatalf("stat signal socket: %v", err)
	}
	if got := signalInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("expected caller-owned signal socket mode 0600, got %04o", got)
	}
	if filepath.Dir(resp.SignalSocket) != notifyDir {
		t.Fatalf("expected signal socket to share notify dir, got %s vs %s", filepath.Dir(resp.SignalSocket), notifyDir)
	}
}

func TestWrapInit_NoSignalSocketWithoutPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	// Use standard helper (no signal policy)
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}

	// SignalSocket should NOT be set without signal policy
	if resp.SignalSocket != "" {
		t.Errorf("expected empty SignalSocket without signal policy, got %q", resp.SignalSocket)
	}

	// AGENTSH_SIGNAL_SOCK_FD should NOT be in wrapper env
	if _, ok := resp.WrapperEnv["AGENTSH_SIGNAL_SOCK_FD"]; ok {
		t.Error("expected no AGENTSH_SIGNAL_SOCK_FD in wrapper env without signal policy")
	}

	// signal_filter_enabled should be false in seccomp config
	var seccompCfg map[string]interface{}
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &seccompCfg); err != nil {
		t.Fatalf("failed to parse seccomp config: %v", err)
	}
	sigEnabled, ok := seccompCfg["signal_filter_enabled"]
	if !ok {
		t.Fatal("seccomp config missing signal_filter_enabled field")
	}
	if sigEnabled != false {
		t.Errorf("expected signal_filter_enabled=false, got %v", sigEnabled)
	}
}

func TestWrapInit_LandlockNetwork_HonorsConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	cases := []struct {
		name     string
		connect  bool
		bind     bool
		wantNet  bool
		wantBind bool
	}{
		{"both_true", true, true, true, true},
		{"connect_true_bind_false", true, false, true, false},
		{"connect_true_bind_true", true, true, true, true},
		{"connect_false_bind_false", false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connect := tc.connect
			bind := tc.bind
			enabled := true
			cfg := &config.Config{}
			cfg.Sandbox.UnixSockets.Enabled = &enabled
			cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
			cfg.Sandbox.Seccomp.Execve.Enabled = true
			cfg.Sandbox.Seccomp.UnixSocket.Enabled = true
			cfg.Landlock.Enabled = true
			cfg.Landlock.Network.AllowConnectTCP = &connect
			cfg.Landlock.Network.AllowBindTCP = &bind

			app, mgr := newTestAppForWrap(t, cfg)
			s, err := mgr.Create(t.TempDir(), "default")
			if err != nil {
				t.Fatalf("create session: %v", err)
			}

			resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
				AgentCommand: "/bin/echo",
			})
			if err != nil {
				t.Fatalf("wrapInitCore: %v", err)
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
				t.Fatalf("unmarshal SeccompConfig: %v\n%s", err, resp.SeccompConfig)
			}

			gotNet, _ := parsed["allow_network"].(bool)
			gotBind, _ := parsed["allow_bind"].(bool)
			if gotNet != tc.wantNet {
				t.Errorf("allow_network = %v; want %v (JSON: %s)", gotNet, tc.wantNet, resp.SeccompConfig)
			}
			if gotBind != tc.wantBind {
				t.Errorf("allow_bind = %v; want %v (JSON: %s)", gotBind, tc.wantBind, resp.SeccompConfig)
			}
		})
	}
}

func TestWrapInit_LandlockNetwork_BackCompatDefaults(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	// Minimal YAML: Landlock enabled, no network block.
	// Exercises the back-compat promise: omitting landlock.network.* must
	// yield allow_network=true (proxy-compatible) and allow_bind=false
	// (new security default, replacing prior accidental permissive behavior).
	yamlData := []byte(`
landlock:
  enabled: true
sandbox:
  unix_sockets:
    enabled: true
    wrapper_bin: /bin/true
  seccomp:
    execve:
      enabled: true
    unix_socket:
      enabled: true
`)
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmpFile, yamlData, 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := config.Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	// Sanity: applyDefaults ran via config.Load.
	if cfg.Landlock.Network.AllowConnectTCP == nil {
		t.Fatal("applyDefaults should have filled AllowConnectTCP")
	}
	if cfg.Landlock.Network.AllowBindTCP == nil {
		t.Fatal("applyDefaults should have filled AllowBindTCP")
	}

	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("wrapInitCore: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	gotNet, _ := parsed["allow_network"].(bool)
	gotBind, _ := parsed["allow_bind"].(bool)
	if !gotNet {
		t.Error("back-compat: allow_network should default to true (proxy needs it)")
	}
	if gotBind {
		t.Error("back-compat: allow_bind should default to false (security hardening vs prior accidental permissive)")
	}
}
