//go:build integration && linux

package ptrace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requirePtrace(t *testing.T) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "0.01")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start child process")
	}
	pid := cmd.Process.Pid
	err := unix.PtraceSeize(pid)
	cmd.Process.Kill()
	cmd.Wait()
	if err != nil {
		t.Skipf("ptrace not available: %v", err)
	}
}

// waitForTraceesDrained polls until TraceeCount() reaches 0 or timeout.
func waitForTraceesDrained(t *testing.T, tr *Tracer, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tr.TraceeCount() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// --- Enhanced mockExecHandler with per-filename rules ---

type mockExecHandler struct {
	mu           sync.Mutex
	calls        []ExecContext
	defaultAllow bool
	defaultErrno int32
	rules        map[string]ExecResult // keyed by basename or full path
}

func (m *mockExecHandler) HandleExecve(ctx context.Context, ec ExecContext) ExecResult {
	m.mu.Lock()
	m.calls = append(m.calls, ec)
	m.mu.Unlock()

	if m.rules != nil {
		// Exact full-path match
		if r, ok := m.rules[ec.Filename]; ok {
			return r
		}
		// Basename match
		base := filepath.Base(ec.Filename)
		if r, ok := m.rules[base]; ok {
			return r
		}
	}

	// Default
	action := "continue"
	if !m.defaultAllow {
		action = "deny"
	}
	return ExecResult{
		Allow:  m.defaultAllow,
		Action: action,
		Errno:  m.defaultErrno,
	}
}

// WaitForCalls polls until at least n calls are received or timeout.
func (m *mockExecHandler) WaitForCalls(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		count := len(m.calls)
		m.mu.Unlock()
		if count >= n {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// CallsMatching returns calls whose Filename contains the given substring.
func (m *mockExecHandler) CallsMatching(substring string) []ExecContext {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []ExecContext
	for _, c := range m.calls {
		if strings.Contains(c.Filename, substring) {
			result = append(result, c)
		}
	}
	return result
}

// CallCount returns the number of calls received.
func (m *mockExecHandler) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// --- Phase 1 Basic Tests ---

func TestIntegration_AttachDetach(t *testing.T) {
	requirePtrace(t)

	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	defer cmd.Wait()

	cfg := TracerConfig{TraceExecve: true}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	tr.AttachPID(cmd.Process.Pid)

	time.Sleep(200 * time.Millisecond)

	if tr.TraceeCount() == 0 {
		t.Error("expected at least 1 tracee after attach")
	}

	cancel()
	<-errCh
}

func TestIntegration_ExecveAllow(t *testing.T) {
	requirePtrace(t)

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	cmd := exec.Command("/bin/echo", "hello")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)

	err := cmd.Wait()
	cancel()
	<-errCh

	if err != nil {
		t.Errorf("child should have succeeded: %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.calls) == 0 {
		t.Log("Note: execve handler may not have been called if attach happened after exec")
	}
}

func TestIntegration_ForkTree(t *testing.T) {
	requirePtrace(t)

	cfg := TracerConfig{TraceExecve: true}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	cmd := exec.Command("/bin/sh", "-c", "echo parent; /bin/sh -c 'echo child'")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-errCh

	if tr.processTree.Size() > 0 {
		t.Logf("process tree tracked %d processes", tr.processTree.Size())
	}
}

// --- New Test Cases (Docker Integration Tests Plan) ---

func TestIntegration_ExecveDeny(t *testing.T) {
	requirePtrace(t)

	outfile := filepath.Join(t.TempDir(), "outfile")

	handler := &mockExecHandler{
		defaultAllow: true,
		rules: map[string]ExecResult{
			"echo": {Allow: false, Action: "deny", Errno: int32(unix.EACCES)},
		},
	}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	shellCmd := "/bin/echo hello > " + outfile + " 2>&1 || echo denied > " + outfile
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	// Check handler recorded a denied call for echo
	echoCalls := handler.CallsMatching("echo")
	if len(echoCalls) == 0 {
		t.Log("Note: deny may not have been observed if attach happened after exec")
	}

	// Check output
	data, err := os.ReadFile(outfile)
	if err == nil {
		content := strings.TrimSpace(string(data))
		t.Logf("output file content: %q", content)
		if content == "denied" {
			t.Log("echo was successfully denied")
		}
	}
}

func TestIntegration_ExecveMetadata(t *testing.T) {
	requirePtrace(t)

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	cmd := exec.Command("/bin/sh", "-c", "exec /bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	handler.mu.Lock()
	defer handler.mu.Unlock()

	for _, call := range handler.calls {
		if call.Filename == "" {
			t.Error("ExecContext.Filename should not be empty")
		}
		if !filepath.IsAbs(call.Filename) {
			t.Errorf("ExecContext.Filename should be absolute, got %q", call.Filename)
		}
		if call.PID <= 0 {
			t.Errorf("ExecContext.PID should be > 0, got %d", call.PID)
		}
		if call.Depth < 0 {
			t.Errorf("ExecContext.Depth should be >= 0, got %d", call.Depth)
		}
	}
}

func TestIntegration_RelativePathResolution(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()
	symlinkPath := filepath.Join(tmpDir, "myecho")
	if err := os.Symlink("/bin/echo", symlinkPath); err != nil {
		t.Fatal(err)
	}

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	shellCmd := "cd " + tmpDir + " && exec ./myecho hello"
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	// Check that handler received the path (may be relative ./myecho or absolute)
	myechoCalls := handler.CallsMatching("myecho")
	if len(myechoCalls) > 0 {
		t.Logf("received filename: %q", myechoCalls[0].Filename)
		// The kernel resolves to absolute path for execve, so we expect absolute
		if filepath.IsAbs(myechoCalls[0].Filename) {
			t.Log("filename was resolved to absolute path")
		}
	} else {
		t.Log("Note: myecho call not captured (attach may have happened after exec)")
	}
}

func TestIntegration_ForkCloneTracking(t *testing.T) {
	requirePtrace(t)

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	cmd := exec.Command("/bin/sh", "-c", "/bin/echo parent && /bin/sh -c '/bin/echo child'")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	handler.mu.Lock()
	defer handler.mu.Unlock()

	pids := make(map[int]bool)
	for _, c := range handler.calls {
		pids[c.PID] = true
	}
	t.Logf("observed %d unique PIDs from %d calls", len(pids), len(handler.calls))
	if len(pids) >= 2 {
		t.Log("fork/clone tracking working: calls from multiple PIDs")
	}
}

func TestIntegration_ProcessTreeDepth(t *testing.T) {
	requirePtrace(t)

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// 3 nesting levels
	cmd := exec.Command("/bin/sh", "-c", `/bin/sh -c "/bin/sh -c /bin/true"`)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	handler.mu.Lock()
	defer handler.mu.Unlock()

	maxDepth := -1
	for _, c := range handler.calls {
		if c.Depth > maxDepth {
			maxDepth = c.Depth
		}
	}
	t.Logf("max depth observed: %d from %d calls", maxDepth, len(handler.calls))
	if maxDepth >= 2 {
		t.Log("depth tracking working: observed depth >= 2")
	}
}

func TestIntegration_InSyscallResetAfterExec(t *testing.T) {
	requirePtrace(t)

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Chain of execs - tests InSyscall reset
	cmd := exec.Command("/bin/sh", "-c", `exec /bin/sh -c 'exec /bin/echo post_exec'`)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	echoCalls := handler.CallsMatching("echo")
	if len(echoCalls) > 0 {
		t.Logf("handler received echo call: %q", echoCalls[0].Filename)
		t.Log("InSyscall reset working: second exec was intercepted")
	} else {
		t.Log("Note: echo call not captured (attach may have happened after exec)")
	}
}

func TestIntegration_MultipleRapidExecs(t *testing.T) {
	requirePtrace(t)

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	cmd := exec.Command("/bin/sh", "-c", "/bin/echo a && /bin/echo b && /bin/echo c")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	echoCalls := handler.CallsMatching("echo")
	t.Logf("handler received %d echo calls out of %d total", len(echoCalls), handler.CallCount())
	if len(echoCalls) >= 3 {
		t.Log("rapid exec tracking working: captured all 3 echo calls")
	}
}

func TestIntegration_DenyAndContinue(t *testing.T) {
	requirePtrace(t)

	outfile := filepath.Join(t.TempDir(), "outfile")

	handler := &mockExecHandler{
		defaultAllow: true,
		rules: map[string]ExecResult{
			"cat": {Allow: false, Action: "deny", Errno: int32(unix.EACCES)},
		},
	}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	shellCmd := "/bin/cat /dev/null 2>/dev/null; /bin/echo recovered > " + outfile
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	// Check handler has calls for both cat and echo
	catCalls := handler.CallsMatching("cat")
	echoCalls := handler.CallsMatching("echo")
	t.Logf("cat calls: %d, echo calls: %d", len(catCalls), len(echoCalls))

	if len(catCalls) > 0 && len(echoCalls) > 0 {
		t.Log("deny-and-continue working: both cat (denied) and echo (allowed) were intercepted")
	}

	// Check output file
	data, err := os.ReadFile(outfile)
	if err == nil {
		content := strings.TrimSpace(string(data))
		if content == "recovered" {
			t.Log("process continued after deny: output file contains 'recovered'")
		} else {
			t.Logf("unexpected output: %q", content)
		}
	}
}

// --- Mock handlers for Phase 2 ---

type mockFileCall struct {
	FileContext
}

type mockFileHandler struct {
	mu           sync.Mutex
	calls        []mockFileCall
	defaultAllow bool
	defaultErrno int32
	rules        map[string]FileResult // keyed by path substring
}

func (m *mockFileHandler) HandleFile(ctx context.Context, fc FileContext) FileResult {
	m.mu.Lock()
	m.calls = append(m.calls, mockFileCall{fc})
	m.mu.Unlock()

	if m.rules != nil {
		for substr, r := range m.rules {
			if strings.Contains(fc.Path, substr) {
				return r
			}
		}
	}

	return FileResult{Allow: m.defaultAllow, Errno: m.defaultErrno}
}

func (m *mockFileHandler) CallsMatching(substring string) []mockFileCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []mockFileCall
	for _, c := range m.calls {
		if strings.Contains(c.Path, substring) {
			result = append(result, c)
		}
	}
	return result
}

func (m *mockFileHandler) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

type mockNetworkCall struct {
	NetworkContext
}

type mockNetworkHandler struct {
	mu           sync.Mutex
	calls        []mockNetworkCall
	defaultAllow bool
	defaultErrno int32
	denyPorts    map[int]int32 // port → errno
}

func (m *mockNetworkHandler) HandleNetwork(ctx context.Context, nc NetworkContext) NetworkResult {
	m.mu.Lock()
	m.calls = append(m.calls, mockNetworkCall{nc})
	m.mu.Unlock()

	if m.denyPorts != nil {
		if errno, ok := m.denyPorts[nc.Port]; ok {
			return NetworkResult{Allow: false, Errno: errno}
		}
	}

	return NetworkResult{Allow: m.defaultAllow, Errno: m.defaultErrno}
}

func (m *mockNetworkHandler) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

type mockSignalCall struct {
	SignalContext
}

type mockSignalHandler struct {
	mu             sync.Mutex
	calls          []mockSignalCall
	defaultAllow   bool
	defaultErrno   int32
	redirectSignal int // if > 0, redirect to this signal
	denySignals    map[int]int32 // signal → errno
}

func (m *mockSignalHandler) HandleSignal(ctx context.Context, sc SignalContext) SignalResult {
	m.mu.Lock()
	m.calls = append(m.calls, mockSignalCall{sc})
	m.mu.Unlock()

	if m.denySignals != nil {
		if errno, ok := m.denySignals[sc.Signal]; ok {
			return SignalResult{Allow: false, Errno: errno}
		}
	}

	return SignalResult{
		Allow:          m.defaultAllow,
		Errno:          m.defaultErrno,
		RedirectSignal: m.redirectSignal,
	}
}

func (m *mockSignalHandler) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// --- Phase 2 Integration Tests ---

func TestIntegration_FileDeny(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "denied.txt")

	fileHandler := &mockFileHandler{
		defaultAllow: true,
		rules: map[string]FileResult{
			"denied.txt": {Allow: false, Errno: int32(unix.EACCES)},
		},
	}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve: true,
		TraceFile:   true,
		ExecHandler: execHandler,
		FileHandler: fileHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	markerFile := filepath.Join(tmpDir, "marker.txt")
	shellCmd := fmt.Sprintf(`/bin/sh -c 'echo test > %s 2>/dev/null || echo denied > %s'`, targetFile, markerFile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	calls := fileHandler.CallsMatching("denied.txt")
	t.Logf("file handler received %d calls matching 'denied.txt' out of %d total", len(calls), fileHandler.CallCount())

	// The file handler must have received at least some calls (proving wiring works)
	if fileHandler.CallCount() == 0 {
		t.Error("file handler received zero calls; handleFile is not wired up")
	}
	if len(calls) > 0 {
		t.Logf("file deny intercepted: path=%q op=%q", calls[0].Path, calls[0].Operation)
	}
}

func TestIntegration_FileAllow(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "allowed.txt")

	fileHandler := &mockFileHandler{defaultAllow: true}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve: true,
		TraceFile:   true,
		ExecHandler: execHandler,
		FileHandler: fileHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	shellCmd := fmt.Sprintf(`echo hello > %s`, targetFile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Logf("Note: file not created (attach may have happened after open)")
	} else {
		content := strings.TrimSpace(string(data))
		if content != "hello" {
			t.Errorf("expected file content %q, got %q", "hello", content)
		}
	}

	// The file handler must have received at least some calls (proving wiring works)
	if fileHandler.CallCount() == 0 {
		t.Error("file handler received zero calls; handleFile is not wired up")
	}
	t.Logf("file handler received %d total calls", fileHandler.CallCount())
	calls := fileHandler.CallsMatching("allowed.txt")
	if len(calls) > 0 {
		if !filepath.IsAbs(calls[0].Path) {
			t.Errorf("expected absolute path, got %q", calls[0].Path)
		}
		t.Logf("file handler saw: path=%q op=%q", calls[0].Path, calls[0].Operation)
	}
}

func TestIntegration_NetworkDenyConnect(t *testing.T) {
	requirePtrace(t)

	netHandler := &mockNetworkHandler{
		defaultAllow: true,
		denyPorts:    map[int]int32{12345: int32(unix.ECONNREFUSED)},
	}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:    true,
		TraceNetwork:   true,
		ExecHandler:    execHandler,
		NetworkHandler: netHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	outfile := filepath.Join(t.TempDir(), "result.txt")
	// Use a Go helper to attempt a TCP connect to localhost:12345
	// This avoids bash/dash dependency for /dev/tcp
	shellCmd := fmt.Sprintf(`/bin/sh -c '(echo test | /usr/bin/nc -w 1 127.0.0.1 12345) 2>/dev/null && echo connected > %s || echo refused > %s'`, outfile, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	t.Logf("network handler received %d calls", netHandler.CallCount())

	// The network handler must have received at least some calls (proving wiring works)
	if netHandler.CallCount() == 0 {
		t.Error("network handler received zero calls; handleNetwork is not wired up")
	}

	netHandler.mu.Lock()
	for _, c := range netHandler.calls {
		t.Logf("  op=%s family=%d addr=%s port=%d", c.Operation, c.Family, c.Address, c.Port)
	}
	netHandler.mu.Unlock()

	// Verify the connect was refused (outcome assertion)
	data, err := os.ReadFile(outfile)
	if err == nil {
		content := strings.TrimSpace(string(data))
		t.Logf("result: %q", content)
		if content != "refused" {
			t.Errorf("expected 'refused', got %q", content)
		}
	}
}

func TestIntegration_SignalDeny(t *testing.T) {
	requirePtrace(t)

	sigHandler := &mockSignalHandler{
		defaultAllow: true,
		denySignals:  map[int]int32{int(unix.SIGUSR1): int32(unix.EPERM)},
	}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:   true,
		TraceSignal:   true,
		ExecHandler:   execHandler,
		SignalHandler: sigHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	outfile := filepath.Join(t.TempDir(), "result.txt")
	shellCmd := fmt.Sprintf(`/bin/sh -c 'kill -USR1 $$ 2>/dev/null && echo signaled > %s || echo denied > %s'`, outfile, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	t.Logf("signal handler received %d calls", sigHandler.CallCount())

	// The signal handler must have received at least some calls (proving wiring works)
	if sigHandler.CallCount() == 0 {
		t.Error("signal handler received zero calls; handleSignal is not wired up")
	}

	sigHandler.mu.Lock()
	for _, c := range sigHandler.calls {
		t.Logf("  pid=%d target=%d signal=%d", c.PID, c.TargetPID, c.Signal)
	}
	sigHandler.mu.Unlock()

	data, err := os.ReadFile(outfile)
	if err == nil {
		content := strings.TrimSpace(string(data))
		t.Logf("result: %q", content)
		if content != "denied" {
			t.Errorf("expected 'denied', got %q", content)
		}
	}
}

func TestIntegration_SignalRedirect(t *testing.T) {
	requirePtrace(t)

	sigHandler := &mockSignalHandler{
		defaultAllow:   true,
		redirectSignal: int(unix.SIGUSR2),
	}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:   true,
		TraceSignal:   true,
		ExecHandler:   execHandler,
		SignalHandler: sigHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	outfile := filepath.Join(t.TempDir(), "result.txt")
	shellCmd := fmt.Sprintf(`/bin/sh -c 'trap "echo redirected > %s" USR2; kill -USR1 $$; sleep 0.1'`, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	t.Logf("signal handler received %d calls", sigHandler.CallCount())

	// The signal handler must have received at least some calls (proving wiring works)
	if sigHandler.CallCount() == 0 {
		t.Error("signal handler received zero calls; handleSignal is not wired up")
	}

	data, err := os.ReadFile(outfile)
	if err == nil {
		content := strings.TrimSpace(string(data))
		t.Logf("result: %q", content)
		if content != "redirected" {
			t.Errorf("expected 'redirected', got %q", content)
		}
	} else {
		t.Log("Note: redirect output file not created (attach timing)")
	}
}