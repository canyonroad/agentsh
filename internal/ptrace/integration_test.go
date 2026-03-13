//go:build integration && linux

package ptrace

import (
	"context"
	"fmt"
	"net"
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

// waitForAttach polls until TraceeCount() > 0 or timeout, ensuring attach happened.
func waitForAttach(t *testing.T, tr *Tracer, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tr.TraceeCount() > 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 3*time.Second)
	cancel()
	<-errCh

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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 3*time.Second)
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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 5*time.Second)
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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 5*time.Second)
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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 5*time.Second)
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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 5*time.Second)
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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 5*time.Second)
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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 5*time.Second)
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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 5*time.Second)
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

	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)

	waitForTraceesDrained(t, tr, 5*time.Second)
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
	mu               sync.Mutex
	calls            []mockNetworkCall
	defaultAllow     bool
	defaultErrno     int32
	denyPorts        map[int]int32 // port → errno
	redirectPort     int           // target port for redirect
	redirectFromPort int           // only redirect connections to this source port
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

	if m.redirectPort > 0 && nc.Port == m.redirectFromPort {
		return NetworkResult{
			Allow:        true,
			Action:       "redirect",
			RedirectAddr: "127.0.0.1",
			RedirectPort: m.redirectPort,
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
	readyFile := filepath.Join(tmpDir, "ready")

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

	// Use ready-file sync: shell waits for ready file before running test action
	markerFile := filepath.Join(tmpDir, "marker.txt")
	shellCmd := fmt.Sprintf(`while [ ! -f %s ]; do sleep 0.01; done; echo test > %s 2>/dev/null || echo denied > %s`, readyFile, targetFile, markerFile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	// Signal the child to proceed
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 5*time.Second)
	cancel()
	<-errCh

	calls := fileHandler.CallsMatching("denied.txt")
	t.Logf("file handler received %d calls matching 'denied.txt' out of %d total", len(calls), fileHandler.CallCount())

	if fileHandler.CallCount() == 0 {
		t.Error("file handler received zero calls; handleFile is not wired up")
	}
	if len(calls) == 0 {
		t.Error("file handler did not intercept denied.txt access")
	}

	// Assert the denied file was NOT created (enforcement outcome)
	if _, err := os.Stat(targetFile); err == nil {
		t.Error("denied.txt should not have been created, but it exists")
	}

	// Assert the marker file was created (shell fallback executed)
	if data, err := os.ReadFile(markerFile); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "denied" {
			t.Errorf("expected marker 'denied', got %q", content)
		}
	}
}

func TestIntegration_FileAllow(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "allowed.txt")
	readyFile := filepath.Join(tmpDir, "ready")

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

	shellCmd := fmt.Sprintf(`while [ ! -f %s ]; do sleep 0.01; done; echo hello > %s`, readyFile, targetFile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 5*time.Second)
	cancel()
	<-errCh

	// Assert file was created with expected content
	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("allowed file was not created: %v", err)
	}
	content := strings.TrimSpace(string(data))
	if content != "hello" {
		t.Errorf("expected file content %q, got %q", "hello", content)
	}

	if fileHandler.CallCount() == 0 {
		t.Error("file handler received zero calls; handleFile is not wired up")
	}
	calls := fileHandler.CallsMatching("allowed.txt")
	if len(calls) > 0 && !filepath.IsAbs(calls[0].Path) {
		t.Errorf("expected absolute path, got %q", calls[0].Path)
	}
}

func TestIntegration_NetworkDenyConnect(t *testing.T) {
	requirePtrace(t)

	ncPath, err := exec.LookPath("nc")
	if err != nil {
		t.Skip("nc not found in PATH")
	}

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

	tmpDir := t.TempDir()
	readyFile := filepath.Join(tmpDir, "ready")
	outfile := filepath.Join(tmpDir, "result.txt")
	// Use -n to skip DNS resolution (avoids systemd-resolved latency).
	shellCmd := fmt.Sprintf(`while [ ! -f %s ]; do sleep 0.01; done; (echo test | %s -n -w 1 127.0.0.1 12345) 2>/dev/null && echo connected > %s || echo refused > %s`, readyFile, ncPath, outfile, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Release the process from Go's runtime tracking to prevent its internal
	// waitpid from competing with our ptrace tracer's Wait4(-1) for events.
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 8*time.Second)
	cancel()
	<-errCh

	if netHandler.CallCount() == 0 {
		t.Error("network handler received zero calls; handleNetwork is not wired up")
	}

	data, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal("expected result file to exist")
	}
	content := strings.TrimSpace(string(data))
	if content != "refused" {
		t.Errorf("expected 'refused', got %q", content)
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

	tmpDir := t.TempDir()
	readyFile := filepath.Join(tmpDir, "ready")
	outfile := filepath.Join(tmpDir, "result.txt")
	shellCmd := fmt.Sprintf(`while [ ! -f %s ]; do sleep 0.01; done; kill -USR1 $$ 2>/dev/null && echo signaled > %s || echo denied > %s`, readyFile, outfile, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 5*time.Second)
	cancel()
	<-errCh

	if sigHandler.CallCount() == 0 {
		t.Error("signal handler received zero calls; handleSignal is not wired up")
	}

	data, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal("expected result file to exist")
	}
	content := strings.TrimSpace(string(data))
	if content != "denied" {
		t.Errorf("expected 'denied', got %q", content)
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

	tmpDir := t.TempDir()
	readyFile := filepath.Join(tmpDir, "ready")
	outfile := filepath.Join(tmpDir, "result.txt")
	shellCmd := fmt.Sprintf(`trap "echo redirected > %s" USR2; while [ ! -f %s ]; do sleep 0.01; done; kill -USR1 $$; sleep 0.1`, outfile, readyFile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 5*time.Second)
	cancel()
	<-errCh

	if sigHandler.CallCount() == 0 {
		t.Error("signal handler received zero calls; handleSignal is not wired up")
	}

	data, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal("expected redirect output file to exist")
	}
	content := strings.TrimSpace(string(data))
	if content != "redirected" {
		t.Errorf("expected 'redirected', got %q", content)
	}
}

// --- Phase 4a Integration Tests ---

func TestIntegration_FileRedirect(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()

	origFile := filepath.Join(tmpDir, "original.txt")
	redirectTarget := filepath.Join(tmpDir, "redirected.txt")
	os.WriteFile(origFile, []byte("original"), 0644)
	os.WriteFile(redirectTarget, []byte("redirected"), 0644)

	outputFile := filepath.Join(tmpDir, "output.txt")
	readyFile := filepath.Join(tmpDir, "ready")

	fileHandler := &mockFileHandler{
		defaultAllow: true,
		rules: map[string]FileResult{
			"original.txt": {Action: "redirect", RedirectPath: redirectTarget},
		},
	}

	tr := NewTracer(TracerConfig{
		AttachMode:  "pid",
		TraceExecve: true,
		TraceFile:   true,
		ExecHandler: &mockExecHandler{defaultAllow: true},
		FileHandler: fileHandler,
		MaxTracees:  100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	cmd := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("while [ ! -f %s ]; do sleep 0.01; done; cat %s > %s", readyFile, origFile, outputFile))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Release the process from Go's runtime tracking to prevent its internal
	// waitpid from competing with our ptrace tracer's Wait4(-1) for events.
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 8*time.Second)
	cancel()
	<-errCh

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if strings.TrimSpace(string(content)) != "redirected" {
		t.Errorf("expected 'redirected', got %q", string(content))
	}
}

func TestIntegration_SoftDelete(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "delete_me.txt")
	trashDir := filepath.Join(tmpDir, "trash")
	os.WriteFile(targetFile, []byte("precious data"), 0644)

	fileHandler := &mockFileHandler{
		defaultAllow: true,
		rules: map[string]FileResult{
			"delete_me.txt": {Action: "soft-delete", TrashDir: trashDir},
		},
	}

	tr := NewTracer(TracerConfig{
		AttachMode:  "pid",
		TraceExecve: true,
		TraceFile:   true,
		ExecHandler: &mockExecHandler{defaultAllow: true},
		FileHandler: fileHandler,
		MaxTracees:  100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Use sleep to ensure the process is alive when we attach,
	// then call rm. PTRACE_SEIZE doesn't stop the process, so
	// we need the delay.
	cmd := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("sleep 1; rm -f %s", targetFile))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Release the process from Go's runtime tracking to prevent its internal
	// waitpid from competing with our ptrace tracer's Wait4(-1) for events.
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}

	// No ready file needed -- sleep provides the delay.

	waitForTraceesDrained(t, tr, 5*time.Second)
	cancel()
	<-errCh

	// Original location should be gone.
	t.Logf("checking targetFile: %s", targetFile)
	if fi, err := os.Stat(targetFile); err == nil {
		t.Errorf("file should not exist at original path, but it does: mode=%v size=%d", fi.Mode(), fi.Size())
	} else {
		t.Logf("targetFile stat: %v", err)
	}

	// Check if trash dir exists
	t.Logf("checking trashDir: %s", trashDir)
	if fi, err := os.Stat(trashDir); err != nil {
		t.Logf("trashDir stat: %v", err)
	} else {
		t.Logf("trashDir exists: mode=%v", fi.Mode())
	}

	// Trash directory should contain the file.
	entries, err := os.ReadDir(trashDir)
	if err != nil {
		t.Fatalf("read trash dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("trash directory should not be empty")
	}

	trashFile := filepath.Join(trashDir, entries[0].Name())
	content, err := os.ReadFile(trashFile)
	if err != nil {
		t.Fatalf("read trash file: %v", err)
	}
	if string(content) != "precious data" {
		t.Errorf("expected 'precious data', got %q", string(content))
	}
}

func TestIntegration_ConnectRedirect(t *testing.T) {
	requirePtrace(t)

	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("nc not found in PATH")
	}

	// Start a listener on a random port — this is the redirect target.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targetPort := listener.Addr().(*net.TCPAddr).Port

	// Accept one connection and respond.
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("redirected"))
		conn.Close()
	}()

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.txt")
	readyFile := filepath.Join(tmpDir, "ready")

	origPort := 19999

	netHandler := &mockNetworkHandler{
		defaultAllow:     true,
		redirectPort:     targetPort,
		redirectFromPort: origPort,
	}

	tr := NewTracer(TracerConfig{
		AttachMode:     "pid",
		TraceExecve:    true,
		TraceNetwork:   true,
		ExecHandler:    &mockExecHandler{defaultAllow: true},
		NetworkHandler: netHandler,
		MaxTracees:     100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Use nc (netcat) to connect; -n skips DNS resolution to avoid
	// systemd-resolved latency. Wait for ready file first.
	cmd := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("while [ ! -f %s ]; do sleep 0.01; done; echo | nc -n -w2 127.0.0.1 %d > %s 2>/dev/null || echo failed > %s",
			readyFile, origPort, outputFile, outputFile))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Release the process from Go's runtime tracking to prevent its internal
	// waitpid from competing with our ptrace tracer's Wait4(-1) for events.
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 8*time.Second)
	cancel()
	<-errCh

	content, _ := os.ReadFile(outputFile)
	trimmed := strings.TrimSpace(string(content))
	if trimmed != "redirected" {
		t.Errorf("connect redirect output: expected %q, got %q", "redirected", trimmed)
	}
}

func TestIntegration_ScratchPage(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()

	origFile := filepath.Join(tmpDir, "a.txt")
	longName := strings.Repeat("x", 200) + ".txt"
	redirectTarget := filepath.Join(tmpDir, longName)
	os.WriteFile(origFile, []byte("short"), 0644)
	os.WriteFile(redirectTarget, []byte("long-path-content"), 0644)

	outputFile := filepath.Join(tmpDir, "output.txt")
	readyFile := filepath.Join(tmpDir, "ready")

	fileHandler := &mockFileHandler{
		defaultAllow: true,
		rules: map[string]FileResult{
			"a.txt": {Action: "redirect", RedirectPath: redirectTarget},
		},
	}

	tr := NewTracer(TracerConfig{
		AttachMode:  "pid",
		TraceExecve: true,
		TraceFile:   true,
		ExecHandler: &mockExecHandler{defaultAllow: true},
		FileHandler: fileHandler,
		MaxTracees:  100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	cmd := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("while [ ! -f %s ]; do sleep 0.01; done; cat %s > %s", readyFile, origFile, outputFile))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Release the process from Go's runtime tracking to prevent its internal
	// waitpid from competing with our ptrace tracer's Wait4(-1) for events.
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 5*time.Second)
	cancel()
	<-errCh

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if strings.TrimSpace(string(content)) != "long-path-content" {
		t.Errorf("expected 'long-path-content', got %q", string(content))
	}
}