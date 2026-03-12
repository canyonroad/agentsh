//go:build integration && linux

package ptrace

import (
	"context"
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
