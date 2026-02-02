//go:build windows

package pty

import (
	"context"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/UserExistsError/conpty"
)

// skipInCI skips ConPTY tests in CI environments where they can be flaky.
func skipInCI(t *testing.T) {
	t.Helper()
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("skipping ConPTY test in CI (non-interactive environment)")
	}
}

func TestBuildCommandLine(t *testing.T) {
	// Test cases use syscall.EscapeArg behavior
	tests := []struct {
		command string
		args    []string
		want    string
	}{
		{"cmd.exe", nil, "cmd.exe"},
		{"cmd.exe", []string{"/c", "echo", "hello"}, `cmd.exe /c echo hello`},
		{"cmd.exe", []string{"/c", "echo hello world"}, `cmd.exe /c "echo hello world"`},
		// Arg has space AND quotes: gets wrapped in quotes, internal quotes escaped
		{"cmd.exe", []string{"/c", `echo "quoted"`}, `cmd.exe /c "echo \"quoted\""`},
		{"C:\\Program Files\\app.exe", nil, `"C:\Program Files\app.exe"`},
	}

	for _, tt := range tests {
		got := buildCommandLine(tt.command, tt.args)
		if got != tt.want {
			t.Errorf("buildCommandLine(%q, %v) = %q, want %q", tt.command, tt.args, got, tt.want)
		}
	}
}

func TestSyscallEscapeArg(t *testing.T) {
	// Verify syscall.EscapeArg behavior for documentation
	// Note: EscapeArg only wraps in quotes if spaces/tabs present
	tests := []struct {
		arg  string
		want string
	}{
		{"simple", "simple"},
		{"with space", `"with space"`},
		// No spaces = no quotes, but internal quotes are escaped
		{`with"quote`, `with\"quote`},
		{"", `""`},
		{"path\\to\\file", "path\\to\\file"},
		{"C:\\Program Files", `"C:\Program Files"`},
		// Backslashes not before quotes are not escaped
		{`path\`, `path\`},
		// Backslashes before quotes are escaped
		{`path\"`, `path\\\"`},
	}

	for _, tt := range tests {
		got := syscall.EscapeArg(tt.arg)
		if got != tt.want {
			t.Errorf("syscall.EscapeArg(%q) = %q, want %q", tt.arg, got, tt.want)
		}
	}
}

func TestEngineStart(t *testing.T) {
	skipInCI(t)
	if testing.Short() {
		t.Skip("skipping ConPTY test in short mode")
	}
	if !conpty.IsConPtyAvailable() {
		t.Skip("ConPTY not available")
	}

	e := New()
	sess, err := e.Start(context.Background(), StartRequest{
		Command:     "cmd.exe",
		Args:        []string{"/c", "echo hello"},
		InitialSize: Winsize{Rows: 24, Cols: 80},
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Read output with timeout
	var output strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		for b := range sess.Output() {
			output.Write(b)
		}
	}()

	// Wait for process with timeout
	waitDone := make(chan struct{})
	var exitCode int
	var waitErr error
	go func() {
		exitCode, waitErr = sess.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(30 * time.Second):
		t.Fatal("test timed out waiting for process")
	}
	<-done

	if waitErr != nil {
		t.Errorf("Wait error: %v", waitErr)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(output.String(), "hello") {
		t.Errorf("output = %q, want to contain 'hello'", output.String())
	}
}

func TestEngineStartEmptyCommand(t *testing.T) {
	e := New()
	_, err := e.Start(context.Background(), StartRequest{})
	if err == nil {
		t.Error("expected error for empty command")
	}
}

func TestSessionResize(t *testing.T) {
	skipInCI(t)
	if testing.Short() {
		t.Skip("skipping ConPTY test in short mode")
	}
	if !conpty.IsConPtyAvailable() {
		t.Skip("ConPTY not available")
	}

	e := New()
	sess, err := e.Start(context.Background(), StartRequest{
		Command:     "cmd.exe",
		InitialSize: Winsize{Rows: 24, Cols: 80},
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Resize should not error
	if err := sess.Resize(40, 120); err != nil {
		t.Errorf("Resize failed: %v", err)
	}

	// Send exit command and wait
	sess.Write([]byte("exit\r\n"))
	sess.Wait()
}

func TestSessionPID(t *testing.T) {
	skipInCI(t)
	if testing.Short() {
		t.Skip("skipping ConPTY test in short mode")
	}
	if !conpty.IsConPtyAvailable() {
		t.Skip("ConPTY not available")
	}

	e := New()
	sess, err := e.Start(context.Background(), StartRequest{
		Command:     "cmd.exe",
		Args:        []string{"/c", "echo test"},
		InitialSize: Winsize{Rows: 24, Cols: 80},
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer sess.Wait()

	pid := sess.PID()
	if pid == 0 {
		t.Error("PID() returned 0, expected non-zero")
	}
}

func TestSessionSignalINT(t *testing.T) {
	skipInCI(t)
	if testing.Short() {
		t.Skip("skipping ConPTY test in short mode")
	}
	if !conpty.IsConPtyAvailable() {
		t.Skip("ConPTY not available")
	}

	e := New()
	sess, err := e.Start(context.Background(), StartRequest{
		Command:     "cmd.exe",
		InitialSize: Winsize{Rows: 24, Cols: 80},
	})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Send SIGINT (should send Ctrl+C)
	if err := sess.Signal(sigINT); err != nil {
		t.Errorf("Signal(SIGINT) failed: %v", err)
	}

	// Clean exit
	sess.Write([]byte("exit\r\n"))
	sess.Wait()
}

func TestNilSession(t *testing.T) {
	var s *Session

	// These should not panic
	ch := s.Output()
	if ch == nil {
		t.Error("Output() on nil session returned nil channel")
	}

	pid := s.PID()
	if pid != 0 {
		t.Errorf("PID() on nil session = %d, want 0", pid)
	}

	_, err := s.Write([]byte("test"))
	if err != io.ErrClosedPipe {
		t.Errorf("Write() on nil session error = %v, want io.ErrClosedPipe", err)
	}
}
