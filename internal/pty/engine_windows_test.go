//go:build windows

package pty

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/UserExistsError/conpty"
)

func TestBuildCommandLine(t *testing.T) {
	tests := []struct {
		command string
		args    []string
		want    string
	}{
		{"cmd.exe", nil, "cmd.exe"},
		{"cmd.exe", []string{"/c", "echo", "hello"}, `cmd.exe /c echo hello`},
		{"cmd.exe", []string{"/c", "echo hello world"}, `cmd.exe /c "echo hello world"`},
		{"cmd.exe", []string{"/c", `echo "quoted"`}, `cmd.exe /c "echo ""quoted"""`},
		{"C:\\Program Files\\app.exe", nil, `"C:\Program Files\app.exe"`},
	}

	for _, tt := range tests {
		got := buildCommandLine(tt.command, tt.args)
		if got != tt.want {
			t.Errorf("buildCommandLine(%q, %v) = %q, want %q", tt.command, tt.args, got, tt.want)
		}
	}
}

func TestQuoteArg(t *testing.T) {
	tests := []struct {
		arg  string
		want string
	}{
		{"simple", "simple"},
		{"with space", `"with space"`},
		{`with"quote`, `"with""quote"`},
		{"", `""`},
		{"path\\to\\file", "path\\to\\file"},
		{"C:\\Program Files", `"C:\Program Files"`},
	}

	for _, tt := range tests {
		got := quoteArg(tt.arg)
		if got != tt.want {
			t.Errorf("quoteArg(%q) = %q, want %q", tt.arg, got, tt.want)
		}
	}
}

func TestEngineStart(t *testing.T) {
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

	// Read output
	var output strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		for b := range sess.Output() {
			output.Write(b)
		}
	}()

	// Wait for process
	exitCode, err := sess.Wait()
	<-done

	if err != nil {
		t.Errorf("Wait error: %v", err)
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
