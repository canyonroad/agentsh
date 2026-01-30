# Windows PTY Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable interactive terminal sessions on Windows using ConPTY

**Architecture:** Replace the stub Windows PTY implementation with a real ConPTY-based implementation using the `github.com/UserExistsError/conpty` library

**Tech Stack:** Go, ConPTY (Windows API), github.com/UserExistsError/conpty

---

## Task 1: Add conpty dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

**Step 1: Add the dependency**

```bash
go get github.com/UserExistsError/conpty
```

**Step 2: Verify it's in go.mod**

Run: `grep conpty go.mod`
Expected: `github.com/UserExistsError/conpty v0.x.x`

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add github.com/UserExistsError/conpty for Windows PTY"
```

---

## Task 2: Implement Session struct and basic methods

**Files:**
- Modify: `internal/pty/engine_windows.go`

**Step 1: Update Session struct**

Replace the stub Session struct with:

```go
type Session struct {
	cpty    *conpty.ConPty
	outCh   chan []byte
	outDone chan struct{}
	pid     int
	mu      sync.Mutex
	closed  bool
}
```

**Step 2: Implement Output() method**

```go
func (s *Session) Output() <-chan []byte {
	if s == nil {
		ch := make(chan []byte)
		close(ch)
		return ch
	}
	return s.outCh
}
```

**Step 3: Implement PID() method**

```go
func (s *Session) PID() int {
	if s == nil {
		return 0
	}
	return s.pid
}
```

**Step 4: Implement Write() method**

```go
func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.cpty == nil {
		return 0, io.ErrClosedPipe
	}
	return s.cpty.Write(p)
}
```

**Step 5: Verify it compiles**

Run: `GOOS=windows go build ./internal/pty/...`
Expected: No errors

**Step 6: Commit**

```bash
git add internal/pty/engine_windows.go
git commit -m "feat(pty): add Windows Session struct with basic methods"
```

---

## Task 3: Implement Resize() method

**Files:**
- Modify: `internal/pty/engine_windows.go`

**Step 1: Implement Resize()**

```go
func (s *Session) Resize(rows, cols uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.cpty == nil {
		return io.ErrClosedPipe
	}
	return s.cpty.Resize(int(cols), int(rows))
}
```

Note: conpty.Resize takes (width, height) = (cols, rows), so we swap the order.

**Step 2: Verify it compiles**

Run: `GOOS=windows go build ./internal/pty/...`
Expected: No errors

**Step 3: Commit**

```bash
git add internal/pty/engine_windows.go
git commit -m "feat(pty): implement Windows PTY Resize via ConPTY"
```

---

## Task 4: Implement Signal() method

**Files:**
- Modify: `internal/pty/engine_windows.go`

**Step 1: Implement Signal()**

```go
func (s *Session) Signal(sig syscall.Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.cpty == nil {
		return errors.New("session closed")
	}

	switch sig {
	case syscall.SIGINT:
		// Send Ctrl+C character to PTY
		_, err := s.cpty.Write([]byte{0x03})
		return err
	case syscall.SIGQUIT:
		// Send Ctrl+\ character to PTY
		_, err := s.cpty.Write([]byte{0x1c})
		return err
	case syscall.SIGTERM, syscall.SIGHUP, syscall.SIGKILL:
		// Terminate the process
		return s.terminateProcess()
	default:
		// Unsupported signal - terminate as fallback
		return s.terminateProcess()
	}
}

func (s *Session) terminateProcess() error {
	if s.pid == 0 {
		return errors.New("no process to terminate")
	}
	proc, err := os.FindProcess(s.pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
```

**Step 2: Add syscall constants if needed**

Windows may not define all signal constants. Add at top of file:

```go
// Signal constants for Windows compatibility
const (
	sigINT  = syscall.Signal(0x2)  // SIGINT
	sigTERM = syscall.Signal(0xf)  // SIGTERM
	sigKILL = syscall.Signal(0x9)  // SIGKILL
	sigHUP  = syscall.Signal(0x1)  // SIGHUP
	sigQUIT = syscall.Signal(0x3)  // SIGQUIT
)
```

Then use these constants in the switch if syscall.SIGXXX is not available.

**Step 3: Verify it compiles**

Run: `GOOS=windows go build ./internal/pty/...`
Expected: No errors

**Step 4: Commit**

```bash
git add internal/pty/engine_windows.go
git commit -m "feat(pty): implement Windows PTY Signal handling"
```

---

## Task 5: Implement Wait() method

**Files:**
- Modify: `internal/pty/engine_windows.go`

**Step 1: Implement Wait()**

```go
func (s *Session) Wait() (exitCode int, err error) {
	if s == nil || s.cpty == nil {
		return 127, errors.New("process not started")
	}

	code, err := s.cpty.Wait(context.Background())

	// Wait for output to drain
	if s.outDone != nil {
		<-s.outDone
	}

	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	if err != nil {
		return 127, err
	}
	return int(code), nil
}
```

**Step 2: Verify it compiles**

Run: `GOOS=windows go build ./internal/pty/...`
Expected: No errors

**Step 3: Commit**

```bash
git add internal/pty/engine_windows.go
git commit -m "feat(pty): implement Windows PTY Wait method"
```

---

## Task 6: Implement command line building helpers

**Files:**
- Modify: `internal/pty/engine_windows.go`

**Step 1: Add command line building functions**

```go
// buildCommandLine combines command and args into a single Windows command line.
func buildCommandLine(command string, args []string) string {
	if len(args) == 0 {
		return command
	}

	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteArg(command))
	for _, arg := range args {
		parts = append(parts, quoteArg(arg))
	}
	return strings.Join(parts, " ")
}

// quoteArg quotes an argument if it contains special characters.
func quoteArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.ContainsAny(arg, " \t\"") {
		return arg
	}
	// Escape embedded quotes by doubling them
	escaped := strings.ReplaceAll(arg, `"`, `""`)
	return `"` + escaped + `"`
}
```

**Step 2: Add strings import if not present**

**Step 3: Verify it compiles**

Run: `GOOS=windows go build ./internal/pty/...`
Expected: No errors

**Step 4: Commit**

```bash
git add internal/pty/engine_windows.go
git commit -m "feat(pty): add Windows command line building helpers"
```

---

## Task 7: Implement Engine.Start() method

**Files:**
- Modify: `internal/pty/engine_windows.go`

**Step 1: Add error variable**

```go
var ErrConPtyUnavailable = errors.New("ConPTY not available (requires Windows 10 1809+)")
```

**Step 2: Implement Start()**

```go
func (e *Engine) Start(ctx context.Context, req StartRequest) (*Session, error) {
	if !conpty.IsConPtyAvailable() {
		return nil, ErrConPtyUnavailable
	}

	if req.Command == "" {
		return nil, errors.New("command is required")
	}

	// Build command line
	cmdLine := buildCommandLine(req.Command, req.Args)

	// Build options
	opts := []conpty.ConPtyOption{}
	if req.InitialSize.Cols > 0 && req.InitialSize.Rows > 0 {
		opts = append(opts, conpty.ConPtyDimensions(
			int(req.InitialSize.Cols),
			int(req.InitialSize.Rows),
		))
	}
	if req.Dir != "" {
		opts = append(opts, conpty.ConPtyWorkDir(req.Dir))
	}
	if len(req.Env) > 0 {
		opts = append(opts, conpty.ConPtyEnv(req.Env))
	}

	cpty, err := conpty.Start(cmdLine, opts...)
	if err != nil {
		return nil, err
	}

	sess := &Session{
		cpty:    cpty,
		outCh:   make(chan []byte, 16),
		outDone: make(chan struct{}),
		pid:     cpty.Pid(),
	}

	// Start output reader goroutine
	go sess.readOutput()

	return sess, nil
}
```

**Step 3: Implement readOutput()**

```go
func (s *Session) readOutput() {
	defer close(s.outDone)
	defer close(s.outCh)

	buf := make([]byte, 32*1024)
	for {
		n, err := s.cpty.Read(buf)
		if n > 0 {
			b := make([]byte, n)
			copy(b, buf[:n])
			select {
			case s.outCh <- b:
			default:
				// Channel full, drop oldest
				select {
				case <-s.outCh:
				default:
				}
				s.outCh <- b
			}
		}
		if err != nil {
			return
		}
	}
}
```

**Step 4: Add conpty import**

```go
import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/UserExistsError/conpty"
)
```

**Step 5: Verify it compiles**

Run: `GOOS=windows go build ./internal/pty/...`
Expected: No errors

**Step 6: Commit**

```bash
git add internal/pty/engine_windows.go
git commit -m "feat(pty): implement Windows PTY Engine.Start with ConPTY"
```

---

## Task 8: Add tests

**Files:**
- Create: `internal/pty/engine_windows_test.go`

**Step 1: Create test file**

```go
//go:build windows

package pty

import (
	"context"
	"strings"
	"testing"
	"time"

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

func TestEngineStartNotAvailable(t *testing.T) {
	// This test only makes sense if we could mock IsConPtyAvailable
	// For now, just verify it doesn't panic
	e := New()
	_, _ = e.Start(context.Background(), StartRequest{
		Command: "cmd.exe",
	})
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
	defer sess.Wait()

	// Resize should not error
	if err := sess.Resize(40, 120); err != nil {
		t.Errorf("Resize failed: %v", err)
	}

	// Send exit command
	sess.Write([]byte("exit\r\n"))
}
```

**Step 2: Verify tests compile**

Run: `GOOS=windows go build ./internal/pty/...`
Expected: No errors

**Step 3: Commit**

```bash
git add internal/pty/engine_windows_test.go
git commit -m "test(pty): add Windows PTY tests"
```

---

## Task 9: Final verification and cleanup

**Files:**
- Review: `internal/pty/engine_windows.go`

**Step 1: Verify full build**

Run: `go build ./...`
Expected: No errors

Run: `GOOS=windows go build ./...`
Expected: No errors

**Step 2: Run all tests**

Run: `go test ./...`
Expected: All pass

**Step 3: Verify the design doc is committed**

```bash
git add docs/plans/2026-01-30-windows-pty-design.md docs/plans/2026-01-30-windows-pty-plan.md
git commit -m "docs: add Windows PTY design and implementation plan"
```

**Step 4: Review git log**

Run: `git log --oneline main..HEAD`
Expected: ~8-9 commits covering all implementation
