//go:build windows

package pty

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

// ErrConPtyUnavailable is returned when ConPTY is not available on the system.
var ErrConPtyUnavailable = errors.New("ConPTY not available (requires Windows 10 1809+)")

// Signal constants for Windows compatibility.
// Windows doesn't define POSIX signals, so we use the standard values.
const (
	sigHUP  = syscall.Signal(0x1)
	sigINT  = syscall.Signal(0x2)
	sigQUIT = syscall.Signal(0x3)
	sigKILL = syscall.Signal(0x9)
	sigTERM = syscall.Signal(0xf)
)

type Winsize struct {
	Rows uint16
	Cols uint16
}

type StartRequest struct {
	Command string
	Args    []string

	Argv0 string
	Dir   string
	Env   []string

	InitialSize Winsize
}

// Session represents a PTY session on Windows using ConPTY.
type Session struct {
	cpty    *conpty.ConPty
	outCh   chan []byte
	outDone chan struct{}
	pid     int
	mu      sync.Mutex
	closed  bool
}

// Output returns a channel that receives PTY output.
func (s *Session) Output() <-chan []byte {
	if s == nil {
		ch := make(chan []byte)
		close(ch)
		return ch
	}
	return s.outCh
}

// PID returns the process ID of the PTY session.
func (s *Session) PID() int {
	if s == nil {
		return 0
	}
	return s.pid
}

// Write sends input to the PTY.
func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.cpty == nil {
		return 0, io.ErrClosedPipe
	}
	return s.cpty.Write(p)
}

// Resize changes the terminal size.
func (s *Session) Resize(rows, cols uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.cpty == nil {
		return io.ErrClosedPipe
	}
	// conpty.Resize takes (width, height) = (cols, rows)
	return s.cpty.Resize(int(cols), int(rows))
}

// Signal sends a signal to the PTY process.
// Windows doesn't have POSIX signals, so we emulate them:
// - SIGINT/SIGQUIT: Send control characters to PTY
// - SIGTERM/SIGHUP/SIGKILL: Terminate the process
func (s *Session) Signal(sig syscall.Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.cpty == nil {
		return errors.New("session closed")
	}

	switch sig {
	case sigINT:
		// Send Ctrl+C character to PTY
		_, err := s.cpty.Write([]byte{0x03})
		return err
	case sigQUIT:
		// Send Ctrl+\ character to PTY
		_, err := s.cpty.Write([]byte{0x1c})
		return err
	case sigTERM, sigHUP, sigKILL:
		// Terminate the process
		return s.terminateProcess()
	default:
		// Unsupported signal - terminate as fallback
		return s.terminateProcess()
	}
}

// terminateProcess forcefully terminates the PTY process.
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

// Wait waits for the PTY process to exit and returns the exit code.
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

// readOutput continuously reads from the ConPTY and sends to the output channel.
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
				// Channel full, drop oldest and retry
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

// Engine creates and manages PTY sessions.
type Engine struct{}

// New creates a new PTY engine.
func New() *Engine { return &Engine{} }

// Start creates a new PTY session with the given command.
func (e *Engine) Start(ctx context.Context, req StartRequest) (*Session, error) {
	if !conpty.IsConPtyAvailable() {
		return nil, ErrConPtyUnavailable
	}

	if req.Command == "" {
		return nil, errors.New("command is required")
	}

	// Build command line (Windows requires single string)
	cmdLine := buildCommandLine(req.Command, req.Args)

	// Build options
	var opts []conpty.ConPtyOption
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
