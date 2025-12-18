package pty

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
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

type Session struct {
	cmd    *exec.Cmd
	master *os.File

	outCh   chan []byte
	outDone chan struct{}
}

func (s *Session) Output() <-chan []byte { return s.outCh }

func (s *Session) Write(p []byte) (int, error) {
	if s == nil || s.master == nil {
		return 0, io.ErrClosedPipe
	}
	return s.master.Write(p)
}

func (s *Session) Resize(rows, cols uint16) error {
	if s == nil || s.master == nil {
		return io.ErrClosedPipe
	}
	ws := &unix.Winsize{Row: rows, Col: cols}
	return unix.IoctlSetWinsize(int(s.master.Fd()), unix.TIOCSWINSZ, ws)
}

func (s *Session) Signal(sig syscall.Signal) error {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return errors.New("process not started")
	}
	// Signal the process group for job control semantics.
	pgid, err := syscall.Getpgid(s.cmd.Process.Pid)
	if err != nil {
		return s.cmd.Process.Signal(sig)
	}
	return syscall.Kill(-pgid, sig)
}

func (s *Session) Wait() (exitCode int, err error) {
	if s == nil || s.cmd == nil {
		return 127, errors.New("process not started")
	}
	err = s.cmd.Wait()
	if s.outDone != nil {
		<-s.outDone
	}
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 127, err
}

type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Start(ctx context.Context, req StartRequest) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if req.Command == "" {
		return nil, errors.New("command is required")
	}

	masterFD, slaveFD, err := openPTY(req.InitialSize)
	if err != nil {
		return nil, err
	}
	master := os.NewFile(uintptr(masterFD), "pty-master")
	slave := os.NewFile(uintptr(slaveFD), "pty-slave")

	cmd := exec.CommandContext(ctx, req.Command, req.Args...)
	if req.Dir != "" {
		cmd.Dir = req.Dir
	}
	if len(req.Env) > 0 {
		cmd.Env = req.Env
	}
	if req.Argv0 != "" && len(cmd.Args) > 0 {
		cmd.Args[0] = req.Argv0
	}

	// New session + controlling TTY for interactive behavior.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		// Use stdin (fd 0) as controlling TTY after the child maps slave onto stdio.
		Ctty: 0,
	}

	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave

	outCh := make(chan []byte, 16)
	outDone := make(chan struct{})
	sess := &Session{cmd: cmd, master: master, outCh: outCh, outDone: outDone}

	if err := cmd.Start(); err != nil {
		_ = master.Close()
		_ = slave.Close()
		close(outCh)
		close(outDone)
		return nil, err
	}

	// Parent no longer needs the slave FD.
	_ = slave.Close()

	go func() {
		defer func() { _ = master.Close() }()
		defer close(outDone)
		defer close(outCh)
		buf := make([]byte, 32*1024)
		for {
			n, rerr := master.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				outCh <- b
			}
			if rerr != nil {
				return
			}
		}
	}()

	return sess, nil
}

func openPTY(size Winsize) (masterFD, slaveFD int, err error) {
	masterFD, err = unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return -1, -1, err
	}
	defer func() {
		if err != nil && masterFD >= 0 {
			_ = unix.Close(masterFD)
		}
	}()

	// Unlock PTY.
	if err := unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0); err != nil {
		return -1, -1, fmt.Errorf("unlockpt (TIOCSPTLCK): %w", err)
	}
	n, err := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
	if err != nil {
		return -1, -1, fmt.Errorf("get pty number (TIOCGPTN): %w", err)
	}

	slavePath := filepath.Join("/dev/pts", strconv.Itoa(n))
	slaveFD, err = unix.Open(slavePath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return -1, -1, err
	}
	defer func() {
		if err != nil && slaveFD >= 0 {
			_ = unix.Close(slaveFD)
		}
	}()

	if size.Rows > 0 && size.Cols > 0 {
		_ = unix.IoctlSetWinsize(slaveFD, unix.TIOCSWINSZ, &unix.Winsize{Row: size.Rows, Col: size.Cols})
	}
	return masterFD, slaveFD, nil
}
