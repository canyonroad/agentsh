//go:build windows

package pty

import (
	"context"
	"errors"
	"io"
	"syscall"
)

// ErrNotSupported is returned when PTY is not supported on Windows.
var ErrNotSupported = errors.New("pty: not supported on Windows")

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
	pid int
}

func (s *Session) Output() <-chan []byte {
	ch := make(chan []byte)
	close(ch)
	return ch
}

func (s *Session) PID() int {
	if s == nil {
		return 0
	}
	return s.pid
}

func (s *Session) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (s *Session) Resize(rows, cols uint16) error {
	return ErrNotSupported
}

func (s *Session) Signal(sig syscall.Signal) error {
	return ErrNotSupported
}

func (s *Session) Wait() (exitCode int, err error) {
	return 127, ErrNotSupported
}

type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Start(ctx context.Context, req StartRequest) (*Session, error) {
	return nil, ErrNotSupported
}
