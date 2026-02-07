//go:build !linux || !cgo

package api

import (
	"context"
	"errors"
	"os"
)

var (
	errWrapNotSupported = errors.New("wrap is only supported on Linux")
	errWrapperNotFound  = errors.New("seccomp wrapper binary not found")
)

func recvFDFromConn(sock *os.File) (*os.File, error) {
	return nil, errWrapNotSupported
}

func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool) {
	// No-op on non-Linux platforms
}
