//go:build (!linux || !cgo) && !windows

package api

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
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

func startSignalHandlerForWrap(ctx context.Context, signalFD *os.File, sessionID string, a *App) {
	if signalFD != nil {
		signalFD.Close()
	}
}

func (a *App) wrapInitWindows(ctx context.Context, s *session.Session, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	return types.WrapInitResponse{}, http.StatusBadRequest, errWrapNotSupported
}
