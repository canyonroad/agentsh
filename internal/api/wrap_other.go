//go:build (!linux || !cgo) && !windows

package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

var (
	errWrapNotSupported = errors.New("wrap is only supported on Linux")
	errWrapperNotFound  = errors.New("seccomp wrapper binary not found")
)

type peerCreds struct {
	PID int
	UID uint32
}

func recvFDFromConn(sock *os.File) (*os.File, error) {
	return nil, errWrapNotSupported
}

func recvNotifyFDForWrap(conn *net.UnixConn) (*os.File, wrapNotifyMetadata, bool, error) {
	return nil, wrapNotifyMetadata{}, false, errWrapNotSupported
}

func writeNotifyStatusForWrap(w io.Writer, ok bool) error {
	return errWrapNotSupported
}

func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session, cleanup func() error) {
	// No-op on non-Linux platforms
}

func startSignalHandlerForWrap(ctx context.Context, signalFD *os.File, sessionID string, a *App, s *session.Session) {
	if signalFD != nil {
		signalFD.Close()
	}
}

func (a *App) wrapInitWindows(ctx context.Context, s *session.Session, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	return types.WrapInitResponse{}, http.StatusBadRequest, errWrapNotSupported
}

func getConnPeerCreds(conn *net.UnixConn) peerCreds {
	return peerCreds{}
}

func (a *App) acceptPtracePID(ctx context.Context, listener net.Listener, socketPath string, sessionID string, expectedUID int) {
	listener.Close()
}
