//go:build linux && cgo

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"golang.org/x/sys/unix"
)

var (
	errWrapNotSupported = errors.New("wrap is only supported on Linux")
	errWrapperNotFound  = errors.New("seccomp wrapper binary not found (agentsh-unixwrap not in PATH)")
)

// recvFDFromConn receives a file descriptor from a Unix socket connection using SCM_RIGHTS.
func recvFDFromConn(sock *os.File) (*os.File, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return nil, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 || oobn == 0 {
		return nil, fmt.Errorf("no fd received")
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("parse control message: %w", err)
	}
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return os.NewFile(uintptr(fds[0]), "wrap-notif-fd"), nil
		}
	}
	return nil, fmt.Errorf("no fd in control message")
}

// startNotifyHandlerForWrap starts the seccomp notify handler for a wrap session.
// Unlike the exec path where the notify fd comes from a socketpair, here it comes
// from the CLI via a Unix socket connection.
func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool) {
	emitter := &notifyEmitterAdapter{store: a.store, broker: a.broker}

	// Create execve handler if enabled
	var execveHandler *unixmon.ExecveHandler
	if execveEnabled {
		if h := createExecveHandler(a.cfg.Sandbox.Seccomp.Execve, a.policy); h != nil {
			execveHandler, _ = h.(*unixmon.ExecveHandler)
			if execveHandler != nil {
				execveHandler.SetEmitter(emitter)
			}
		}
	}

	go func() {
		defer notifyFD.Close()
		slog.Info("wrap: starting notify handler", "session_id", sessionID, "has_execve", execveHandler != nil)
		unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessionID, a.policy, emitter, execveHandler)
		slog.Info("wrap: notify handler returned", "session_id", sessionID)
	}()
}
