//go:build linux && cgo

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/signal"
	"github.com/agentsh/agentsh/pkg/types"
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
func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int) {
	emitter := &notifyEmitterAdapter{store: a.store, broker: a.broker}

	// Create execve handler if enabled
	var execveHandler *unixmon.ExecveHandler
	var cleanupSymlink func()
	if execveEnabled {
		if h := createExecveHandler(a.cfg.Sandbox.Seccomp.Execve, a.policy, a.approvals); h != nil {
			execveHandler, _ = h.(*unixmon.ExecveHandler)
			if execveHandler != nil {
				execveHandler.SetEmitter(emitter)

				// Register wrapper process for depth tracking
				if wrapperPID > 0 {
					execveHandler.RegisterSession(wrapperPID, sessionID)
				}

				// Create stub symlink for execve redirect
				stubPath, err := exec.LookPath("agentsh-stub")
				if err != nil {
					slog.Warn("wrap: agentsh-stub not found, redirect will deny",
						"error", err, "session_id", sessionID)
				} else {
					// Normalize to absolute path in case LookPath returns relative
					if !filepath.IsAbs(stubPath) {
						if abs, err := filepath.Abs(stubPath); err == nil {
							stubPath = abs
						}
					}
					symlinkPath, cleanup, err := unixmon.CreateStubSymlink(stubPath)
					if err != nil {
						slog.Warn("wrap: failed to create stub symlink, redirect will deny",
							"error", err, "session_id", sessionID)
					} else {
						execveHandler.SetStubSymlinkPath(symlinkPath)
						cleanupSymlink = cleanup
						slog.Debug("wrap: created stub symlink",
							"symlink", symlinkPath, "target", stubPath, "session_id", sessionID)
					}

					// Set the global stub binary path for reference
					unixmon.SetStubBinaryPath(stubPath)
				}
			}
		}
	}

	go func() {
		defer notifyFD.Close()
		if cleanupSymlink != nil {
			defer cleanupSymlink()
		}
		slog.Info("wrap: starting notify handler", "session_id", sessionID, "has_execve", execveHandler != nil)
		unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessionID, a.policy, emitter, execveHandler, nil)
		slog.Info("wrap: notify handler returned", "session_id", sessionID)
	}()
}

// startSignalHandlerForWrap starts the signal filter handler for a wrap session.
func startSignalHandlerForWrap(ctx context.Context, signalFD *os.File, sessionID string, a *App) {
	if a.policy == nil || a.policy.SignalEngine() == nil {
		signalFD.Close()
		return
	}

	emitter := &signalEmitterAdapter{
		store:     a.store,
		broker:    a.broker,
		sessionID: sessionID,
		commandID: func() string { return "" },
	}
	registry := signal.NewPIDRegistry(sessionID, os.Getpid())
	handler := signal.NewHandler(a.policy.SignalEngine(), registry, emitter)

	go func() {
		defer signalFD.Close()
		slog.Info("wrap: starting signal handler", "session_id", sessionID)
		serveSignalNotify(ctx, signalFD, handler)
		slog.Info("wrap: signal handler returned", "session_id", sessionID)
	}()
}

// wrapInitWindows is not available on Linux.
func (a *App) wrapInitWindows(_ context.Context, _ *session.Session, _ string, _ types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	return types.WrapInitResponse{}, http.StatusBadRequest, errWrapNotSupported
}

// getConnPeerPID extracts the peer process PID from a Unix connection.
func getConnPeerPID(conn *net.UnixConn) int {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		slog.Debug("getConnPeerPID: failed to get syscall conn", "error", err)
		return 0
	}
	var pid int
	rawConn.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			slog.Debug("getConnPeerPID: GetsockoptUcred failed", "error", err)
		} else {
			pid = int(ucred.Pid)
		}
	})
	return pid
}
