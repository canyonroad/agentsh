//go:build linux && cgo

package api

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

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
func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session) {
	emitter := &notifyEmitterAdapter{store: a.store, broker: a.broker}

	// Prefer session-specific policy engine (has expanded ${PROJECT_ROOT} etc.)
	// over app-level engine, matching the exec path pattern in core.go.
	sessionPolicy := a.policyEngineFor(s)

	// Create execve handler if enabled
	var execveHandler *unixmon.ExecveHandler
	var cleanupSymlink func()
	if execveEnabled {
		if h := createExecveHandler(a.cfg.Sandbox.Seccomp.Execve, sessionPolicy, a.approvals); h != nil {
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

	// Create file handler if configured
	fileHandler := createFileHandler(a.cfg.Sandbox.Seccomp.FileMonitor, sessionPolicy, emitter, a.cfg.Landlock.Enabled)

	// Probe: verify ProcessVMReadv (or /proc/mem fallback) works against
	// the wrapper before starting. Same logic as the exec path probe in
	// notify_linux.go — catches broken memory access at startup.
	if wrapperPID > 0 {
		pvrErr, memErr := probeMemoryAccess(wrapperPID)
		if pvrErr != nil && memErr != nil {
			if fileHandler != nil || execveHandler != nil || sessionPolicy != nil {
				slog.Error("wrap: ProcessVMReadv and /proc/mem both failed — "+
					"handler cannot read tracee memory for path resolution",
					"wrapper_pid", wrapperPID,
					"pvr_error", pvrErr, "mem_error", memErr,
					"session_id", sessionID,
					"hint", "check kernel.yama.ptrace_scope, ensure CAP_SYS_PTRACE, "+
						"or set sandbox.seccomp.file_monitor.enabled: false")
				// Clean up resources that would normally be handled by the goroutine.
				notifyFD.Close()
				if cleanupSymlink != nil {
					cleanupSymlink()
				}
				return
			}
			slog.Warn("wrap: ProcessVMReadv probe failed, monitoring may be degraded",
				"wrapper_pid", wrapperPID, "pvr_error", pvrErr, "mem_error", memErr)
		} else if pvrErr != nil {
			// /proc/mem fallback works for file monitoring, but socket monitoring
			// uses ProcessVMReadv directly (ReadSockaddr has no /proc/mem fallback).
			if sessionPolicy != nil {
				slog.Warn("wrap: ProcessVMReadv failed — socket monitoring will be degraded "+
					"(ReadSockaddr requires ProcessVMReadv), /proc/mem fallback works for file monitoring",
					"wrapper_pid", wrapperPID, "pvr_error", pvrErr)
			} else {
				slog.Debug("wrap: ProcessVMReadv failed but /proc/mem fallback works",
					"wrapper_pid", wrapperPID, "pvr_error", pvrErr)
			}
		}
	}

	go func() {
		defer notifyFD.Close()
		if cleanupSymlink != nil {
			defer cleanupSymlink()
		}
		// Build the per-session block-list dispatch config. Empty for
		// errno/kill (kernel-side) and populated for log/log_and_kill.
		// The method returns any for cross-platform symmetry; the concrete
		// type on Linux is *unixmon.BlockListConfig.
		bl, _ := a.buildBlockListConfigFor(sessionID).(*unixmon.BlockListConfig)
		if bl != nil && len(bl.ActionByNr) > 0 && emitter == nil {
			slog.Warn("seccomp: on_block=log/log_and_kill selected but no event emitter wired; events will be dropped",
				"session_id", sessionID)
		}
		slog.Info("wrap: starting notify handler", "session_id", sessionID, "has_execve", execveHandler != nil, "has_file_handler", fileHandler != nil)
		unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessionID, sessionPolicy, emitter, execveHandler, fileHandler, bl)
		slog.Info("wrap: notify handler returned", "session_id", sessionID)
	}()
}

// startSignalHandlerForWrap starts the signal filter handler for a wrap session.
func startSignalHandlerForWrap(ctx context.Context, signalFD *os.File, sessionID string, a *App, s *session.Session) {
	// Route through the session's effective policy engine so per-session
	// signal rules are honored (canyonroad/agentsh#191). Previously this
	// function read a.policy directly, which silently ignored rules
	// authored in any non-default policy file.
	engine := a.policyEngineFor(s)
	if engine == nil {
		signalFD.Close()
		return
	}
	sigEngine := engine.SignalEngine()
	if sigEngine == nil {
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
	handler := signal.NewHandler(sigEngine, registry, emitter)

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

type peerCreds struct {
	PID int
	UID uint32
}

// getConnPeerCreds extracts the peer process credentials from a Unix connection.
func getConnPeerCreds(conn *net.UnixConn) peerCreds {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		slog.Debug("getConnPeerCreds: failed to get syscall conn", "error", err)
		return peerCreds{}
	}
	var creds peerCreds
	if err := rawConn.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			slog.Debug("getConnPeerCreds: GetsockoptUcred failed", "error", err)
		} else {
			creds.PID = int(ucred.Pid)
			creds.UID = ucred.Uid
		}
	}); err != nil {
		slog.Debug("getConnPeerCreds: RawConn.Control failed", "error", err)
		return peerCreds{}
	}
	return creds
}

// acceptPtracePID accepts a connection on the notify socket, extracts the peer
// PID via SO_PEERCRED, and attaches the ptrace tracer. The connection is kept
// open as a keepalive — when the shell exits, the connection closes.
func (a *App) acceptPtracePID(ctx context.Context, listener net.Listener, socketPath string, sessionID string, expectedUID int) {
	defer listener.Close()
	defer os.RemoveAll(filepath.Dir(socketPath))

	// Set accept deadline to prevent indefinite goroutine leak
	if ul, ok := listener.(*net.UnixListener); ok {
		ul.SetDeadline(time.Now().Add(30 * time.Second))
	}

	conn, err := listener.Accept()
	if err != nil {
		slog.Error("ptrace wrap: accept failed", "error", err, "session_id", sessionID)
		return
	}

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		slog.Error("ptrace wrap: connection is not a Unix connection", "session_id", sessionID)
		return
	}

	creds := getConnPeerCreds(unixConn)
	if expectedUID < 0 {
		conn.Close()
		slog.Warn("ptrace wrap: rejecting connection with invalid caller UID",
			"expected_uid", expectedUID, "session_id", sessionID)
		return
	}
	if expectedUID > 0 && creds.UID != uint32(expectedUID) {
		conn.Close()
		slog.Warn("ptrace wrap: rejecting connection from unexpected UID",
			"peer_uid", creds.UID, "expected_uid", expectedUID, "session_id", sessionID)
		return
	}

	// Set read deadline for the handshake
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read child PID from client (4-byte little-endian).
	// The CLI sends the spawned shell's PID explicitly rather than relying
	// on SO_PEERCRED, which would give the CLI's PID instead.
	pidBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, pidBuf); err != nil {
		conn.Write([]byte{0}) // NACK
		conn.Close()
		slog.Error("ptrace wrap: failed to read PID", "error", err, "session_id", sessionID)
		return
	}
	pid := int(binary.LittleEndian.Uint32(pidBuf))
	if pid <= 0 {
		conn.Write([]byte{0}) // NACK
		conn.Close()
		slog.Error("ptrace wrap: invalid PID", "pid", pid, "session_id", sessionID)
		return
	}

	// Basic validation: verify the PID exists
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		conn.Write([]byte{0}) // NACK
		conn.Close()
		slog.Error("ptrace wrap: PID does not exist", "pid", pid, "error", err, "session_id", sessionID)
		return
	}

	// Clear read deadline for the keepalive phase
	conn.SetDeadline(time.Time{})

	_, _, attachErr := ptraceExecAttach(a.ptraceTracer, pid, sessionID, "", false)
	if attachErr != nil {
		conn.Write([]byte{0}) // NACK
		conn.Close()
		slog.Error("ptrace wrap: attach failed", "pid", pid, "error", attachErr, "session_id", sessionID)
		return
	}

	// ACK: attach succeeded, CLI can proceed
	conn.Write([]byte{1})
	slog.Info("ptrace wrap: attached to shell", "pid", pid, "session_id", sessionID)

	// Keep connection open until context is cancelled or shell exits.
	go func() {
		defer conn.Close()
		buf := make([]byte, 1)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn.Read(buf) // blocks until close or error
				return
			}
		}
	}()
}
