//go:build linux

package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/agentsh/agentsh/internal/envinject"
	"github.com/agentsh/agentsh/internal/wrapenv"
	"github.com/agentsh/agentsh/internal/wraphandoff"
	"github.com/agentsh/agentsh/internal/wrapperlog"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

var notifySetupStatusTimeout = 30 * time.Second

// platformSetupWrap creates a socket pair, configures the wrapper launch, and
// returns a postStart function that receives the notify fd from the wrapper and
// forwards it to the server's Unix listener socket.
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
	// Ptrace mode: no wrapper binary needed. Connect to the server's socket
	// for PID handshake via SO_PEERCRED, then launch the shell directly.
	if wrapResp.PtraceMode {
		notifySocket := wrapResp.NotifySocket

		env := buildWrapEnv(wrapenv.Filter(os.Environ(), wrapResp.EnvPolicy), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
		// Overlay sandbox.env_inject so injected vars reach the command in
		// ptrace mode too, matching the seccomp/shim paths (issue #374).
		env = envinject.Apply(env, wrapResp.EnvInject)

		// connHolder stores the keepalive connection set by ptracePostStart.
		var connHolder net.Conn

		return &wrapLaunchConfig{
			command: agentPath,
			args:    agentArgs,
			env:     env,
			sysProcAttr: func() *syscall.SysProcAttr {
				attr := &syscall.SysProcAttr{Setpgid: true}
				if isTerminal(os.Stdin.Fd()) {
					attr.Foreground = true
					attr.Ctty = int(os.Stdin.Fd())
				}
				return attr
			}(),
			ptracePostStart: func(childPID int) error {
				// Connect after child starts, send the child PID explicitly
				// (SO_PEERCRED would give our parent PID, not the child's).
				conn, err := net.Dial("unix", notifySocket)
				if err != nil {
					return fmt.Errorf("dial: %w", err)
				}

				// Send child PID as 4-byte little-endian
				pidBytes := make([]byte, 4)
				binary.LittleEndian.PutUint32(pidBytes, uint32(childPID))
				if _, err := conn.Write(pidBytes); err != nil {
					conn.Close()
					return fmt.Errorf("send PID: %w", err)
				}

				// Wait for server ACK/NACK
				ack := make([]byte, 1)
				if _, err := conn.Read(ack); err != nil {
					conn.Close()
					return fmt.Errorf("read ACK: %w", err)
				}
				if ack[0] != 1 {
					conn.Close()
					return fmt.Errorf("server rejected attach")
				}

				connHolder = conn
				return nil
			},
			postWait: func() {
				if connHolder != nil {
					connHolder.Close()
				}
				if isTerminal(os.Stdin.Fd()) {
					reclaimTerminal()
				}
			},
		}, nil
	}

	// Create a socket pair for the notify fd exchange between the wrapper and this CLI process.
	// The child end (fds[1]) is inherited by agentsh-unixwrap as ExtraFiles[0] (fd 3).
	// The parent end (fds[0]) receives the seccomp notify fd from the wrapper.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}

	parentFile := os.NewFile(uintptr(fds[0]), "notify-parent")
	childFile := os.NewFile(uintptr(fds[1]), "notify-child")

	// Clear CLOEXEC on the child fd so it survives exec
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fds[1]), unix.F_SETFD, 0); errno != 0 {
		parentFile.Close()
		childFile.Close()
		return nil, fmt.Errorf("fcntl clear cloexec: %w", errno)
	}

	// Create a second socket pair for the signal filter fd if the server configured one.
	// The child end is inherited as ExtraFiles[1] (fd 4).
	var signalParentFile, signalChildFile *os.File
	hasSignalSocket := wrapResp.SignalSocket != ""
	if hasSignalSocket {
		sigFds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			parentFile.Close()
			childFile.Close()
			return nil, fmt.Errorf("signal socketpair: %w", err)
		}
		signalParentFile = os.NewFile(uintptr(sigFds[0]), "signal-parent")
		signalChildFile = os.NewFile(uintptr(sigFds[1]), "signal-child")

		// Clear CLOEXEC on the child fd so it survives exec
		if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(sigFds[1]), unix.F_SETFD, 0); errno != 0 {
			parentFile.Close()
			childFile.Close()
			signalParentFile.Close()
			signalChildFile.Close()
			return nil, fmt.Errorf("fcntl clear cloexec signal: %w", errno)
		}
	}

	// Build env for the wrapped process
	env := buildWrapEnv(wrapenv.Filter(os.Environ(), wrapResp.EnvPolicy), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
	// Overlay operator-configured sandbox.env_inject (override semantics)
	// before the internal markers, matching the shim and server-spawned exec
	// paths so injected vars reach the executed command (issue #374).
	env = envinject.Apply(env, wrapResp.EnvInject)
	env = append(env, "AGENTSH_NOTIFY_SOCK_FD=3") // fd 3 = ExtraFiles[0]
	if hasSignalSocket {
		env = append(env, "AGENTSH_SIGNAL_SOCK_FD=4") // fd 4 = ExtraFiles[1]
	}

	// Add wrapper env vars (seccomp config, etc.)
	for k, v := range wrapResp.WrapperEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	// Build command: agentsh-unixwrap -- <agent-path> <agent-args...>
	wrapperArgs := append([]string{"--", agentPath}, agentArgs...)

	notifySocket := wrapResp.NotifySocket
	signalSocket := wrapResp.SignalSocket

	extraFiles := []*os.File{childFile}
	if hasSignalSocket {
		extraFiles = append(extraFiles, signalChildFile)
	}

	// Wrapper log routing (issue #415): the CLI's stderr is the user's
	// terminal, so route wrapper diagnostics to the state-dir log file.
	// fd number = next ExtraFiles slot (4, or 5 with the signal socket).
	// Debug-level fallback note on open failure — a Warn would reintroduce
	// the exact noise this removes. wrap.go closes every extraFiles entry
	// after Start, so no extra cleanup is needed.
	// os.Getenv returns the FIRST duplicate, so drop any copy of the
	// key carried in by the inherited environment, env_inject, or
	// server WrapperEnv. Unconditional: even on open failure a stale
	// value must not survive — inside the wrapper it could name a
	// valid-but-unrelated fd (e.g. the signal socket at fd 4) and
	// receive routed diagnostics.
	env = stripEnvKey(env, wrapperlog.EnvKey)
	logFile, logErr := wrapperlog.OpenStateLogFile()
	if logErr != nil {
		// Debug, not Warn: the CLI's stderr is the user's terminal and
		// the wrapper falls back to it anyway (legacy behavior).
		slog.Debug("wrap: wrapper log file unavailable; wrapper diagnostics stay on stderr", "error", logErr)
	} else {
		env = append(env, fmt.Sprintf("%s=%d", wrapperlog.EnvKey, 3+len(extraFiles)))
		extraFiles = append(extraFiles, logFile)
	}

	return &wrapLaunchConfig{
		command:    wrapResp.WrapperBinary,
		args:       wrapperArgs,
		env:        env,
		extraFiles: extraFiles,
		sysProcAttr: func() *syscall.SysProcAttr {
			attr := &syscall.SysProcAttr{Setpgid: true}
			// If stdin is a terminal, make the child the foreground process
			// group so interactive shells (bash -i) can read from the TTY.
			if isTerminal(os.Stdin.Fd()) {
				attr.Foreground = true
				attr.Ctty = int(os.Stdin.Fd())
			}
			return attr
		}(),
		postWait: func() {
			// Reclaim the terminal's foreground process group after the child
			// exits so the parent can continue writing to stderr.
			if isTerminal(os.Stdin.Fd()) {
				reclaimTerminal()
			}
		},
		postStart: func(childPID int) {
			defer parentFile.Close()
			// Receive the seccomp notify fd from the wrapper
			notifyFD, err := recvNotifyFD(parentFile)
			if err != nil {
				slog.Error("wrap: failed to receive notify fd from wrapper", "error", err, "session_id", sessID)
				return
			}
			defer func() { unix.Close(notifyFD) }()

			// Forward the notify fd to the server's Unix listener socket
			if err := forwardNotifyFDWithPID(notifySocket, notifyFD, childPID); err != nil {
				slog.Error("wrap: failed to forward notify fd to server", "error", err, "session_id", sessID)
				return
			}
			slog.Info("wrap: notify fd accepted by server", "session_id", sessID, "socket", notifySocket, "wrapper_pid", childPID)

			// Send ACK to wrapper so it knows the handler is ready before exec.
			// This prevents a race where the wrapper execs before the seccomp
			// notify handler is started on the server.
			if _, err := parentFile.Write([]byte{1}); err != nil {
				slog.Debug("wrap: ACK write failed (wrapper may have already exited)", "error", err, "session_id", sessID)
			}

			// Forward signal filter fd if configured
			if hasSignalSocket && signalParentFile != nil {
				defer signalParentFile.Close()
				signalFD, err := recvNotifyFD(signalParentFile)
				if err != nil {
					slog.Debug("wrap: no signal fd from wrapper (signal filter may not be supported)", "error", err, "session_id", sessID)
					return
				}
				defer func() { unix.Close(signalFD) }()

				if err := forwardNotifyFD(signalSocket, signalFD); err != nil {
					slog.Error("wrap: failed to forward signal fd to server", "error", err, "session_id", sessID)
					return
				}
				slog.Info("wrap: signal fd forwarded to server", "session_id", sessID)
			}
		},
	}, nil
}

// recvNotifyFD receives a file descriptor from a Unix socket using SCM_RIGHTS.
func recvNotifyFD(sock *os.File) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return -1, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 || oobn == 0 {
		return -1, fmt.Errorf("no fd received (n=%d, oobn=%d)", n, oobn)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse control message: %w", err)
	}
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no fd in control message")
}

func forwardNotifyFDWithPID(socketPath string, notifyFD int, wrapperPID int) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	if err := wraphandoff.SendNotifyFD(unixConn, notifyFD, wraphandoff.Metadata{WrapperPID: wrapperPID}); err != nil {
		return err
	}
	if err := unixConn.SetReadDeadline(time.Now().Add(notifySetupStatusTimeout)); err != nil {
		return fmt.Errorf("set notify setup status deadline: %w", err)
	}
	if err := wraphandoff.ReadStatus(unixConn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return fmt.Errorf("timed out waiting for notify setup status after %s: %w", notifySetupStatusTimeout, err)
		}
		return fmt.Errorf("read notify setup status: %w", err)
	}
	return nil
}

func forwardNotifyFD(socketPath string, notifyFD int) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	file, err := unixConn.File()
	if err != nil {
		return fmt.Errorf("get file from connection: %w", err)
	}
	defer file.Close()

	// Send the notify fd via SCM_RIGHTS
	rights := unix.UnixRights(notifyFD)
	if err := unix.Sendmsg(int(file.Fd()), []byte{0}, rights, nil, 0); err != nil {
		return fmt.Errorf("sendmsg: %w", err)
	}

	return nil
}

// isTerminal returns true if the given file descriptor is a terminal.
func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

// reclaimTerminal makes the current process group the foreground group of stdin.
func reclaimTerminal() {
	pgid := int32(unix.Getpgrp())
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, os.Stdin.Fd(), unix.TIOCSPGRP, uintptr(unsafe.Pointer(&pgid)))
}

// stripEnvKey returns env without any KEY=... entries for key.
// WARNING: filters in place via env[:0] — it mutates the input slice's
// backing array, so callers must pass a slice they exclusively own.
func stripEnvKey(env []string, key string) []string {
	out := env[:0]
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}
