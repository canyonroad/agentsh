//go:build linux

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

// platformSetupWrap creates a socket pair, configures the wrapper launch, and
// returns a postStart function that receives the notify fd from the wrapper and
// forwards it to the server's Unix listener socket.
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
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
	env := os.Environ()
	env = append(env,
		fmt.Sprintf("AGENTSH_SESSION_ID=%s", sessID),
		fmt.Sprintf("AGENTSH_SERVER=%s", cfg.serverAddr),
		"AGENTSH_NOTIFY_SOCK_FD=3", // fd 3 = ExtraFiles[0]
	)
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

	return &wrapLaunchConfig{
		command:    wrapResp.WrapperBinary,
		args:       wrapperArgs,
		env:        env,
		extraFiles: extraFiles,
		sysProcAttr: &syscall.SysProcAttr{
			Setpgid: true,
		},
		postStart: func() {
			defer parentFile.Close()
			// Receive the seccomp notify fd from the wrapper
			notifyFD, err := recvNotifyFD(parentFile)
			if err != nil {
				slog.Error("wrap: failed to receive notify fd from wrapper", "error", err, "session_id", sessID)
				return
			}
			defer func() { unix.Close(notifyFD) }()

			// Forward the notify fd to the server's Unix listener socket
			if err := forwardNotifyFD(notifySocket, notifyFD); err != nil {
				slog.Error("wrap: failed to forward notify fd to server", "error", err, "session_id", sessID)
				return
			}
			slog.Info("wrap: notify fd forwarded to server", "session_id", sessID, "socket", notifySocket)

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

// forwardNotifyFD connects to the server's Unix listener socket and sends the
// notify fd using SCM_RIGHTS.
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
