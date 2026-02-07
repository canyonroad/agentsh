//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/agentsh/agentsh/internal/stub"
	sysunix "golang.org/x/sys/unix"
)

// stubBinaryPath is the path to the agentsh-stub binary.
var stubBinaryPath string

// SetStubBinaryPath sets the path to the agentsh-stub binary.
func SetStubBinaryPath(path string) {
	stubBinaryPath = path
}

// createStubSocketPair creates a Unix socketpair for stub <-> server communication.
// Returns (stub-side-fd, server-side-conn, error).
// The stub-side fd is a raw fd (for injection via SECCOMP_ADDFD).
// The server-side conn is a net.Conn ready for ServeStubConnection.
func createStubSocketPair() (stubRawFD int, srvConn net.Conn, err error) {
	fds, err := sysunix.Socketpair(sysunix.AF_UNIX, sysunix.SOCK_STREAM|sysunix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, nil, fmt.Errorf("socketpair: %w", err)
	}

	srvFile := os.NewFile(uintptr(fds[1]), "srv-sock")
	srvConn, err = net.FileConn(srvFile)
	srvFile.Close()
	if err != nil {
		sysunix.Close(fds[0])
		return -1, nil, fmt.Errorf("srv FileConn: %w", err)
	}

	return fds[0], srvConn, nil
}

// handleRedirect implements the redirect path for an intercepted execve.
// 1. Creates socketpair
// 2. Injects stub-side fd into tracee via SECCOMP_ADDFD (with SEND flag to atomically respond)
// 3. Starts ServeStubConnection to run the original command
func handleRedirect(notifFD int, reqID uint64, ctx ExecveContext) error {
	stubRawFD, srvConn, err := createStubSocketPair()
	if err != nil {
		return fmt.Errorf("create socketpair: %w", err)
	}

	// Use a high fd number to avoid conflicts with the process's existing fds.
	const targetFD = 100

	// Inject the stub-side fd into the trapped process using SECCOMP_ADDFD_FLAG_SEND.
	// SEND atomically adds the fd AND responds to the notification, avoiding TOCTOU.
	_, err = NotifAddFD(notifFD, reqID, stubRawFD, targetFD, SECCOMP_ADDFD_FLAG_SETFD|SECCOMP_ADDFD_FLAG_SEND)
	sysunix.Close(stubRawFD) // Close our copy regardless of success
	if err != nil {
		srvConn.Close()
		return fmt.Errorf("addfd: %w", err)
	}

	// Start server handler in background to run the original command
	// and proxy I/O to the stub.
	go func() {
		defer srvConn.Close()
		sErr := stub.ServeStubConnection(context.Background(), srvConn, stub.ServeConfig{
			Command: ctx.Filename,
			Args:    ctx.Argv,
		})
		if sErr != nil {
			slog.Error("stub serve error", "pid", ctx.PID, "cmd", ctx.Filename, "error", sErr)
		}
	}()

	return nil
}
