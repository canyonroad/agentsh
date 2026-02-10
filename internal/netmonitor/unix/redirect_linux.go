//go:build linux && cgo

package unix

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/agentsh/agentsh/internal/stub"
	sysunix "golang.org/x/sys/unix"
)

// stubBinaryPath is the path to the agentsh-stub binary.
var stubBinaryPath string

// ErrRedirectPathTooLong is returned when the stub symlink path exceeds the
// original filename length, making in-place memory overwrite impossible.
var ErrRedirectPathTooLong = errors.New("stub symlink path longer than original filename")

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
//
// Three-phase approach:
//  1. Inject stub socket fd into tracee via SECCOMP_ADDFD (without SEND — notification stays pending)
//  2. Overwrite filename in tracee memory with stub symlink path via process_vm_writev
//  3. Return nil to signal the caller should respond with CONTINUE (kernel re-executes modified execve)
//
// If the stub symlink path is longer than the original filename, the overwrite
// cannot safely fit and we return ErrRedirectPathTooLong. The caller should deny.
//
// Parameters:
//   - filenamePtr: the tracee memory address of the filename string (from execve arg0)
//   - stubSymlinkPath: short path to a symlink that points to agentsh-stub
func handleRedirect(notifFD int, reqID uint64, ctx ExecveContext, filenamePtr uint64, stubSymlinkPath string, originalFilenameLen int) error {
	// Validate the stub path fits within the original filename's memory.
	// The original string at filenamePtr has originalFilenameLen+1 bytes (including null).
	// We need len(stubSymlinkPath)+1 bytes for the replacement.
	if len(stubSymlinkPath) > originalFilenameLen {
		return ErrRedirectPathTooLong
	}

	stubRawFD, srvConn, err := createStubSocketPair()
	if err != nil {
		return fmt.Errorf("create socketpair: %w", err)
	}

	// Use a high fd number to avoid conflicts with the process's existing fds.
	const targetFD = 100

	// Phase 1: Inject the stub-side fd WITHOUT SEND.
	// The notification remains pending so we can modify memory before responding.
	_, err = NotifAddFD(notifFD, reqID, stubRawFD, targetFD, SECCOMP_ADDFD_FLAG_SETFD)
	sysunix.Close(stubRawFD) // Close our copy regardless of success
	if err != nil {
		srvConn.Close()
		return fmt.Errorf("addfd: %w", err)
	}

	// Phase 2: Overwrite the filename in tracee memory with the stub symlink path.
	// The tracee is frozen on the seccomp notification, so no race condition.
	if err := writeString(ctx.PID, filenamePtr, stubSymlinkPath); err != nil {
		srvConn.Close()
		// fd 100 is already injected but the execve will be denied by caller.
		// The leaked fd is harmless — the tracee doesn't know about it.
		return fmt.Errorf("overwrite filename: %w", err)
	}

	// Phase 3 (CONTINUE response) is handled by the caller after we return nil.

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
