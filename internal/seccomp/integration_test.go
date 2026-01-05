//go:build linux && cgo && integration

package seccomp_test

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSeccompBlocksPtrace(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for seccomp filter installation")
	}

	// Build the wrapper
	cmd := exec.Command("go", "build", "-o", "/tmp/test-unixwrap", "./cmd/agentsh-unixwrap")
	cmd.Dir = "../../.."
	require.NoError(t, cmd.Run())
	defer os.Remove("/tmp/test-unixwrap")

	// Create socketpair for notify fd
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])

	// Wrap fds[1] in os.File so child process inherits it; closing happens via the file.
	notifyFile := os.NewFile(uintptr(fds[1]), "notify")
	defer notifyFile.Close()

	// Run wrapper with ptrace blocked
	wrapCmd := exec.Command("/tmp/test-unixwrap", "--", "/bin/strace", "-p", "1")
	wrapCmd.Env = append(os.Environ(),
		"AGENTSH_NOTIFY_SOCK_FD=3",
		`AGENTSH_SECCOMP_CONFIG={"unix_socket_enabled":true,"blocked_syscalls":["ptrace"]}`,
	)
	wrapCmd.ExtraFiles = []*os.File{notifyFile}

	err = wrapCmd.Run()
	require.Error(t, err)

	// Check that it was killed by SIGSYS (seccomp signal)
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok, "expected ExitError")
	status := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, status.Signaled(), "expected process to be signaled")
	// SIGSYS is sent when seccomp blocks a syscall
	require.Equal(t, syscall.Signal(unix.SIGSYS), status.Signal(), "expected SIGSYS from seccomp")
}
