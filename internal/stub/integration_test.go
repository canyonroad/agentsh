//go:build integration

package stub

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_ExitCodeFidelity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cmd      string
		args     []string
		wantCode int
	}{
		{"exit-0", "/bin/sh", []string{"sh", "-c", "exit 0"}, 0},
		{"exit-1", "/bin/sh", []string{"sh", "-c", "exit 1"}, 1},
		{"exit-42", "/bin/sh", []string{"sh", "-c", "exit 42"}, 42},
		{"exit-127", "/bin/sh", []string{"sh", "-c", "exit 127"}, 127},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srvConn, stubConn := net.Pipe()
			defer srvConn.Close()
			defer stubConn.Close()

			go func() {
				ServeStubConnection(context.Background(), srvConn, ServeConfig{
					Command: tc.cmd,
					Args:    tc.args,
				})
			}()

			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCode, exitCode)
		})
	}
}

func TestIntegration_StdoutStderrOrdering(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	go func() {
		ServeStubConnection(context.Background(), srvConn, ServeConfig{
			Command: "/bin/sh",
			Args:    []string{"sh", "-c", "echo stdout1; echo stderr1 >&2; echo stdout2"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout.String(), "stdout1")
	assert.Contains(t, stdout.String(), "stdout2")
	assert.Contains(t, stderr.String(), "stderr1")
}

func TestIntegration_LargeOutput(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	// Generate ~1MB of output
	go func() {
		ServeStubConnection(context.Background(), srvConn, ServeConfig{
			Command: "/bin/sh",
			Args:    []string{"sh", "-c", "dd if=/dev/zero bs=1024 count=1024 2>/dev/null | base64"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Greater(t, stdout.Len(), 1000000, "should have received ~1MB of output")
}

func TestIntegration_Timeout(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		ServeStubConnection(ctx, srvConn, ServeConfig{
			Command: "/bin/sleep",
			Args:    []string{"sleep", "60"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, _ := RunProxy(stubConn, nil, stdout, stderr)
	assert.NotEqual(t, 0, exitCode, "timed-out command should have non-zero exit")
}

func TestIntegration_StdinForwarding(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	go func() {
		ServeStubConnection(context.Background(), srvConn, ServeConfig{
			Command: "/bin/sh",
			Args:    []string{"sh", "-c", "read line; echo got: $line"},
		})
	}()

	stdin := bytes.NewReader([]byte("hello\n"))
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, stdin, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout.String(), "got: hello")
}
