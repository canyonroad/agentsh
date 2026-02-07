package stub

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerHandler_EchoCommand(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeStubConnection(context.Background(), srvConn, ServeConfig{
			Command: "/bin/echo",
			Args:    []string{"echo", "hello from server"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "hello from server\n", stdout.String())

	require.NoError(t, <-errCh)
}

func TestServerHandler_NonZeroExit(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	go func() {
		ServeStubConnection(context.Background(), srvConn, ServeConfig{
			Command: "/bin/sh",
			Args:    []string{"sh", "-c", "exit 42"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 42, exitCode)
}

func TestServerHandler_StderrCapture(t *testing.T) {
	srvConn, stubConn := net.Pipe()
	defer srvConn.Close()
	defer stubConn.Close()

	go func() {
		ServeStubConnection(context.Background(), srvConn, ServeConfig{
			Command: "/bin/sh",
			Args:    []string{"sh", "-c", "echo err >&2; echo out"},
		})
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exitCode, err := RunProxy(stubConn, nil, stdout, stderr)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout.String(), "out")
	assert.Contains(t, stderr.String(), "err")
}
