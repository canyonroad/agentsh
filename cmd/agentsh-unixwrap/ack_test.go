//go:build linux && cgo

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestWaitForACK_Success(t *testing.T) {
	// Create a socketpair to simulate the CLI<->wrapper handshake.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	// Writer sends 1-byte ACK.
	go func() {
		_, _ = unix.Write(fds[1], []byte{0x01})
	}()

	err = waitForACK(fds[0])
	assert.NoError(t, err)
}

func TestWaitForACK_ClosedSocket(t *testing.T) {
	// Create a socketpair, close the writer immediately → EOF.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	unix.Close(fds[1]) // Close writer side

	err = waitForACK(fds[0])
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 1 ACK byte, got 0")
}

func TestWaitForACK_BadFD(t *testing.T) {
	err := waitForACK(99999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read:")
}
