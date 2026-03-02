//go:build linux && cgo

package main

import (
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func fdReader(fd int) func([]byte) (int, error) {
	return func(b []byte) (int, error) { return unix.Read(fd, b) }
}

func TestWaitForACK_Success(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	go func() {
		_, _ = unix.Write(fds[1], []byte{0x01})
	}()

	err = waitForACK(fdReader(fds[0]))
	assert.NoError(t, err)
}

func TestWaitForACK_ClosedSocket(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	unix.Close(fds[1]) // Close writer → EOF on reader

	err = waitForACK(fdReader(fds[0]))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 1 ACK byte, got 0")
}

func TestWaitForACK_BadFD(t *testing.T) {
	// Create and immediately close an FD to guarantee EBADF.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	unix.Close(fds[0])
	unix.Close(fds[1])

	err = waitForACK(fdReader(fds[0]))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read:")
}

func TestWaitForACK_EINTRRetry(t *testing.T) {
	// Simulate one EINTR followed by a successful 1-byte read.
	var calls atomic.Int32
	readFn := func(b []byte) (int, error) {
		if calls.Add(1) == 1 {
			return 0, syscall.EINTR
		}
		b[0] = 0x01
		return 1, nil
	}

	err := waitForACK(readFn)
	assert.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "should have retried once after EINTR")
}
