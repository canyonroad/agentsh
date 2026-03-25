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

// --- READY/GO handshake tests ---

func TestPtraceSync_ReadyGoSuccess(t *testing.T) {
	// Simulate a successful READY/GO handshake over a socketpair.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0]) // wrapper side
	defer unix.Close(fds[1]) // server side

	// Wrapper sends READY byte.
	_, err = unix.Write(fds[0], []byte{'R'})
	require.NoError(t, err)

	// Server reads and validates READY.
	buf := make([]byte, 1)
	n, err := unix.Read(fds[1], buf)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, byte('R'), buf[0])

	// Server sends GO byte.
	_, err = unix.Write(fds[1], []byte{'G'})
	require.NoError(t, err)

	// Wrapper reads and validates GO.
	goBuf := make([]byte, 1)
	err = waitForACK(func(b []byte) (int, error) {
		n, err := unix.Read(fds[0], b)
		if n == 1 {
			goBuf[0] = b[0]
		}
		return n, err
	})
	assert.NoError(t, err)
	assert.Equal(t, byte('G'), goBuf[0])
}

func TestPtraceSync_InvalidReadyByte(t *testing.T) {
	// If wrapper sends wrong READY byte, server should detect it.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	// Wrapper sends wrong byte.
	_, err = unix.Write(fds[0], []byte{'X'})
	require.NoError(t, err)

	// Server reads — byte doesn't match 'R'.
	buf := make([]byte, 1)
	n, err := unix.Read(fds[1], buf)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.NotEqual(t, byte('R'), buf[0], "should detect invalid READY byte")
}

func TestPtraceSync_InvalidGoByte(t *testing.T) {
	// If server sends wrong GO byte, wrapper should detect it.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	// Server sends wrong byte.
	_, err = unix.Write(fds[1], []byte{'X'})
	require.NoError(t, err)

	// Wrapper reads GO byte.
	goBuf := make([]byte, 1)
	err = waitForACK(func(b []byte) (int, error) {
		n, err := unix.Read(fds[0], b)
		if n == 1 {
			goBuf[0] = b[0]
		}
		return n, err
	})
	assert.NoError(t, err, "waitForACK succeeds (reads 1 byte)")
	assert.NotEqual(t, byte('G'), goBuf[0], "should detect invalid GO byte")
}

func TestPtraceSync_GoTimeout(t *testing.T) {
	// If GO byte never arrives and socket has a timeout, read should fail.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	// Set a very short timeout (10ms) on the wrapper side.
	_ = unix.SetsockoptTimeval(fds[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 10000})

	err = waitForACK(fdReader(fds[0]))
	assert.Error(t, err, "should timeout when GO byte never arrives")
}

