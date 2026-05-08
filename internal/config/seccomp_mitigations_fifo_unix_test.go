//go:build linux || darwin

package config

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func createExternalMitigationFIFO(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, unix.Mkfifo(path, 0o600))
}

func startExternalMitigationFIFOWriter(t *testing.T, path string, data []byte) func() {
	t.Helper()

	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)

		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		timeout := time.NewTimer(2 * time.Second)
		defer timeout.Stop()

		for {
			fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
			if err == nil {
				_, _ = unix.Write(fd, data)
				_ = unix.Close(fd)
				return
			}
			if !errors.Is(err, unix.ENXIO) {
				return
			}

			select {
			case <-done:
				return
			case <-ticker.C:
			case <-timeout.C:
				return
			}
		}
	}()

	return func() {
		close(done)
		<-finished
	}
}
