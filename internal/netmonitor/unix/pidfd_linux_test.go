//go:build linux

package unix

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	gounix "golang.org/x/sys/unix"
)

func TestPidfdOpen_Self(t *testing.T) {
	fd, err := pidfdOpen(os.Getpid())
	require.NoError(t, err)
	require.Greater(t, fd, 0)
	t.Cleanup(func() { _ = gounix.Close(fd) })
}

func TestPidfdOpen_Nonexistent(t *testing.T) {
	_, err := pidfdOpen(0x7FFFFFFF)
	require.ErrorIs(t, err, gounix.ESRCH)
}

func TestPidfdSendSignal_SelfSIGURG(t *testing.T) {
	fd, err := pidfdOpen(os.Getpid())
	require.NoError(t, err)
	defer gounix.Close(fd)

	err = pidfdSendSignal(fd, gounix.SIGURG)
	require.NoError(t, err)
}

func TestPidfdFnIndirection(t *testing.T) {
	require.NotNil(t, pidfdOpenFn)
	require.NotNil(t, pidfdSendSignalFn)
}
