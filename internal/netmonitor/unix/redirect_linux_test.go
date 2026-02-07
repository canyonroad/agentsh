//go:build linux && cgo

package unix

import (
	"testing"

	"github.com/stretchr/testify/require"
	sysunix "golang.org/x/sys/unix"
)

func TestCreateStubSocketPair(t *testing.T) {
	stubFD, srvConn, err := createStubSocketPair()
	require.NoError(t, err)
	defer srvConn.Close()

	// Verify stub fd is valid by trying to close it
	require.True(t, stubFD >= 0, "stub fd should be non-negative")

	// Clean up
	sysunix.Close(stubFD)
}

func TestSetStubBinaryPath(t *testing.T) {
	SetStubBinaryPath("/usr/local/bin/agentsh-stub")
	require.Equal(t, "/usr/local/bin/agentsh-stub", stubBinaryPath)
}
