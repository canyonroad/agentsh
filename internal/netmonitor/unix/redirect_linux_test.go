//go:build linux && cgo

package unix

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
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

// A redirect with no target must be refused before anything touches the
// tracee: falling back to the original command would run it server-side,
// outside the tracee's sandbox.
func TestHandleRedirect_NoTargetRefused(t *testing.T) {
	ctx := ExecveContext{PID: 1, Filename: "/usr/local/lib/some-long-directory/probe"}
	for _, r := range []*types.RedirectInfo{nil, {}} {
		err := handleRedirect(-1, 0, ctx, 0, "/s", len(ctx.Filename), r)
		require.ErrorIs(t, err, ErrRedirectNoTarget)
	}
}
