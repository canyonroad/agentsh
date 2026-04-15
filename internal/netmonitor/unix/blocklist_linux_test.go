//go:build linux && cgo

package unix

import (
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/stretchr/testify/require"
	gounix "golang.org/x/sys/unix"
)

// TestBuildSeccompBlockedEvent verifies that the event builder produces the
// expected typed fields and Fields map keys. Task 7 will key assertions off
// these field names, so they must remain stable.
func TestBuildSeccompBlockedEvent(t *testing.T) {
	ev := buildSeccompBlockedEvent(
		"sess-xyz",
		1234,
		"ptrace",
		uint32(101),
		seccompkg.OnBlockLogAndKill,
		"killed",
	)

	require.Equal(t, "seccomp_blocked", ev.Type)
	require.Equal(t, "sess-xyz", ev.SessionID)
	require.Equal(t, 1234, ev.PID)
	require.Equal(t, "seccomp", ev.Source)
	require.NotEmpty(t, ev.ID)
	require.False(t, ev.Timestamp.IsZero())
	require.NotNil(t, ev.Fields)
	require.Equal(t, "ptrace", ev.Fields["syscall"])
	require.Equal(t, uint32(101), ev.Fields["syscall_nr"])
	require.Equal(t, "log_and_kill", ev.Fields["action"])
	require.Equal(t, "killed", ev.Fields["outcome"])
	arch, ok := ev.Fields["arch"].(string)
	require.True(t, ok, "arch should be a string")
	require.NotEmpty(t, arch, "arch should be non-empty")
}

// swapPidfdSeams replaces the pidfd_open / pidfd_send_signal seams and
// returns a restore function. Callers defer restore immediately.
func swapPidfdSeams(
	t *testing.T,
	openFn func(pid int) (int, error),
	sendFn func(pidfd int, sig gounix.Signal) error,
) func() {
	t.Helper()
	origOpen := pidfdOpenFn
	origSend := pidfdSendSignalFn
	pidfdOpenFn = openFn
	pidfdSendSignalFn = sendFn
	return func() {
		pidfdOpenFn = origOpen
		pidfdSendSignalFn = origSend
	}
}

func TestAttemptKill_Success(t *testing.T) {
	var capturedFD int
	var capturedSig gounix.Signal
	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return 42, nil },
		func(pidfd int, sig gounix.Signal) error {
			capturedFD = pidfd
			capturedSig = sig
			return nil
		},
	)
	defer restore()

	outcome := attemptKill(5555, "sess-abc", "ptrace")
	require.Equal(t, "killed", outcome)
	require.Equal(t, 42, capturedFD)
	require.Equal(t, gounix.SIGKILL, capturedSig)
}

func TestAttemptKill_PidfdOpenESRCH(t *testing.T) {
	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return -1, gounix.ESRCH },
		func(pidfd int, sig gounix.Signal) error {
			t.Fatalf("pidfdSendSignalFn must not be called when open returned ESRCH")
			return nil
		},
	)
	defer restore()

	outcome := attemptKill(4242, "sess-abc", "ptrace")
	require.Equal(t, "killed", outcome)
}

func TestAttemptKill_PidfdOpenEPERM(t *testing.T) {
	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return -1, gounix.EPERM },
		func(pidfd int, sig gounix.Signal) error {
			t.Fatalf("pidfdSendSignalFn must not be called when open returned EPERM")
			return nil
		},
	)
	defer restore()

	outcome := attemptKill(4242, "sess-abc", "ptrace")
	require.Equal(t, "denied", outcome)
}

func TestAttemptKill_PidfdSendSignalESRCH(t *testing.T) {
	// Use a /dev/null fd so that the deferred unix.Close(pidfd) in attemptKill
	// has a real kernel fd to close (won't log warnings).
	f, err := gounix.Open("/dev/null", gounix.O_RDONLY, 0)
	require.NoError(t, err)

	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return f, nil },
		func(pidfd int, sig gounix.Signal) error { return gounix.ESRCH },
	)
	defer restore()

	outcome := attemptKill(4242, "sess-abc", "ptrace")
	require.Equal(t, "killed", outcome)
}

func TestAttemptKill_PidfdSendSignalEINVAL(t *testing.T) {
	f, err := gounix.Open("/dev/null", gounix.O_RDONLY, 0)
	require.NoError(t, err)

	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return f, nil },
		func(pidfd int, sig gounix.Signal) error { return gounix.EINVAL },
	)
	defer restore()

	outcome := attemptKill(4242, "sess-abc", "ptrace")
	require.Equal(t, "denied", outcome)
}

func TestBlockListConfig_IsBlockListed(t *testing.T) {
	// nil receiver returns false.
	var nilCfg *BlockListConfig
	act, ok := nilCfg.IsBlockListed(42)
	require.False(t, ok)
	require.Equal(t, seccompkg.OnBlockAction(""), act)

	// Empty map returns false.
	empty := &BlockListConfig{ActionByNr: map[uint32]seccompkg.OnBlockAction{}}
	act, ok = empty.IsBlockListed(42)
	require.False(t, ok)
	require.Equal(t, seccompkg.OnBlockAction(""), act)

	// Populated map returns (action, true) for matching nr.
	cfg := &BlockListConfig{
		ActionByNr: map[uint32]seccompkg.OnBlockAction{
			101: seccompkg.OnBlockLogAndKill,
			202: seccompkg.OnBlockLog,
		},
	}
	act, ok = cfg.IsBlockListed(101)
	require.True(t, ok)
	require.Equal(t, seccompkg.OnBlockLogAndKill, act)

	act, ok = cfg.IsBlockListed(202)
	require.True(t, ok)
	require.Equal(t, seccompkg.OnBlockLog, act)

	// Non-matching nr returns (_, false).
	_, ok = cfg.IsBlockListed(999)
	require.False(t, ok)
}
