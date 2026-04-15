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

// swapPidfdSeams replaces the pidfd_open / pidfd_send_signal / notif-id-valid
// seams and returns a restore function. Callers defer restore immediately.
// The notifIDValidFn seam defaults to "always valid" so existing call sites
// that don't exercise the race need not touch it explicitly.
func swapPidfdSeams(
	t *testing.T,
	openFn func(pid int) (int, error),
	sendFn func(pidfd int, sig gounix.Signal) error,
) func() {
	t.Helper()
	origOpen := pidfdOpenFn
	origSend := pidfdSendSignalFn
	origValid := notifIDValidFn
	pidfdOpenFn = openFn
	pidfdSendSignalFn = sendFn
	notifIDValidFn = func(int, uint64) error { return nil }
	return func() {
		pidfdOpenFn = origOpen
		pidfdSendSignalFn = origSend
		notifIDValidFn = origValid
	}
}

// swapNotifIDValidFn installs a NotifIDValid stub without touching the pidfd
// seams; used by the race-coverage test. Defer the returned restore.
func swapNotifIDValidFn(t *testing.T, fn func(int, uint64) error) func() {
	t.Helper()
	orig := notifIDValidFn
	notifIDValidFn = fn
	return func() { notifIDValidFn = orig }
}

// openDevNullFD returns a scratch fd suitable for attemptKill's deferred
// unix.Close. Using /dev/null (instead of a fabricated integer like 42)
// ensures we never accidentally close an unrelated fd the test process is
// holding, and avoids spurious close-of-unknown-fd warnings from the kernel.
func openDevNullFD(t *testing.T) int {
	t.Helper()
	fd, err := gounix.Open("/dev/null", gounix.O_RDONLY, 0)
	require.NoError(t, err)
	return fd
}

func TestAttemptKill_Success(t *testing.T) {
	fd := openDevNullFD(t)

	var capturedFD int
	var capturedSig gounix.Signal
	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return fd, nil },
		func(pidfd int, sig gounix.Signal) error {
			capturedFD = pidfd
			capturedSig = sig
			return nil
		},
	)
	defer restore()

	outcome := attemptKill(0, 0, 5555, "sess-abc", "ptrace")
	require.Equal(t, "killed", outcome)
	require.Equal(t, fd, capturedFD)
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

	outcome := attemptKill(0, 0, 4242, "sess-abc", "ptrace")
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

	outcome := attemptKill(0, 0, 4242, "sess-abc", "ptrace")
	require.Equal(t, "denied", outcome)
}

func TestAttemptKill_PidfdSendSignalESRCH(t *testing.T) {
	fd := openDevNullFD(t)

	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return fd, nil },
		func(pidfd int, sig gounix.Signal) error { return gounix.ESRCH },
	)
	defer restore()

	outcome := attemptKill(0, 0, 4242, "sess-abc", "ptrace")
	require.Equal(t, "killed", outcome)
}

func TestAttemptKill_PidfdSendSignalEINVAL(t *testing.T) {
	fd := openDevNullFD(t)

	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return fd, nil },
		func(pidfd int, sig gounix.Signal) error { return gounix.EINVAL },
	)
	defer restore()

	outcome := attemptKill(0, 0, 4242, "sess-abc", "ptrace")
	require.Equal(t, "denied", outcome)
}

// TestAttemptKill_NotifIDInvalidAfterOpen covers the TOCTOU race fix: when the
// target exits between the caller's initial NotifIDValid check and
// attemptKill's own pidfd_open, the pidfd may now reference a PID-reused
// unrelated process. Re-checking NotifIDValid *after* pidfd_open closes the
// race — if it fails, we must NOT send SIGKILL, and outcome is still
// "killed" because the original trapped caller is, by definition, gone.
func TestAttemptKill_NotifIDInvalidAfterOpen(t *testing.T) {
	fd := openDevNullFD(t)

	signalCalled := false
	restore := swapPidfdSeams(t,
		func(pid int) (int, error) { return fd, nil },
		func(pidfd int, sig gounix.Signal) error {
			signalCalled = true
			return nil
		},
	)
	defer restore()

	// Override the default "always valid" stub installed by swapPidfdSeams
	// so NotifIDValid returns ENOENT on the recheck.
	restoreValid := swapNotifIDValidFn(t, func(int, uint64) error { return gounix.ENOENT })
	defer restoreValid()

	outcome := attemptKill(0, 0, 4242, "sess-abc", "ptrace")
	require.Equal(t, "killed", outcome,
		"notif id invalid after open means the original target is gone")
	require.False(t, signalCalled,
		"SIGKILL must NOT be sent when notif id is invalid — pidfd may reference a reused PID")
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
