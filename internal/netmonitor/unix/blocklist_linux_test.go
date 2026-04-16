//go:build linux && cgo

package unix

import (
	"os"
	"runtime"
	"sync"
	"syscall"
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
// unix.Close. Using os.DevNull (the Go constant — "/dev/null" on Linux,
// "NUL" on Windows, etc.) instead of a fabricated integer like 42 ensures
// we never accidentally close an unrelated fd the test process is holding,
// and avoids spurious close-of-unknown-fd warnings from the kernel.
func openDevNullFD(t *testing.T) int {
	t.Helper()
	fd, err := gounix.Open(os.DevNull, gounix.O_RDONLY, 0)
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

// TestAttemptKill_NotifIDInvalidAfterOpen_ENOENT covers the TOCTOU race fix:
// when the target exits between the caller's initial NotifIDValid check and
// attemptKill's own pidfd_open, NotifIDValid reports ENOENT on recheck —
// the canonical "notif id is gone" signal. We must NOT send SIGKILL (the
// pidfd may reference a PID-reused unrelated process) and outcome is
// "killed" because the original trapped caller is, by definition, gone.
func TestAttemptKill_NotifIDInvalidAfterOpen_ENOENT(t *testing.T) {
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
		"ENOENT on recheck means the original target is gone")
	require.False(t, signalCalled,
		"SIGKILL must NOT be sent when notif id is gone — pidfd may reference a reused PID")
}

// TestAttemptKill_NotifIDInvalidAfterOpen_UnexpectedError covers the second
// half of the narrowed recheck semantics: non-ENOENT errors (bad listener
// fd, interrupted ioctl, EINVAL, …) are NOT evidence the target exited, so
// we must refuse to signal AND report "denied" so the audit record reflects
// that we could not deliver the kill — never silently downgrade to "killed".
func TestAttemptKill_NotifIDInvalidAfterOpen_UnexpectedError(t *testing.T) {
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

	restoreValid := swapNotifIDValidFn(t, func(int, uint64) error { return gounix.EINVAL })
	defer restoreValid()

	outcome := attemptKill(0, 0, 4242, "sess-abc", "ptrace")
	require.Equal(t, "denied", outcome,
		"non-ENOENT revalidation error must not be treated as kill success")
	require.False(t, signalCalled,
		"SIGKILL must NOT be sent when revalidation fails for any reason")
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

// TestResolveTGIDFromProc_MainThread verifies that reading /proc/<tid>/status
// for the test process's own main-thread TID returns its own TGID.
func TestResolveTGIDFromProc_MainThread(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mainTID := syscall.Gettid()
	pid := os.Getpid()

	tgid, err := resolveTGIDFromProc(mainTID)
	require.NoError(t, err)
	require.Equal(t, pid, tgid, "main thread TID must map to PID (TGID)")
}

// TestResolveTGIDFromProc_NonMainThread is the regression test for the bug
// flagged in Task 7: seccomp_notif.pid is a TID, and for non-leader threads
// that TID != TGID. If resolveTGIDFromProc mis-reports for a non-leader
// thread, pidfd_open(resolved_tid, 0) would fail with ESRCH/ENOENT and
// SIGKILL would not land under log_and_kill. Spawn a goroutine pinned to its
// own OS thread and verify its TID resolves to the parent TGID.
func TestResolveTGIDFromProc_NonMainThread(t *testing.T) {
	pid := os.Getpid()
	var childTID int
	var wg sync.WaitGroup
	wg.Add(1)
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		childTID = syscall.Gettid()
		close(ready)
		<-done // Keep the thread alive until the test has read /proc.
	}()
	<-ready
	require.NotEqual(t, syscall.Gettid(), childTID, "test goroutine must be on a different OS thread")

	tgid, err := resolveTGIDFromProc(childTID)
	require.NoError(t, err)
	require.Equal(t, pid, tgid,
		"non-leader thread TID %d must resolve to TGID %d (the process PID)", childTID, pid)

	close(done)
	wg.Wait()
}

// TestResolveTGIDFromProc_Nonexistent verifies the "target already gone" path
// surfaces as unix.ESRCH so callers can pattern-match it the same way they do
// pidfd_open ESRCH.
func TestResolveTGIDFromProc_Nonexistent(t *testing.T) {
	// 0x7FFFFFFF is within pid_t range but vastly above any realistic tid —
	// guaranteed not to exist on any Linux host running this test.
	_, err := resolveTGIDFromProc(0x7FFFFFFF)
	require.ErrorIs(t, err, gounix.ESRCH,
		"non-existent TID must surface as ESRCH (not a generic os.ErrNotExist)")
}
