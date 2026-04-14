//go:build linux && cgo

package unix

import (
	"errors"
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// TestLoadWithRetryOnWaitKillFailure_RetriesOnWaitKillFailure verifies that
// when the first Load() call fails with WaitKill set, the helper calls
// SetWaitKill(false) and retries — reproducing the fallback path used for
// custom kernels that report >=6.0 but reject WAIT_KILLABLE_RECV.
func TestLoadWithRetryOnWaitKillFailure_RetriesOnWaitKillFailure(t *testing.T) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	if err := filt.SetWaitKill(true); err != nil {
		t.Skipf("SetWaitKill unsupported on this libseccomp build: %v", err)
	}

	calls := 0
	loadFn := func() error {
		calls++
		if calls == 1 {
			return errors.New("simulated: kernel rejected WAIT_KILLABLE_RECV")
		}
		return nil
	}

	if err := loadWithRetryOnWaitKillFailure(filt, true, loadFn); err != nil {
		t.Fatalf("loadWithRetryOnWaitKillFailure: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 load calls (initial + retry), got %d", calls)
	}

	got, err := filt.GetWaitKill()
	if err != nil {
		t.Fatalf("GetWaitKill: %v", err)
	}
	if got {
		t.Fatalf("expected WaitKill to be cleared after retry, got true")
	}
}

// TestLoadWithRetryOnWaitKillFailure_NoRetryWhenWaitKillNotSet verifies that
// a failure without WaitKill set surfaces the original error — no retry
// attempted, no silent recovery.
func TestLoadWithRetryOnWaitKillFailure_NoRetryWhenWaitKillNotSet(t *testing.T) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	origErr := errors.New("simulated: transient load error")
	calls := 0
	loadFn := func() error {
		calls++
		return origErr
	}

	err = loadWithRetryOnWaitKillFailure(filt, false, loadFn)
	if !errors.Is(err, origErr) {
		t.Fatalf("expected original error to propagate, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 load call, got %d", calls)
	}
}

// TestLoadWithRetryOnWaitKillFailure_SuccessFirstCall verifies that when
// the first load succeeds, no retry is attempted and no WaitKill state
// change happens.
func TestLoadWithRetryOnWaitKillFailure_SuccessFirstCall(t *testing.T) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	if err := filt.SetWaitKill(true); err != nil {
		t.Skipf("SetWaitKill unsupported on this libseccomp build: %v", err)
	}

	calls := 0
	loadFn := func() error {
		calls++
		return nil
	}

	if err := loadWithRetryOnWaitKillFailure(filt, true, loadFn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 load call (no retry on success), got %d", calls)
	}

	got, err := filt.GetWaitKill()
	if err != nil {
		t.Fatalf("GetWaitKill: %v", err)
	}
	if !got {
		t.Fatalf("expected WaitKill to remain true after successful load, got false")
	}
}
