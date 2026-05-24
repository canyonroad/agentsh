package audit

import (
	"errors"
	"testing"
	"time"
)

// retryReplace is the platform-neutral retry wrapper used by the Windows
// replaceFile to ride out transient MoveFileEx failures (ERROR_ACCESS_DENIED /
// ERROR_SHARING_VIOLATION) that occur when another handle briefly holds the
// destination sidecar open. These tests exercise the retry behavior with
// injected fakes so they run on every platform.

func TestRetryReplace_SucceedsAfterTransientErrors(t *testing.T) {
	transientErr := errors.New("Access is denied.")
	transient := func(err error) bool { return errors.Is(err, transientErr) }

	calls, sleeps := 0, 0
	move := func() error {
		calls++
		if calls < 3 {
			return transientErr
		}
		return nil
	}

	err := retryReplace(move, transient, 10, time.Millisecond, func(time.Duration) { sleeps++ })
	if err != nil {
		t.Fatalf("err = %v, want nil after transient retries succeed", err)
	}
	if calls != 3 {
		t.Fatalf("move called %d times, want 3", calls)
	}
	if sleeps != 2 {
		t.Fatalf("slept %d times, want 2 (between the 3 attempts)", sleeps)
	}
}

func TestRetryReplace_NonTransientReturnsImmediately(t *testing.T) {
	permanent := errors.New("not a directory")
	transient := func(error) bool { return false }

	calls := 0
	move := func() error { calls++; return permanent }

	err := retryReplace(move, transient, 10, time.Millisecond, func(time.Duration) {
		t.Fatal("must not sleep/retry on a non-transient error")
	})
	if !errors.Is(err, permanent) {
		t.Fatalf("err = %v, want permanent error returned immediately", err)
	}
	if calls != 1 {
		t.Fatalf("move called %d times, want 1 (no retry on non-transient)", calls)
	}
}

func TestRetryReplace_ExhaustsAttemptsAndReturnsLastError(t *testing.T) {
	transientErr := errors.New("The process cannot access the file because it is being used by another process.")
	transient := func(err error) bool { return errors.Is(err, transientErr) }

	calls := 0
	move := func() error { calls++; return transientErr }

	err := retryReplace(move, transient, 4, time.Millisecond, func(time.Duration) {})
	if !errors.Is(err, transientErr) {
		t.Fatalf("err = %v, want the last transient error after exhausting attempts", err)
	}
	if calls != 4 {
		t.Fatalf("move called %d times, want 4 (maxAttempts)", calls)
	}
}

func TestRetryReplace_SucceedsFirstTry(t *testing.T) {
	calls := 0
	move := func() error { calls++; return nil }

	err := retryReplace(move, func(error) bool { return true }, 10, time.Millisecond, func(time.Duration) {
		t.Fatal("must not sleep when the first attempt succeeds")
	})
	if err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d, want nil and 1 call", err, calls)
	}
}

func TestRetryReplace_NonPositiveAttemptsStillMovesOnce(t *testing.T) {
	// A misconfigured maxAttempts must never silently "succeed" without
	// attempting the move; it should still try exactly once.
	calls := 0
	move := func() error { calls++; return nil }

	if err := retryReplace(move, func(error) bool { return true }, 0, time.Millisecond, func(time.Duration) {}); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if calls != 1 {
		t.Fatalf("move called %d times with maxAttempts=0, want exactly 1", calls)
	}
}
