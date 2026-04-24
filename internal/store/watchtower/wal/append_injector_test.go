package wal_test

import (
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// TestSetAppendInjector_CleanFailureDoesNotLatch verifies the test-only
// injector returns a clean error to the caller WITHOUT latching the
// WAL into a fatal state — so a subsequent Append with the injector
// removed succeeds.
func TestSetAppendInjector_CleanFailureDoesNotLatch(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   64 * 1024,
		MaxTotalBytes: 1024 * 1024,
		SyncMode:      wal.SyncImmediate,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	wal.SetAppendInjector(func() error {
		return &wal.AppendError{Class: wal.FailureClean, Op: "append", Err: errors.New("disk full")}
	})
	t.Cleanup(func() { wal.SetAppendInjector(nil) })

	_, err = w.Append(0, 1, []byte("x"))
	if err == nil {
		t.Fatal("expected injected clean failure, got nil")
	}
	if !wal.IsClean(err) {
		t.Errorf("IsClean(err)=false for injected clean failure: %v", err)
	}

	// Remove injector; subsequent Append MUST succeed (no fatal latch).
	wal.SetAppendInjector(nil)
	if _, err := w.Append(0, 1, []byte("y")); err != nil {
		t.Errorf("clean failure latched fatal state: %v", err)
	}
}

// TestSetAppendInjector_AmbiguousFailureLatchesFatal verifies the
// injector's ambiguous path latches w.fatalErr identically to a real
// I/O-ambiguous failure: subsequent Appends surface ErrFatal even
// after the injector is removed.
func TestSetAppendInjector_AmbiguousFailureLatchesFatal(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   64 * 1024,
		MaxTotalBytes: 1024 * 1024,
		SyncMode:      wal.SyncImmediate,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	wal.SetAppendInjector(func() error {
		return &wal.AppendError{Class: wal.FailureAmbiguous, Op: "fsync", Err: errors.New("io error")}
	})
	t.Cleanup(func() { wal.SetAppendInjector(nil) })

	_, err = w.Append(0, 1, []byte("x"))
	if err == nil {
		t.Fatal("expected injected ambiguous failure, got nil")
	}
	if !wal.IsAmbiguous(err) {
		t.Errorf("IsAmbiguous(err)=false for injected ambiguous failure: %v", err)
	}

	// Remove injector — a real Append must STILL fail because the WAL
	// latched fatal on the prior ambiguous return. The surfaced error
	// wraps ErrFatal.
	wal.SetAppendInjector(nil)
	_, err = w.Append(1, 1, []byte("y"))
	if err == nil {
		t.Fatal("expected fatal-latched failure on second Append, got nil")
	}
	if !errors.Is(err, wal.ErrFatal) {
		t.Errorf("errors.Is(err, ErrFatal)=false — ambiguous injector did not latch fatal: %v", err)
	}
}
