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

// TestSetAppendInjector_RunsAfterOversizedPayloadCheck regresses the
// roborev #5935 Medium finding: the injector MUST fire AFTER the
// clean-validation preflight (closed / fatal-latched / oversized-
// payload). Without this ordering, an installed injector could
// convert what should be a clean validation rejection into an
// injected ambiguous latch — a WAL state the real code path cannot
// reach.
func TestSetAppendInjector_RunsAfterOversizedPayloadCheck(t *testing.T) {
	dir := t.TempDir()
	// Smallest legal segment that still passes Open's size check;
	// recordOverhead (20 bytes) + header (16) = 36, so anything > 36
	// is rejected up-front as oversized.
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   128,
		MaxTotalBytes: 1024,
		SyncMode:      wal.SyncImmediate,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	injectorCalled := false
	wal.SetAppendInjector(func() error {
		injectorCalled = true
		return &wal.AppendError{Class: wal.FailureAmbiguous, Op: "fsync", Err: errors.New("should not fire")}
	})
	t.Cleanup(func() { wal.SetAppendInjector(nil) })

	// Payload > segment budget — preflight MUST reject cleanly before
	// the injector runs. Use 256 bytes so the check fails regardless
	// of alignment nuance.
	_, err = w.Append(0, 1, make([]byte, 256))
	if err == nil {
		t.Fatal("expected oversized-payload clean failure, got nil")
	}
	if !wal.IsClean(err) {
		t.Errorf("expected clean failure, got %v (IsClean=false) — injector likely ran before preflight", err)
	}
	if injectorCalled {
		t.Error("injector ran before the oversized-payload preflight check — ordering regression")
	}

	// Remove injector and append a legal record — it MUST succeed
	// (no fatal latch because the injector never fired).
	wal.SetAppendInjector(nil)
	if _, err := w.Append(0, 1, []byte("ok")); err != nil {
		t.Errorf("legal append after oversized rejection: got %v — store latched despite preflight-only failure", err)
	}
}

// TestSetAppendInjector_NilReturnContinuesToRealAppend locks in the
// narrowed injector contract (roborev #5935 Medium): a nil return
// from the injector does NOT short-circuit Append; the real write
// path runs and the record lands on disk.
func TestSetAppendInjector_NilReturnContinuesToRealAppend(t *testing.T) {
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

	injectorCalls := 0
	wal.SetAppendInjector(func() error {
		injectorCalls++
		return nil // signal "continue with real append"
	})
	t.Cleanup(func() { wal.SetAppendInjector(nil) })

	if _, err := w.Append(5, 1, []byte("payload")); err != nil {
		t.Fatalf("Append with nil-returning injector: got %v, want success", err)
	}
	if injectorCalls != 1 {
		t.Errorf("injector call count = %d, want 1 (must still be consulted even when it returns nil)", injectorCalls)
	}
	if got := w.HighWatermark(); got != 5 {
		t.Errorf("HighWatermark after nil-injector Append = %d, want 5 — real append path did not run", got)
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
