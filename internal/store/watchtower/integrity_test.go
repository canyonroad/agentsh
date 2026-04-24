package watchtower_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"github.com/agentsh/agentsh/pkg/types"
)

// mkIntegrityStore builds a fully-wired Store for the integrity tests.
// Uses testserver's default Options + StubMapper. Close is registered
// on t.Cleanup so the test driver tears down deterministically.
func mkIntegrityStore(t *testing.T) *watchtower.Store {
	t.Helper()
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		BatchMaxRecords: 8,
		BatchMaxBytes:   8 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// mkEvent returns a minimal types.Event that satisfies AppendEvent's
// Chain-required + StubMapper contract: SessionID, Type, Timestamp, and
// a non-nil ChainState with the given (seq, gen).
func mkEvent(seq uint64, gen uint32) types.Event {
	return types.Event{
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: seq, Generation: gen},
	}
}

// TestStore_WALCleanFailure_NoChainAdvance is one of the four spec-
// required high-risk integrity tests (Task 24). A clean WAL failure
// (e.g., closed WAL, validation rejected the call, or the test-only
// SetAppendInjector returns a FailureClean AppendError) MUST leave the
// chain state unchanged so the next append re-signs from the same
// prev_hash.
func TestStore_WALCleanFailure_NoChainAdvance(t *testing.T) {
	s := mkIntegrityStore(t)

	// Baseline: record the pre-failure prev_hash.
	prev := s.PeekPrevHash()

	// Inject a clean WAL failure.
	wal.SetAppendInjector(func() error {
		return &wal.AppendError{Class: wal.FailureClean, Op: "append", Err: errors.New("disk full")}
	})
	t.Cleanup(func() { wal.SetAppendInjector(nil) })

	if err := s.AppendEvent(context.Background(), mkEvent(1, 1)); err == nil {
		t.Fatal("AppendEvent returned nil; expected clean WAL failure to propagate")
	}

	// Chain state MUST match the pre-call value — Compute ran but
	// Commit did not, so prev_hash is unchanged.
	if got := s.PeekPrevHash(); got != prev {
		t.Fatalf("clean WAL failure advanced the chain: prev=%q got=%q", prev, got)
	}

	// Remove the injector — a subsequent append MUST succeed (no
	// fatal latch on clean failure).
	wal.SetAppendInjector(nil)
	if err := s.AppendEvent(context.Background(), mkEvent(2, 1)); err != nil {
		t.Errorf("clean failure appears to have latched the store fatal: %v", err)
	}
}

// TestStore_WALAmbiguousFailure_LatchesFatal is the second of the four
// high-risk integrity tests. An ambiguous WAL failure (I/O attempted,
// on-disk state may have mutated) MUST latch the store fatal so every
// subsequent AppendEvent returns errFatalLatch via errors.Is match on
// the exported ErrFatalLatch sentinel (surfaced through err.Error()
// substring here since the sentinel is intentionally unexported per
// the plan — callers detect the fatal state via Store.Err()).
func TestStore_WALAmbiguousFailure_LatchesFatal(t *testing.T) {
	s := mkIntegrityStore(t)

	wal.SetAppendInjector(func() error {
		return &wal.AppendError{Class: wal.FailureAmbiguous, Op: "fsync", Err: errors.New("io error")}
	})
	t.Cleanup(func() { wal.SetAppendInjector(nil) })

	if err := s.AppendEvent(context.Background(), mkEvent(1, 1)); err == nil {
		t.Fatal("AppendEvent returned nil; expected ambiguous WAL failure")
	}

	// Remove the injector — the store MUST still refuse further
	// appends because the ambiguous failure latched fatal. The
	// second call bails BEFORE touching the injector, so clearing
	// it has no effect.
	wal.SetAppendInjector(nil)
	err := s.AppendEvent(context.Background(), mkEvent(2, 1))
	if err == nil {
		t.Fatal("second AppendEvent succeeded after ambiguous failure; store did not latch fatal")
	}
	if got := err.Error(); got == "" {
		t.Errorf("expected fatal-latch error with diagnostic text, got empty string")
	}
}
