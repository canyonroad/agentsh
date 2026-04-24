package watchtower_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
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

	// Roborev #5935 Medium: Err() MUST surface the stored cause once
	// the store is latched fatal, without waiting for Close / run-loop
	// exit. Operators polling the health surface should see the
	// original I/O error, not a nil result.
	if gotErr := s.Err(); gotErr == nil {
		t.Error("Store.Err() returned nil after fatal latch — operators cannot discover the cause pre-Close")
	}
}

// TestStore_AppendEvent_PopulatesIntegrityRecord is the happy-path
// acceptance for the roborev #5939 High fix. It drives AppendEvent
// through a successful Compute → Append → Commit and then reads the
// WAL segment back to verify that the stored IntegrityRecord is the
// WTP-spec form:
//
//   - event_hash equals sha256(deterministic-marshal of the
//     CompactEvent WITHOUT Integrity set) — NOT the sink's HMAC chain
//     output.
//   - context_digest equals chain.ComputeContextDigest for the
//     Options-bound SessionContext — NOT empty.
//   - prev_hash equals the sink's prev_hash BEFORE this append; for
//     the genesis event it is the empty string.
//   - key_fingerprint mirrors Options.KeyFingerprint.
//   - sequence / generation mirror the ev.Chain values.
//   - format_version equals audit.IntegrityFormatVersion.
//
// Close is called before the WAL reader opens so all in-flight writes
// have been fsync'd; the WAL's re-open path then exposes the sealed +
// in-progress segments for iteration.
func TestStore_AppendEvent_PopulatesIntegrityRecord(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	opts := watchtower.Options{
		WALDir:          dir,
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:deadbeef",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 8,
		BatchMaxBytes:   8 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
	}
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}

	ev := mkEvent(1, 7)
	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	// Close before opening the WAL reader so the in-progress segment
	// is flushed to disk and re-Open picks it up without racing the
	// background run loop.
	if err := s.Close(); err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close: %v", err)
	}

	w, err := wal.Open(wal.Options{
		Dir:            dir,
		SegmentSize:    64 * 1024,
		MaxTotalBytes:  1024 * 1024,
		SyncMode:       wal.SyncImmediate,
		SessionID:      opts.SessionID,
		KeyFingerprint: opts.KeyFingerprint,
	})
	if err != nil {
		t.Fatalf("wal.Open for readback: %v", err)
	}
	defer w.Close()

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 7, Start: 1})
	if err != nil {
		t.Fatalf("wal.NewReader: %v", err)
	}
	defer rdr.Close()

	rec, err := rdr.Next()
	if err != nil {
		t.Fatalf("Reader.Next: %v", err)
	}

	ce := &wtpv1.CompactEvent{}
	if err := proto.Unmarshal(rec.Payload, ce); err != nil {
		t.Fatalf("unmarshal stored CompactEvent: %v", err)
	}
	ir := ce.GetIntegrity()
	if ir == nil {
		t.Fatal("stored CompactEvent missing Integrity")
	}

	if got := ir.GetFormatVersion(); got != uint32(audit.IntegrityFormatVersion) {
		t.Errorf("IntegrityRecord.FormatVersion = %d, want %d", got, audit.IntegrityFormatVersion)
	}
	if got := ir.GetSequence(); got != 1 {
		t.Errorf("IntegrityRecord.Sequence = %d, want 1", got)
	}
	if got := ir.GetGeneration(); got != 7 {
		t.Errorf("IntegrityRecord.Generation = %d, want 7", got)
	}
	if got := ir.GetPrevHash(); got != "" {
		t.Errorf("IntegrityRecord.PrevHash = %q, want \"\" (genesis event)", got)
	}
	if got := ir.GetKeyFingerprint(); got != opts.KeyFingerprint {
		t.Errorf("IntegrityRecord.KeyFingerprint = %q, want %q", got, opts.KeyFingerprint)
	}

	// context_digest MUST match chain.ComputeContextDigest for the
	// Options-bound SessionContext. Empty would mean we regressed
	// roborev #5939 Medium.
	wantCtx, err := chain.ComputeContextDigest(chain.SessionContext{
		SessionID:      opts.SessionID,
		AgentID:        opts.AgentID,
		FormatVersion:  uint32(audit.IntegrityFormatVersion),
		Algorithm:      opts.HMACAlgorithm,
		KeyFingerprint: opts.KeyFingerprint,
	})
	if err != nil {
		t.Fatalf("chain.ComputeContextDigest: %v", err)
	}
	if got := ir.GetContextDigest(); got != wantCtx {
		t.Errorf("IntegrityRecord.ContextDigest = %q, want %q", got, wantCtx)
	}
	if ir.GetContextDigest() == "" {
		t.Error("IntegrityRecord.ContextDigest is empty — roborev #5939 Medium regressed")
	}

	// event_hash MUST equal sha256(deterministic marshal of the
	// CompactEvent WITHOUT Integrity) — the canonical form every
	// verifier will arrive at. Reconstruct by clearing Integrity and
	// re-marshaling deterministically.
	ceNoIntegrity := proto.Clone(ce).(*wtpv1.CompactEvent)
	ceNoIntegrity.Integrity = nil
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(ceNoIntegrity)
	if err != nil {
		t.Fatalf("marshal canonical event: %v", err)
	}
	sum := sha256.Sum256(canonical)
	wantEventHash := hex.EncodeToString(sum[:])
	if got := ir.GetEventHash(); got != wantEventHash {
		t.Errorf("IntegrityRecord.EventHash = %q, want %q — event_hash is not sha256(canonical event)", got, wantEventHash)
	}
}
