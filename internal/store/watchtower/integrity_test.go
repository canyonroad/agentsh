package watchtower_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
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

// TestStore_AppendEvent_GenerationRollResetsPrevHash regresses the
// roborev #5942 High finding: when ev.Chain.Generation differs from
// the chain's current generation, audit.SinkChain.Compute resets
// prev_hash to "" for the rollover record. AppendEvent MUST mirror
// that rule when stamping IntegrityRecord.PrevHash; otherwise the
// first record of the new generation would serialise the prior
// generation's hash and break cross-implementation replay.
func TestStore_AppendEvent_GenerationRollResetsPrevHash(t *testing.T) {
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

	// First event in generation 1 — advances the chain.
	if err := s.AppendEvent(context.Background(), mkEvent(1, 1)); err != nil {
		t.Fatalf("gen=1 AppendEvent: %v", err)
	}

	// Second event in NEW generation 2 — chain rolls; IntegrityRecord
	// MUST serialise PrevHash="" not the gen=1 entry hash.
	if err := s.AppendEvent(context.Background(), mkEvent(2, 2)); err != nil {
		t.Fatalf("gen=2 AppendEvent: %v", err)
	}

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

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 2, Start: 2})
	if err != nil {
		t.Fatalf("wal.NewReader(gen=2): %v", err)
	}
	defer rdr.Close()

	rec, err := rdr.Next()
	if err != nil {
		t.Fatalf("Reader.Next: %v", err)
	}
	ce := &wtpv1.CompactEvent{}
	if err := proto.Unmarshal(rec.Payload, ce); err != nil {
		t.Fatalf("unmarshal gen=2 record: %v", err)
	}
	if got := ce.GetIntegrity().GetPrevHash(); got != "" {
		t.Errorf("IntegrityRecord.PrevHash on gen=2 first record = %q, want \"\" (generation roll)", got)
	}
	if got := ce.GetIntegrity().GetGeneration(); got != 2 {
		t.Errorf("IntegrityRecord.Generation = %d, want 2", got)
	}
}

// TestStore_AppendEvent_ConcurrentCallersDoNotLatchFatal regresses the
// roborev #5935 High concurrency fix and its #5942 Low follow-up:
// many goroutines calling AppendEvent on one Store MUST complete
// without any latching fatal, and the chain MUST advance once per
// successful call. Store.appendMu serialises the Compute → Append →
// Commit transaction so two concurrent calls cannot race on the
// shared prev_hash.
func TestStore_AppendEvent_ConcurrentCallersDoNotLatchFatal(t *testing.T) {
	s := mkIntegrityStore(t)

	const n = 32
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Unique (seq, gen) per call — the Allocator is the
			// composite-store concern; here we simulate by passing
			// distinct values. All goroutines run against one Store
			// so the mutex serialises them.
			errs <- s.AppendEvent(context.Background(), mkEvent(uint64(i+1), 1))
		}(i)
	}
	wg.Wait()
	close(errs)

	var failed int
	for err := range errs {
		if err != nil {
			failed++
			t.Errorf("concurrent AppendEvent: %v", err)
		}
	}
	if failed > 0 {
		t.Fatalf("%d/%d concurrent AppendEvent calls failed — serialisation regression", failed, n)
	}
	if err := s.Err(); err != nil {
		t.Errorf("Store.Err() = %v after concurrent appends; store should not be latched fatal", err)
	}
}

// TestStore_RestartRestoresChainState regresses roborev #5945 High #2:
// after a clean restart, the next AppendEvent MUST chain to the last
// committed record's entry hash — NOT reset prev_hash to "". Without
// the restore path in watchtower.New, the new chain instance would
// begin at prev_hash="" even though the WAL carries earlier records,
// breaking cross-restart integrity continuity.
func TestStore_RestartRestoresChainState(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	newOpts := func() watchtower.Options {
		return watchtower.Options{
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
	}

	// Phase 1: first Store writes seqs 1+2 in gen=1, then Closes.
	s1, err := watchtower.New(context.Background(), newOpts())
	if err != nil {
		t.Fatalf("first watchtower.New: %v", err)
	}
	if err := s1.AppendEvent(context.Background(), mkEvent(1, 1)); err != nil {
		t.Fatalf("seq=1 AppendEvent: %v", err)
	}
	if err := s1.AppendEvent(context.Background(), mkEvent(2, 1)); err != nil {
		t.Fatalf("seq=2 AppendEvent: %v", err)
	}
	prevBeforeClose := s1.PeekPrevHash()
	if prevBeforeClose == "" {
		t.Fatal("pre-close PeekPrevHash is empty; chain did not advance")
	}
	if err := s1.Close(); err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Close: %v", err)
	}

	// Phase 2: re-open the SAME WAL dir with a fresh Store. The
	// chain restore path MUST re-derive the post-commit state from
	// the last WAL record so PeekPrevHash matches what the first
	// Store had at close.
	s2, err := watchtower.New(context.Background(), newOpts())
	if err != nil {
		t.Fatalf("second watchtower.New: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	if got := s2.PeekPrevHash(); got != prevBeforeClose {
		t.Fatalf("post-restart PeekPrevHash = %q, want %q (chain state not restored)", got, prevBeforeClose)
	}

	// Phase 3: append seq=3 in the same generation. Its stored
	// IntegrityRecord.PrevHash MUST equal prevBeforeClose (the
	// restored state), NOT "" — otherwise a verifier replaying the
	// full WAL would see a broken chain link at the restart boundary.
	if err := s2.AppendEvent(context.Background(), mkEvent(3, 1)); err != nil {
		t.Fatalf("seq=3 AppendEvent: %v", err)
	}
	if err := s2.Close(); err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Close: %v", err)
	}

	w, err := wal.Open(wal.Options{
		Dir:            dir,
		SegmentSize:    64 * 1024,
		MaxTotalBytes:  1024 * 1024,
		SyncMode:       wal.SyncImmediate,
		SessionID:      "s",
		KeyFingerprint: "sha256:deadbeef",
	})
	if err != nil {
		t.Fatalf("wal.Open for readback: %v", err)
	}
	defer w.Close()

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 1, Start: 3})
	if err != nil {
		t.Fatalf("wal.NewReader(start=3): %v", err)
	}
	defer rdr.Close()
	rec, err := rdr.Next()
	if err != nil {
		t.Fatalf("Reader.Next(seq=3): %v", err)
	}
	ce := &wtpv1.CompactEvent{}
	if err := proto.Unmarshal(rec.Payload, ce); err != nil {
		t.Fatalf("unmarshal seq=3: %v", err)
	}
	if got := ce.GetIntegrity().GetPrevHash(); got != prevBeforeClose {
		t.Errorf("seq=3 IntegrityRecord.PrevHash = %q, want %q (chain restore failed)", got, prevBeforeClose)
	}
}

// TestStore_TransportSessionInitUsesConfiguredAlgorithm regresses
// roborev #5945 High #1: the transport's SessionInit frame MUST
// advertise the same algorithm / key_fingerprint / context_digest the
// Store chains its WAL records with. The test drives one AppendEvent
// through an hmac-sha512 Store + testserver, then inspects the
// SessionInit the server received for matching identity fields.
func TestStore_TransportSessionInitUsesConfiguredAlgorithm(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	keyFP := "sha512:cafebabe"
	opts := watchtower.Options{
		WALDir:          dir,
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "agent-x",
		SessionID:       "session-y",
		KeyFingerprint:  keyFP,
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("b"), 64), // sha512 wants 64 bytes
		HMACAlgorithm:   "hmac-sha512",
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
	t.Cleanup(func() { _ = s.Close() })

	// Wait up to 2s for the transport to complete its SessionInit
	// handshake with the testserver. The testserver records the
	// accepting stream's SessionInit on WaitForFirstSessionInit.
	init, err := srv.WaitForFirstSessionInit(2 * time.Second)
	if err != nil {
		t.Fatalf("WaitForFirstSessionInit: %v", err)
	}

	if got := init.GetAlgorithm(); got != wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA512 {
		t.Errorf("SessionInit.Algorithm = %v, want HMAC_SHA512 (configured via Options.HMACAlgorithm)", got)
	}
	if got := init.GetKeyFingerprint(); got != keyFP {
		t.Errorf("SessionInit.KeyFingerprint = %q, want %q", got, keyFP)
	}
	wantCtx, err := chain.ComputeContextDigest(chain.SessionContext{
		SessionID:      opts.SessionID,
		AgentID:        opts.AgentID,
		FormatVersion:  uint32(audit.IntegrityFormatVersion),
		Algorithm:      opts.HMACAlgorithm,
		KeyFingerprint: opts.KeyFingerprint,
	})
	if err != nil {
		t.Fatalf("ComputeContextDigest: %v", err)
	}
	if got := init.GetContextDigest(); got != wantCtx {
		t.Errorf("SessionInit.ContextDigest = %q, want %q", got, wantCtx)
	}
}
