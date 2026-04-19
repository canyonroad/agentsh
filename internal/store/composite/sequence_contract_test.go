package composite

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/pkg/types"
)

// chainingFakeSink simulates a second chained sink. It serializes events
// using an intentionally minimal canonical encoding of (id, seq, gen) and
// runs each event through its own SinkChain. The canonical form is just
// enough to produce distinct entry hashes per event without coupling the
// test to types.Event fields whose serialization is not stable across
// changes (Fields, Timestamp, etc.); the test's purpose is to verify the
// (seq, gen) sharing contract, not to mirror a real sink's exhaustive
// canonicalization. Every accepted event also produces a record so tests
// can compare what each sink saw.
type chainingFakeSink struct {
	chain     *audit.SinkChain
	mu        sync.Mutex
	records   []chainRecord
	failNext  error // if set, the next AppendEvent fails clean (no chain advance)
	failFatal bool  // if set, the next AppendEvent fails ambiguously (Fatal)
	failedSeq int64 // sequence at which failure was injected
}

type chainRecord struct {
	Sequence   uint64
	Generation uint32
	EntryHash  string
	PrevHash   string
}

func newChainingFakeSink(t *testing.T, key []byte) *chainingFakeSink {
	t.Helper()
	c, err := audit.NewSinkChain(key, "hmac-sha256")
	if err != nil {
		t.Fatalf("NewSinkChain: %v", err)
	}
	return &chainingFakeSink{chain: c}
}

func (s *chainingFakeSink) AppendEvent(ctx context.Context, ev types.Event) error {
	if ev.Chain == nil {
		return audit.ErrMissingChainState
	}
	seq := ev.Chain.Sequence
	gen := ev.Chain.Generation
	canonical := []byte(`{"id":"` + ev.ID + `","seq":` + strconv.FormatUint(seq, 10) + `,"gen":` + strconv.FormatUint(uint64(gen), 10) + `}`)

	result, err := s.chain.Compute(audit.IntegrityFormatVersion, int64(seq), gen, canonical)
	if err != nil {
		return err
	}

	s.mu.Lock()
	failClean := s.failNext
	failAmbiguous := s.failFatal
	if failClean != nil {
		s.failedSeq = int64(seq)
		s.failNext = nil
	}
	if failAmbiguous {
		s.failedSeq = int64(seq)
		s.failFatal = false
	}
	s.mu.Unlock()

	switch {
	case failClean != nil:
		// Clean failure → do NOT commit, chain unchanged.
		return failClean
	case failAmbiguous:
		// Ambiguous failure → latch fatal.
		s.chain.Fatal(errors.New("ambiguous write"))
		return errors.New("ambiguous write")
	default:
		// Successful durable write — commit. A non-nil error here means the
		// chain has latched fatal (e.g., backwards-generation Commit), which
		// is itself a write divergence and must be surfaced to the caller.
		if err := s.chain.Commit(result); err != nil {
			return err
		}
		s.mu.Lock()
		s.records = append(s.records, chainRecord{
			Sequence:   seq,
			Generation: gen,
			EntryHash:  result.EntryHash(),
			PrevHash:   result.PrevHash(),
		})
		s.mu.Unlock()
		return nil
	}
}

func (s *chainingFakeSink) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return nil, nil
}
func (s *chainingFakeSink) Close() error { return nil }

func newSharedKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, audit.MinKeyLength)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// newDistinctKey returns a key that is byte-different from newSharedKey,
// used to construct heterogeneous chained sinks that must produce
// different entry hashes despite sharing (seq, gen).
func newDistinctKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, audit.MinKeyLength)
	for i := range key {
		key[i] = byte(0xFF - i)
	}
	return key
}

// TestPhase0_CrossSinkSequenceConvergence (Spec verification #1):
// With two chained sinks, every event's (seq, gen) matches between sinks.
// entry_hash matches when both sinks hash identical canonical bytes with
// the same key — but the contract only guarantees (seq, gen) convergence,
// not entry_hash equality in general.
func TestPhase0_CrossSinkSequenceConvergence(t *testing.T) {
	key := newSharedKey(t)
	a := newChainingFakeSink(t, key)
	b := newChainingFakeSink(t, key)

	s := New(a, nil, b)

	const N = 10000
	for i := 0; i < N; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{ID: strconv.Itoa(i)}); err != nil {
			t.Fatalf("AppendEvent #%d: %v", i, err)
		}
	}

	if len(a.records) != N || len(b.records) != N {
		t.Fatalf("record counts: a=%d b=%d want %d", len(a.records), len(b.records), N)
	}
	for i := 0; i < N; i++ {
		ar := a.records[i]
		br := b.records[i]
		if ar.Sequence != br.Sequence || ar.Generation != br.Generation {
			t.Fatalf("record %d: a=(seq=%d,gen=%d) b=(seq=%d,gen=%d)", i, ar.Sequence, ar.Generation, br.Sequence, br.Generation)
		}
		if ar.Sequence != uint64(i) {
			t.Fatalf("record %d: seq=%d want %d", i, ar.Sequence, i)
		}
		// Both sinks hashed identical canonical bytes with the same key, so
		// entry_hash must also match. This is the narrow case where the
		// stronger assertion holds.
		if ar.EntryHash != br.EntryHash {
			t.Fatalf("record %d: entry_hash mismatch a=%q b=%q", i, ar.EntryHash, br.EntryHash)
		}
	}
}

// TestPhase0_HeterogeneousSinks_SequenceConvergence_HashesDiverge
// (Spec verification #1, heterogeneous case):
//
// This is the heterogeneous case. Different HMAC keys MUST produce
// different entry hashes per event, but the shared sequence allocator
// MUST still produce identical (seq, gen) for both sinks. This directly
// verifies the Phase 0 contract claim of "shared sequence, sink-local
// hash chains."
//
// The narrow same-key case in TestPhase0_CrossSinkSequenceConvergence
// is itself a useful invariant (it documents that identical canonical
// inputs to identical chains are reproducible), but it does not exercise
// the design claim that the contract holds across heterogeneous sinks.
// This test does.
func TestPhase0_HeterogeneousSinks_SequenceConvergence_HashesDiverge(t *testing.T) {
	a := newChainingFakeSink(t, newSharedKey(t))
	b := newChainingFakeSink(t, newDistinctKey(t))

	s := New(a, nil, b)

	const N = 1000
	for i := 0; i < N; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{ID: strconv.Itoa(i)}); err != nil {
			t.Fatalf("AppendEvent #%d: %v", i, err)
		}
	}

	if len(a.records) != N || len(b.records) != N {
		t.Fatalf("record counts: a=%d b=%d want %d", len(a.records), len(b.records), N)
	}

	for i := 0; i < N; i++ {
		ar := a.records[i]
		br := b.records[i]

		// SHARED invariant: identical (seq, gen) for both sinks.
		if ar.Sequence != br.Sequence {
			t.Fatalf("record %d: sequence mismatch a=%d b=%d", i, ar.Sequence, br.Sequence)
		}
		if ar.Generation != br.Generation {
			t.Fatalf("record %d: generation mismatch a=%d b=%d", i, ar.Generation, br.Generation)
		}
		if ar.Sequence != uint64(i) {
			t.Fatalf("record %d: seq=%d want %d", i, ar.Sequence, i)
		}
		if ar.Generation != 0 {
			t.Fatalf("record %d: gen=%d want 0", i, ar.Generation)
		}

		// Non-vacuous: entry hashes are populated on both sides.
		if ar.EntryHash == "" {
			t.Fatalf("record %d: a.EntryHash is empty", i)
		}
		if br.EntryHash == "" {
			t.Fatalf("record %d: b.EntryHash is empty", i)
		}

		// SINK-LOCAL invariant: different keys MUST produce different
		// entry hashes for every event.
		if ar.EntryHash == br.EntryHash {
			t.Fatalf("record %d: entry_hash unexpectedly equal under distinct keys: a=%q b=%q",
				i, ar.EntryHash, br.EntryHash)
		}
	}
}

// TestPhase0_GenerationRollConsistency (Spec verification #2):
// After NextGeneration(), both sinks observe the rollover at the same
// event boundary; sequence resets to 0 in both; each sink's prev_hash
// resets to "" independently.
func TestPhase0_GenerationRollConsistency(t *testing.T) {
	key := newSharedKey(t)
	a := newChainingFakeSink(t, key)
	b := newChainingFakeSink(t, key)
	s := New(a, nil, b)

	for i := 0; i < 3; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{ID: strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}

	gen, err := s.NextGeneration()
	if err != nil {
		t.Fatalf("NextGeneration: %v", err)
	}
	if gen != 1 {
		t.Fatalf("NextGeneration() = %d, want 1", gen)
	}

	for i := 0; i < 3; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{ID: strconv.Itoa(i + 100)}); err != nil {
			t.Fatal(err)
		}
	}

	if len(a.records) != 6 || len(b.records) != 6 {
		t.Fatalf("counts: a=%d b=%d", len(a.records), len(b.records))
	}

	// Records 0..2 are gen=0 with monotonic seq; records 3..5 are gen=1
	// with seq starting from 0.
	expected := []struct {
		seq uint64
		gen uint32
	}{
		{0, 0}, {1, 0}, {2, 0},
		{0, 1}, {1, 1}, {2, 1},
	}
	for i, want := range expected {
		got := a.records[i]
		if got.Sequence != want.seq || got.Generation != want.gen {
			t.Errorf("a.records[%d] = (seq=%d, gen=%d), want (seq=%d, gen=%d)", i, got.Sequence, got.Generation, want.seq, want.gen)
		}
		if a.records[i] != b.records[i] {
			t.Errorf("a.records[%d] != b.records[%d]: %+v vs %+v", i, i, a.records[i], b.records[i])
		}
	}

	// First record after rollover MUST have prev_hash == "" — independent
	// per-sink chain reset.
	if a.records[3].PrevHash != "" {
		t.Errorf("a.records[3].PrevHash = %q, want empty", a.records[3].PrevHash)
	}
	if b.records[3].PrevHash != "" {
		t.Errorf("b.records[3].PrevHash = %q, want empty", b.records[3].PrevHash)
	}
}

// TestPhase0_TransactionalRollback_CleanFailure (Spec verification #3a):
// A clean durable-write failure does NOT advance prev_hash. After the
// failure, a successful write of a new event uses the previous (pre-failure)
// prev_hash — proving rollback is correct.
func TestPhase0_TransactionalRollback_CleanFailure(t *testing.T) {
	key := newSharedKey(t)
	a := newChainingFakeSink(t, key)
	s := New(a, nil)

	// Three successful events first.
	for i := 0; i < 3; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{ID: strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	preFailPrev := a.records[2].EntryHash

	// Inject clean failure for next event.
	cleanErr := errors.New("transient disk full")
	a.mu.Lock()
	a.failNext = cleanErr
	a.mu.Unlock()

	err := s.AppendEvent(context.Background(), types.Event{ID: "fail"})
	if !errors.Is(err, cleanErr) {
		t.Fatalf("expected clean error, got %v", err)
	}

	// Sink recorded no new entry on failure.
	if len(a.records) != 3 {
		t.Fatalf("record count after clean failure: %d, want 3 (no advance)", len(a.records))
	}

	// Next successful event continues from the PRE-FAILURE prev_hash, not
	// from a phantom advanced state.
	if err := s.AppendEvent(context.Background(), types.Event{ID: "after-fail"}); err != nil {
		t.Fatal(err)
	}
	if got := a.records[3].PrevHash; got != preFailPrev {
		t.Errorf("after clean failure: prev_hash advanced unexpectedly. got=%q want=%q", got, preFailPrev)
	}
}

// TestPhase0_TransactionalRollback_AmbiguousFailure (Spec verification #3b):
// An ambiguous durable-write failure latches Fatal. Subsequent SinkChain.Compute
// (driven by a subsequent AppendEvent) returns ErrFatalIntegrity.
func TestPhase0_TransactionalRollback_AmbiguousFailure(t *testing.T) {
	key := newSharedKey(t)
	a := newChainingFakeSink(t, key)
	s := New(a, nil)

	if err := s.AppendEvent(context.Background(), types.Event{ID: "0"}); err != nil {
		t.Fatal(err)
	}

	a.mu.Lock()
	a.failFatal = true
	a.mu.Unlock()
	if err := s.AppendEvent(context.Background(), types.Event{ID: "ambig"}); err == nil {
		t.Fatal("expected ambiguous error, got nil")
	}

	// Subsequent AppendEvent now drives Compute, which must return
	// ErrFatalIntegrity from the latched chain.
	err := s.AppendEvent(context.Background(), types.Event{ID: "after-ambig"})
	if !errors.Is(err, audit.ErrFatalIntegrity) {
		t.Fatalf("after ambiguous failure: err = %v, want ErrFatalIntegrity", err)
	}
}

// TestPhase0_MixedSinkOutcome_PrimaryCommitsSecondaryFailsClean
// (Spec verification #4a — composite-level mixed outcome):
//
// Exercises the meeting point of eager sequence consumption, sink-local
// rollback, and append-error surfacing. Primary commits while secondary
// returns a CLEAN failure (no Fatal latch). The composite must:
//
//   - return the secondary's error to the caller (firstErr);
//   - leave the primary's chain advanced (it succeeded);
//   - leave the secondary's chain UN-advanced (clean failure rolled back);
//   - have eagerly consumed the shared sequence anyway (TransportLoss
//     semantics: shared sequence reflects what the system PRODUCED, not
//     what each sink DELIVERED).
//
// The follow-up event then proves that secondary's chain continued from
// its PRE-FAILURE prev_hash (true rollback), while both sinks observe
// the same post-failure sequence (eager-advance is symmetric).
func TestPhase0_MixedSinkOutcome_PrimaryCommitsSecondaryFailsClean(t *testing.T) {
	key := newSharedKey(t)
	a := newChainingFakeSink(t, key)
	b := newChainingFakeSink(t, key)
	s := New(a, nil, b)

	// Two successful events through both sinks.
	for i := 0; i < 2; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{ID: strconv.Itoa(i)}); err != nil {
			t.Fatalf("AppendEvent #%d: %v", i, err)
		}
	}
	if len(a.records) != 2 {
		t.Fatalf("len(a.records) = %d, want 2", len(a.records))
	}
	if len(b.records) != 2 {
		t.Fatalf("len(b.records) = %d, want 2", len(b.records))
	}
	bPreFailEntryHash := b.records[1].EntryHash
	if bPreFailEntryHash == "" {
		t.Fatalf("bPreFailEntryHash is empty; cannot verify rollback against it")
	}

	seqBeforeFailure := s.State().Sequence

	// Inject a clean failure on the secondary's next append.
	cleanErr := errors.New("secondary disk full")
	b.mu.Lock()
	b.failNext = cleanErr
	b.mu.Unlock()

	err := s.AppendEvent(context.Background(), types.Event{ID: "mixed-fail"})
	if !errors.Is(err, cleanErr) {
		t.Fatalf("AppendEvent: err = %v, want errors.Is(err, cleanErr)", err)
	}

	// Primary committed; secondary did NOT.
	if len(a.records) != 3 {
		t.Fatalf("len(a.records) after mixed failure = %d, want 3 (primary committed)", len(a.records))
	}
	if len(b.records) != 2 {
		t.Fatalf("len(b.records) after mixed failure = %d, want 2 (secondary rolled back)", len(b.records))
	}

	// Allocator advanced eagerly even though secondary failed.
	if got := s.State().Sequence; got != seqBeforeFailure+1 {
		t.Fatalf("State().Sequence after mixed failure = %d, want %d (eager advance)",
			got, seqBeforeFailure+1)
	}

	// Recovery event must succeed.
	if err := s.AppendEvent(context.Background(), types.Event{ID: "after-mixed-fail"}); err != nil {
		t.Fatalf("recovery AppendEvent: %v", err)
	}
	if len(a.records) != 4 {
		t.Fatalf("len(a.records) after recovery = %d, want 4", len(a.records))
	}
	if len(b.records) != 3 {
		t.Fatalf("len(b.records) after recovery = %d, want 3", len(b.records))
	}

	// Both sinks observe the SAME post-failure sequence on the recovery event.
	if a.records[3].Sequence != 3 {
		t.Fatalf("a.records[3].Sequence = %d, want 3", a.records[3].Sequence)
	}
	if b.records[2].Sequence != 3 {
		t.Fatalf("b.records[2].Sequence = %d, want 3 (eager-advance leaves both observing the same fresh seq)",
			b.records[2].Sequence)
	}

	// Secondary's chain continued from PRE-FAILURE prev_hash — rollback proof.
	if got := b.records[2].PrevHash; got != bPreFailEntryHash {
		t.Fatalf("b.records[2].PrevHash = %q, want %q (secondary chain must continue from pre-failure prev_hash)",
			got, bPreFailEntryHash)
	}

	// Primary's chain continued normally; never failed.
	if got, want := a.records[3].PrevHash, a.records[2].EntryHash; got != want {
		t.Fatalf("a.records[3].PrevHash = %q, want %q (primary chain unaffected)", got, want)
	}
}

// TestPhase0_MixedSinkOutcome_PrimaryCommitsSecondaryLatchesFatal
// (Spec verification #4b — composite-level mixed outcome with Fatal):
//
// Same composite shape as Test A, but secondary fails AMBIGUOUSLY and
// latches Fatal. The composite must:
//
//   - return the secondary's ambiguous error on the failing call (Fatal
//     is being SET, not yet observed via Compute);
//   - on the NEXT append, surface ErrFatalIntegrity (Compute observes
//     the latched Fatal) while the primary continues to commit normally.
//
// Verifies that a latched secondary does not block the primary's chain
// from making progress — only the secondary's error stream surfaces.
func TestPhase0_MixedSinkOutcome_PrimaryCommitsSecondaryLatchesFatal(t *testing.T) {
	key := newSharedKey(t)
	a := newChainingFakeSink(t, key)
	b := newChainingFakeSink(t, key)
	s := New(a, nil, b)

	// One successful event through both sinks.
	if err := s.AppendEvent(context.Background(), types.Event{ID: "0"}); err != nil {
		t.Fatalf("AppendEvent #0: %v", err)
	}
	if len(a.records) != 1 || len(b.records) != 1 {
		t.Fatalf("initial counts: a=%d b=%d, want 1/1", len(a.records), len(b.records))
	}
	seqBeforeAmbig := s.State().Sequence

	// Inject ambiguous failure on the secondary.
	b.mu.Lock()
	b.failFatal = true
	b.mu.Unlock()

	err := s.AppendEvent(context.Background(), types.Event{ID: "mixed-ambig"})
	if err == nil {
		t.Fatal("expected ambiguous error from mixed append, got nil")
	}

	// Primary committed; secondary did NOT.
	if len(a.records) != 2 {
		t.Fatalf("len(a.records) after mixed-ambig = %d, want 2 (primary committed)", len(a.records))
	}
	if len(b.records) != 1 {
		t.Fatalf("len(b.records) after mixed-ambig = %d, want 1 (secondary latched, no commit)", len(b.records))
	}
	// Allocator advanced.
	if got := s.State().Sequence; got != seqBeforeAmbig+1 {
		t.Fatalf("State().Sequence after mixed-ambig = %d, want %d (eager advance)",
			got, seqBeforeAmbig+1)
	}

	// Next append: secondary's Compute returns ErrFatalIntegrity, which
	// surfaces as the firstErr (primary succeeds, secondary returns
	// ErrFatalIntegrity from Compute).
	err = s.AppendEvent(context.Background(), types.Event{ID: "after-mixed-ambig"})
	if !errors.Is(err, audit.ErrFatalIntegrity) {
		t.Fatalf("AppendEvent after mixed-ambig: err = %v, want ErrFatalIntegrity", err)
	}
	if len(a.records) != 3 {
		t.Fatalf("len(a.records) after follow-up = %d, want 3 (primary continues despite latched secondary)",
			len(a.records))
	}
	if len(b.records) != 1 {
		t.Fatalf("len(b.records) after follow-up = %d, want 1 (secondary remains latched)", len(b.records))
	}

	// Primary's chain unaffected by secondary's Fatal.
	if got, want := a.records[2].PrevHash, a.records[1].EntryHash; got != want {
		t.Fatalf("a.records[2].PrevHash = %q, want %q (primary chain unaffected by secondary Fatal)",
			got, want)
	}
}
