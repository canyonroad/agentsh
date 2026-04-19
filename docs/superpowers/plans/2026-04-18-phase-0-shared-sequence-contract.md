# Phase 0 — Shared Sequence Allocator + Sink-Local Chain Contract — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the integrity layer so the composite store allocates one shared `(sequence, generation)` tuple per event, and each chained sink computes its own sink-local HMAC via a transactional Compute → durable-write → Commit/Fatal protocol. Single-sink installations (today's bare JSONL primary) keep working with byte-identical output.

**Architecture:** Two new types in `internal/audit` — `SequenceAllocator` (composite-owned, no hash state) and `SinkChain` (per-sink, owns prev_hash). The legacy `IntegrityChain.Wrap()` is preserved verbatim by composing the two new types internally. A typed `Chain *ChainState` field on `pkg/types.Event` (with `json:"-"`) carries the allocated tuple from composite to sinks; the JSON tag prevents leakage into any user-visible serializer at the type level. The composite store gains an allocator and stamps `ev.Chain` before fanout. Three verification tests assert cross-sink convergence, generation roll consistency, and transactional rollback.

**Tech Stack:** Go 1.x stdlib only. Uses `sync.Mutex`, `crypto/hmac`, `crypto/sha256`, `crypto/sha512`, `errors`, `math`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md`

**Naming note:** Spec calls the SinkChain state struct `ChainState`, but `audit.ChainState` already exists for `IntegrityChain.State()` and is referenced from `internal/store/integrity_startup_test.go`, `internal/store/integrity_wrapper_test.go`. To avoid breaking those callers, this plan uses `audit.SinkChainState` for the new type. The `pkg/types.ChainState` carried on `Event.Chain` keeps the spec's name (no collision in that package).

**Format version note:** The HMAC input format remains `format_version=2` — `(formatVersion | sequence | prevHash | canonicalPayload)`, no generation byte. Generation only controls when prev_hash resets to `""`. Bumping to `format_version=3` to fold generation into the HMAC is out of scope (would need verify-CLI dual-version support); cross-generation framing protection lives in the WTP wire layer per its spec.

---

## Files

**Create:**
- `internal/audit/sequence_allocator.go` — `SequenceAllocator` type, `AllocatorState`, `ErrSequenceOverflow` (re-exposed via this file)
- `internal/audit/sequence_allocator_test.go` — unit tests
- `internal/audit/sink_chain.go` — `SinkChain` type, `SinkChainState`, `ErrFatalIntegrity`, `ErrMissingChainState`
- `internal/audit/sink_chain_test.go` — unit tests
- `internal/store/composite/sequence_contract_test.go` — three Phase 0 verification tests

**Modify:**
- `pkg/types/events.go` — add `ChainState` type and `Event.Chain *ChainState` field with `json:"-"`
- `internal/audit/integrity.go` — refactor `IntegrityChain` internals to compose `SequenceAllocator` + `SinkChain`; preserve `NewIntegrityChain`, `NewIntegrityChainWithAlgorithm`, `Wrap`, `State`, `KeyFingerprint`, `VerifyHash`, `VerifyWrapped` verbatim. `Restore` gains an `error` return (mirrors the SequenceAllocator.Restore and SinkChain.Restore validation; existing callers in `internal/store/` must check the error)
- `internal/store/composite/composite.go` — add `allocator *audit.SequenceAllocator` field, stamp `ev.Chain` in `AppendEvent` before fanout, add `NextGeneration()` method

---

## Task 1: Add typed `Chain` field on `pkg/types.Event`

**Files:**
- Modify: `pkg/types/events.go`
- Test: `pkg/types/events_test.go` (create if absent)

- [ ] **Step 1: Write the failing test**

If `pkg/types/events_test.go` does not exist, create it. Otherwise append:

```go
package types

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestEvent_ChainFieldNotMarshaled is a load-bearing safety test for the
// Phase 0 contract: the typed Chain field MUST NEVER appear in JSON output,
// because it carries internal sink coordination state, not user-visible data.
func TestEvent_ChainFieldNotMarshaled(t *testing.T) {
	ev := Event{
		ID:        "abc",
		Timestamp: time.Unix(1700000000, 0).UTC(),
		Type:      "file_open",
		SessionID: "sess-1",
		Chain: &ChainState{
			Sequence:   42,
			Generation: 7,
		},
	}

	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(out)

	for _, banned := range []string{`"chain"`, `"Chain"`, `"sequence":42`, `"generation":7`} {
		if strings.Contains(got, banned) {
			t.Errorf("Event JSON must not contain %q; got %s", banned, got)
		}
	}
}

// TestEvent_ChainFieldIgnoredOnUnmarshal verifies that decoding JSON which
// happens to contain a "chain" key does not populate Event.Chain.
func TestEvent_ChainFieldIgnoredOnUnmarshal(t *testing.T) {
	raw := []byte(`{"id":"x","type":"file_open","session_id":"s","timestamp":"2024-01-02T03:04:05Z","chain":{"sequence":99,"generation":3}}`)
	var ev Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if ev.Chain != nil {
		t.Fatalf("Chain should remain nil after unmarshal, got %+v", ev.Chain)
	}
}
```

The per-sink-copy contract (composite stamps a fresh `*ChainState` per
sink during fanout) is a composite-fanout property that this Task cannot
verify in isolation — the composite stamping logic does not exist yet.
Task 6's `TestComposite_StampsChainBeforeFanout` exercises that contract
end-to-end (pointer-distinct, value-equal, mutation-isolated).

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/eran/work/agentsh
go test ./pkg/types/ -run TestEvent_ChainField -v
```

Expected: build failure ("undefined: ChainState", "Event has no field Chain") — both compile errors prove the field/type don't exist yet.

- [ ] **Step 3: Add the type and field**

Edit `pkg/types/events.go`. Inside the file, find the `Event` struct (currently lines 23-59) and add the `Chain` field as the LAST field of the struct, right after `Fields map[string]any \`json:"fields,omitempty"\``:

```go
	Fields map[string]any `json:"fields,omitempty"`

	// Chain is the shared (sequence, generation) allocated by the composite
	// store before fanout. Used by chained sinks to produce sink-local
	// integrity hashes. Nil until composite stamps it.
	//
	// json:"-" is load-bearing: this field must never appear in any
	// user-visible serialization. Tested by TestEvent_ChainFieldNotMarshaled.
	//
	// Sinks MUST treat the pointed-to ChainState as read-only — see the
	// ChainState type comment for the per-sink-copy contract.
	Chain *ChainState `json:"-"`
}
```

Then add the `ChainState` type at the end of the file (after the `EventQuery` struct):

```go
// ChainState is the shared (sequence, generation) tuple stamped on each event
// by the composite store before fanout to chained sinks. See
// docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md.
//
// Contract for consumers: ChainState MUST be treated as read-only. Sinks
// must never mutate the fields of a *ChainState they receive on
// types.Event.Chain. The composite store is the sole writer; it allocates
// the (sequence, generation) tuple via audit.SequenceAllocator and stamps
// the resulting ChainState onto the event in AppendEvent.
//
// To make accidental aliasing across sinks impossible, the composite is
// expected to stamp a separate *ChainState per fanned-out sink (see Task 5
// of the Phase 0 plan). Until Task 5 lands the typed Chain field is unused
// at runtime; this type and the field exist now so downstream tasks can
// build against a stable type.
type ChainState struct {
	Sequence   uint64
	Generation uint32
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./pkg/types/ -run TestEvent_ChainField -v
```

Expected: PASS for both `TestEvent_ChainFieldNotMarshaled` and `TestEvent_ChainFieldIgnoredOnUnmarshal`.

- [ ] **Step 5: Verify the rest of the build still compiles**

```bash
go build ./...
```

Expected: clean build, no errors. Adding a field is source-compatible with all existing code.

- [ ] **Step 6: Run the full test suite**

```bash
go test ./...
```

Expected: all tests pass. Adding a `nil`-by-default field changes no behavior.

- [ ] **Step 7: Commit**

```bash
git add pkg/types/events.go pkg/types/events_test.go
git commit -m "$(cat <<'EOF'
feat(types): add typed Event.Chain field for sink coordination

Adds pkg/types.ChainState (exported Sequence/Generation fields; treated
as read-only — Task 5 will land the composite stamping that allocates a
fresh *ChainState per sink during fanout) and an Event.Chain pointer
field with json:"-" so the composite store can stamp the shared
sequence tuple onto events without ever leaking it into JSONL, OTEL,
gRPC, webhook or any future serializer. Tested by
TestEvent_ChainFieldNotMarshaled.

Phase 0 of the shared sequence allocator contract — see
docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Implement `SequenceAllocator`

**Files:**
- Create: `internal/audit/sequence_allocator.go`
- Create: `internal/audit/sequence_allocator_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/audit/sequence_allocator_test.go`:

```go
package audit

import (
	"errors"
	"math"
	"sync"
	"testing"
)

func TestSequenceAllocator_Next_ReturnsZeroFirst(t *testing.T) {
	a := NewSequenceAllocator()
	seq, gen, err := a.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if seq != 0 || gen != 0 {
		t.Fatalf("first Next() = (%d, %d), want (0, 0)", seq, gen)
	}
}

func TestSequenceAllocator_Next_Monotonic(t *testing.T) {
	a := NewSequenceAllocator()
	for i := int64(0); i < 100; i++ {
		seq, gen, err := a.Next()
		if err != nil {
			t.Fatalf("Next #%d: %v", i, err)
		}
		if seq != i {
			t.Fatalf("Next #%d returned seq=%d, want %d", i, seq, i)
		}
		if gen != 0 {
			t.Fatalf("Next #%d returned gen=%d, want 0", i, gen)
		}
	}
}

func TestSequenceAllocator_NextGeneration_ResetsSequence(t *testing.T) {
	a := NewSequenceAllocator()
	if _, _, err := a.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, _, err := a.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	// State now: sequence=1, gen=0; next Next() would return (2, 0).

	newGen, err := a.NextGeneration()
	if err != nil {
		t.Fatalf("NextGeneration: %v", err)
	}
	if newGen != 1 {
		t.Fatalf("NextGeneration() = %d, want 1", newGen)
	}

	seq, gen, err := a.Next()
	if err != nil {
		t.Fatalf("Next after NextGeneration: %v", err)
	}
	if seq != 0 || gen != 1 {
		t.Fatalf("after rollover: Next() = (%d, %d), want (0, 1)", seq, gen)
	}
}

func TestSequenceAllocator_State_Restore_RoundTrip(t *testing.T) {
	a := NewSequenceAllocator()
	for i := 0; i < 5; i++ {
		if _, _, err := a.Next(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.NextGeneration(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Next(); err != nil {
		t.Fatal(err)
	}
	// State: sequence=0, gen=1.

	state := a.State()
	if state.Sequence != 0 || state.Generation != 1 {
		t.Fatalf("State() = %+v, want {Sequence:0 Generation:1}", state)
	}

	b := NewSequenceAllocator()
	if err := b.Restore(state); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	seq, gen, err := b.Next()
	if err != nil {
		t.Fatalf("Next after Restore: %v", err)
	}
	if seq != 1 || gen != 1 {
		t.Fatalf("after restore: Next() = (%d, %d), want (1, 1)", seq, gen)
	}
}

func TestSequenceAllocator_Overflow(t *testing.T) {
	a := NewSequenceAllocator()
	if err := a.Restore(AllocatorState{Sequence: math.MaxInt64, Generation: 0}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	_, _, err := a.Next()
	if !errors.Is(err, ErrSequenceOverflow) {
		t.Fatalf("Next at MaxInt64: err = %v, want ErrSequenceOverflow", err)
	}
}

func TestSequenceAllocator_ConcurrentNext_NoDuplicates(t *testing.T) {
	a := NewSequenceAllocator()
	const workers = 8
	const perWorker = 1000

	var wg sync.WaitGroup
	results := make(chan int64, workers*perWorker)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				seq, _, err := a.Next()
				if err != nil {
					t.Errorf("Next: %v", err)
					return
				}
				results <- seq
			}
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[int64]bool, workers*perWorker)
	for s := range results {
		if seen[s] {
			t.Fatalf("duplicate sequence: %d", s)
		}
		seen[s] = true
	}
	if len(seen) != workers*perWorker {
		t.Fatalf("got %d unique sequences, want %d", len(seen), workers*perWorker)
	}
}

func TestSequenceAllocator_NextGeneration_Overflow(t *testing.T) {
	a := NewSequenceAllocator()
	if err := a.Restore(AllocatorState{Sequence: -1, Generation: math.MaxUint32}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	_, err := a.NextGeneration()
	if !errors.Is(err, ErrGenerationOverflow) {
		t.Fatalf("NextGeneration at MaxUint32: err = %v, want ErrGenerationOverflow", err)
	}

	// Allocator must not be mutated by a rejected NextGeneration.
	state := a.State()
	if state.Generation != math.MaxUint32 {
		t.Fatalf("Generation mutated after rejected NextGeneration: got %d, want MaxUint32", state.Generation)
	}
	if state.Sequence != -1 {
		t.Fatalf("Sequence mutated after rejected NextGeneration: got %d, want -1", state.Sequence)
	}

	// Sequences in the current (max) generation must still allocate cleanly.
	seq, gen, err := a.Next()
	if err != nil {
		t.Fatalf("Next after rejected NextGeneration: %v", err)
	}
	if seq != 0 || gen != math.MaxUint32 {
		t.Fatalf("Next at max generation: got (%d, %d), want (0, MaxUint32)", seq, gen)
	}
}

func TestSequenceAllocator_Restore_RejectsInvalidSequence(t *testing.T) {
	a := NewSequenceAllocator()
	// Allocate one tuple so we have non-default state to verify we don't perturb on reject.
	if _, _, err := a.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	pre := a.State()

	for _, bad := range []int64{-2, -100, math.MinInt64} {
		err := a.Restore(AllocatorState{Sequence: bad, Generation: 5})
		if !errors.Is(err, ErrInvalidAllocatorState) {
			t.Fatalf("Restore(Sequence=%d): err = %v, want ErrInvalidAllocatorState", bad, err)
		}
	}

	// Allocator must be unchanged after rejected restores.
	post := a.State()
	if post != pre {
		t.Fatalf("allocator mutated by rejected Restore: pre=%+v, post=%+v", pre, post)
	}

	// Boundary: Sequence == -1 is the valid minimum (means "no Next() yet").
	if err := a.Restore(AllocatorState{Sequence: -1, Generation: 9}); err != nil {
		t.Fatalf("Restore(Sequence=-1): %v", err)
	}
	seq, gen, err := a.Next()
	if err != nil {
		t.Fatalf("Next after Restore(-1, 9): %v", err)
	}
	if seq != 0 || gen != 9 {
		t.Fatalf("after Restore(-1, 9): Next() = (%d, %d), want (0, 9)", seq, gen)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/audit/ -run TestSequenceAllocator -v
```

Expected: build failure ("undefined: NewSequenceAllocator", "undefined: AllocatorState"). The type does not exist yet.

- [ ] **Step 3: Implement the type**

Create `internal/audit/sequence_allocator.go`:

```go
package audit

import (
	"errors"
	"math"
	"sync"
)

// ErrGenerationOverflow is returned by NextGeneration when the generation
// counter would wrap past math.MaxUint32. Reaching this is a fatal
// integrity event — wrapping would re-use prior (sequence, generation)
// tuples, defeating the new-generation boundary guarantee.
var ErrGenerationOverflow = errors.New("integrity generation overflow")

// ErrInvalidAllocatorState is returned by Restore when the supplied state
// violates allocator invariants (e.g., Sequence < -1). The allocator is
// not modified on rejected restore.
var ErrInvalidAllocatorState = errors.New("invalid allocator state")

// SequenceAllocator owns the shared (sequence, generation) tuple. It has no
// hash state. Composite holds exactly one allocator and stamps every event
// with the next allocated tuple before fanning out to chained sinks.
//
// Sequence is monotonically increasing within a generation, starting at 0.
// Generation is incremented by NextGeneration() and resets sequence so the
// next Next() returns (0, new_generation).
//
// Concurrency-safe.
type SequenceAllocator struct {
	mu         sync.Mutex
	sequence   int64  // last returned sequence; -1 means "none yet"
	generation uint32 // current generation
}

// AllocatorState captures the allocator's persistent state. Snapshot via
// State() and rehydrate with Restore() across restarts.
type AllocatorState struct {
	Sequence   int64
	Generation uint32
}

// NewSequenceAllocator creates an allocator whose first Next() returns (0, 0).
func NewSequenceAllocator() *SequenceAllocator {
	return &SequenceAllocator{sequence: -1}
}

// Next returns the next (sequence, generation) and advances the counter.
// Returns ErrSequenceOverflow when sequence == math.MaxInt64; the caller
// should treat this as fatal (it implies > 9.2e18 events in a single
// generation, so a generation rotation is the recovery path).
func (a *SequenceAllocator) Next() (sequence int64, generation uint32, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sequence == math.MaxInt64 {
		return 0, 0, ErrSequenceOverflow
	}
	a.sequence++
	return a.sequence, a.generation, nil
}

// NextGeneration increments generation and resets sequence so the next Next()
// returns (0, new_generation). Returns the new generation. Used by the
// composite owner when the chain key rotates.
//
// Returns ErrGenerationOverflow if generation == math.MaxUint32; the
// allocator is not modified in that case. Reaching this is fatal — there
// is no clean recovery short of provisioning a new allocator with a fresh
// chain key namespace.
func (a *SequenceAllocator) NextGeneration() (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.generation == math.MaxUint32 {
		return 0, ErrGenerationOverflow
	}
	a.generation++
	a.sequence = -1
	return a.generation, nil
}

// State returns the current (sequence, generation) for persistence. After
// Restore(state), the next Next() returns (state.Sequence + 1, state.Generation).
func (a *SequenceAllocator) State() AllocatorState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AllocatorState{Sequence: a.sequence, Generation: a.generation}
}

// Restore rehydrates allocator state after restart. Returns
// ErrInvalidAllocatorState if state.Sequence < -1 (which would violate the
// monotonic-from-zero contract); the allocator is not modified in that case.
func (a *SequenceAllocator) Restore(state AllocatorState) error {
	if state.Sequence < -1 {
		return ErrInvalidAllocatorState
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sequence = state.Sequence
	a.generation = state.Generation
	return nil
}
```

Note: `ErrSequenceOverflow` already exists in `internal/audit/integrity.go:51` (`var ErrSequenceOverflow = errors.New("integrity sequence overflow")`). Reusing it — do not redeclare.

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/audit/ -run TestSequenceAllocator -v
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Run the full audit test suite**

```bash
go test ./internal/audit/ -v
```

Expected: all existing audit tests still PASS — we added a new file with no edits to existing code.

- [ ] **Step 6: Commit**

```bash
git add internal/audit/sequence_allocator.go internal/audit/sequence_allocator_test.go
git commit -m "$(cat <<'EOF'
feat(audit): add SequenceAllocator for shared (seq, gen) allocation

Composite-owned allocator that produces a single (sequence, generation)
tuple per event before fanout. No hash state — that lives in SinkChain
(next commit). Concurrency-safe; reuses the existing ErrSequenceOverflow.

Phase 0 — see docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Implement `SinkChain`

**Files:**
- Create: `internal/audit/sink_chain.go`
- Create: `internal/audit/sink_chain_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/audit/sink_chain_test.go`:

```go
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// computeExpectedHash mirrors the production HMAC formula from
// internal/audit/integrity.go: format_version | sequence | prev_hash | payload.
// Generation is intentionally NOT in the HMAC input — see the format-version
// note in the implementation plan.
func computeExpectedHash(t *testing.T, key []byte, formatVersion int, sequence int64, prevHash string, payload []byte) string {
	t.Helper()
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strconv.Itoa(formatVersion)))
	h.Write([]byte("|"))
	h.Write([]byte(strconv.FormatInt(sequence, 10)))
	h.Write([]byte("|"))
	h.Write([]byte(prevHash))
	h.Write([]byte("|"))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

func newTestSinkChain(t *testing.T) (*SinkChain, []byte) {
	t.Helper()
	key := make([]byte, MinKeyLength)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c, err := NewSinkChain(key, "hmac-sha256")
	if err != nil {
		t.Fatalf("NewSinkChain: %v", err)
	}
	return c, key
}

func TestSinkChain_Compute_FirstEntryUsesEmptyPrev(t *testing.T) {
	c, key := newTestSinkChain(t)
	payload := []byte(`{"k":"v"}`)

	result, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if result.PrevHash() != "" {
		t.Errorf("first Compute: prevHash = %q, want empty", result.PrevHash())
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 0, "", payload)
	if result.EntryHash() != want {
		t.Errorf("entryHash = %q, want %q", result.EntryHash(), want)
	}
}

func TestSinkChain_Compute_IsPure_NoMutationWithoutCommit(t *testing.T) {
	c, _ := newTestSinkChain(t)
	payload := []byte(`{"k":"v"}`)

	first, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Compute again without Commit — must produce the SAME entryHash, since
	// prev_hash hasn't moved.
	second, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if first.EntryHash() != second.EntryHash() {
		t.Errorf("Compute mutated chain state: first=%q second=%q", first.EntryHash(), second.EntryHash())
	}
}

func TestSinkChain_Commit_AdvancesPrevHash(t *testing.T) {
	c, key := newTestSinkChain(t)

	first, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(first); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	second, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if second.PrevHash() != first.EntryHash() {
		t.Errorf("after Commit: prev_hash = %q, want %q", second.PrevHash(), first.EntryHash())
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 1, first.EntryHash(), []byte(`{"b":2}`))
	if second.EntryHash() != want {
		t.Errorf("second entryHash = %q, want %q", second.EntryHash(), want)
	}
}

func TestSinkChain_Compute_GenerationRollover_ResetsPrevToEmpty(t *testing.T) {
	c, key := newTestSinkChain(t)

	// Establish gen=0 chain with one committed entry.
	r0, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(r0); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Compute at gen=1 — prev_hash should be "" automatically.
	r1, err := c.Compute(IntegrityFormatVersion, 0, 1, []byte(`{"y":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if r1.PrevHash() != "" {
		t.Errorf("after gen rollover: prev_hash = %q, want empty", r1.PrevHash())
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 0, "", []byte(`{"y":2}`))
	if r1.EntryHash() != want {
		t.Errorf("rolled entryHash = %q, want %q", r1.EntryHash(), want)
	}

	// Until Commit(r1), the chain's recorded generation is still 0.
	state := c.State()
	if state.Generation != 0 {
		t.Errorf("State.Generation before Commit = %d, want 0", state.Generation)
	}

	if err := c.Commit(r1); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	state = c.State()
	if state.Generation != 1 {
		t.Errorf("State.Generation after Commit = %d, want 1", state.Generation)
	}
	if state.PrevHash != r1.EntryHash() {
		t.Errorf("State.PrevHash = %q, want %q", state.PrevHash, r1.EntryHash())
	}
}

func TestSinkChain_Fatal_LatchesAndBlocksFurtherCompute(t *testing.T) {
	c, _ := newTestSinkChain(t)

	if _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}

	c.Fatal(errors.New("ambiguous WAL write"))

	_, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if !errors.Is(err, ErrFatalIntegrity) {
		t.Fatalf("Compute after Fatal: err = %v, want ErrFatalIntegrity", err)
	}
}

func TestSinkChain_State_Restore_RoundTrip(t *testing.T) {
	c, _ := newTestSinkChain(t)

	r0, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(r0); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	r1, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(r1); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	state := c.State()
	if state.Generation != 0 || state.PrevHash != r1.EntryHash() {
		t.Fatalf("State() = %+v, want {Generation:0 PrevHash:%q}", state, r1.EntryHash())
	}

	d, _ := newTestSinkChain(t)
	if err := d.Restore(state.Generation, state.PrevHash, state.Fatal); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Continue the chain from d — same key, so same entry hash as if c
	// had continued.
	cNext, err := c.Compute(IntegrityFormatVersion, 2, 0, []byte(`{"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	dNext, err := d.Compute(IntegrityFormatVersion, 2, 0, []byte(`{"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	if cNext.EntryHash() != dNext.EntryHash() {
		t.Errorf("after Restore: entryHash mismatch %q vs %q", cNext.EntryHash(), dNext.EntryHash())
	}
}

func TestNewSinkChain_RejectsShortKey(t *testing.T) {
	_, err := NewSinkChain(make([]byte, MinKeyLength-1), "hmac-sha256")
	if err == nil {
		t.Fatal("NewSinkChain accepted a too-short key")
	}
	if !strings.Contains(err.Error(), "key too short") {
		t.Errorf("error = %q, want 'key too short'", err)
	}
}

func TestNewSinkChain_RejectsUnsupportedAlgorithm(t *testing.T) {
	key := make([]byte, MinKeyLength)
	_, err := NewSinkChain(key, "md5")
	if err == nil {
		t.Fatal("NewSinkChain accepted unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("error = %q, want 'unsupported algorithm'", err)
	}
}

func TestSinkChain_SerialComputeCommit_NoChainBreakage(t *testing.T) {
	c, key := newTestSinkChain(t)

	// Single-goroutine serialization verifies chain continuity; concurrent
	// ComputeCommit pairs across goroutines is NOT a supported pattern (Commit
	// cannot identify which Compute it finalizes). This test asserts that
	// repeated Compute+Commit in serial order produces a chain that verifies
	// when replayed in committed order.
	const N = 200
	type record struct {
		seq       int64
		payload   []byte
		entryHash string
		prevHash  string
	}
	records := make([]record, 0, N)

	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := int64(0); i < N; i++ {
			payload := []byte(`{"i":` + strconv.FormatInt(i, 10) + `}`)
			result, err := c.Compute(IntegrityFormatVersion, i, 0, payload)
			if err != nil {
				t.Errorf("Compute %d: %v", i, err)
				return
			}
			if err := c.Commit(result); err != nil {
				t.Errorf("Commit %d: %v", i, err)
				return
			}
			mu.Lock()
			records = append(records, record{seq: i, payload: payload, entryHash: result.EntryHash(), prevHash: result.PrevHash()})
			mu.Unlock()
		}
	}()
	wg.Wait()

	// Walk records and verify chain continuity.
	if len(records) != N {
		t.Fatalf("got %d records, want %d", len(records), N)
	}
	expectedPrev := ""
	for _, r := range records {
		if r.prevHash != expectedPrev {
			t.Fatalf("seq %d: prev=%q want %q", r.seq, r.prevHash, expectedPrev)
		}
		want := computeExpectedHash(t, key, IntegrityFormatVersion, r.seq, expectedPrev, r.payload)
		if r.entryHash != want {
			t.Fatalf("seq %d: entry=%q want %q", r.seq, r.entryHash, want)
		}
		expectedPrev = r.entryHash
	}
}

func TestSinkChain_Compute_IsPureUnderConcurrentCallers(t *testing.T) {
	c, _ := newTestSinkChain(t)
	payload := []byte(`{"k":"v"}`)

	const N = 32
	results := make([]*ComputeResult, 0, N)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			result, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
			if err != nil {
				t.Errorf("Compute: %v", err)
				return
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(results) != N {
		t.Fatalf("got %d results, want %d", len(results), N)
	}
	wantEntry := results[0].EntryHash()
	wantPrev := results[0].PrevHash()
	for i, r := range results {
		if r.EntryHash() != wantEntry {
			t.Errorf("result %d: entry=%q, want %q (Compute is not pure under contention)", i, r.EntryHash(), wantEntry)
		}
		if r.PrevHash() != wantPrev {
			t.Errorf("result %d: prev=%q, want %q (Compute is not pure under contention)", i, r.PrevHash(), wantPrev)
		}
	}
}

func TestSinkChain_State_PersistsFatal(t *testing.T) {
	c, _ := newTestSinkChain(t)

	if _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	c.Fatal(errors.New("ambiguous WAL write"))

	state := c.State()
	if !state.Fatal {
		t.Fatalf("State.Fatal = false after Fatal(); want true")
	}

	// Round-trip into a fresh chain via Restore. The latch must survive.
	d, _ := newTestSinkChain(t)
	if err := d.Restore(state.Generation, state.PrevHash, state.Fatal); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := d.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`)); !errors.Is(err, ErrFatalIntegrity) {
		t.Fatalf("Compute after Restore-with-Fatal: err = %v, want ErrFatalIntegrity", err)
	}
}

func TestSinkChain_Restore_ValidatesPrevHash(t *testing.T) {
	validSha256 := strings.Repeat("a", 64)  // 32 bytes hex-encoded
	validSha512 := strings.Repeat("b", 128) // 64 bytes hex-encoded

	cases := []struct {
		name      string
		algorithm string
		prevHash  string
		wantErr   bool
	}{
		{name: "empty is genesis", algorithm: "hmac-sha256", prevHash: "", wantErr: false},
		{name: "valid sha256 hex", algorithm: "hmac-sha256", prevHash: validSha256, wantErr: false},
		{name: "wrong length hex (sha512 under sha256)", algorithm: "hmac-sha256", prevHash: validSha512, wantErr: true},
		{name: "non-hex characters", algorithm: "hmac-sha256", prevHash: strings.Repeat("z", 64), wantErr: true},
		{name: "odd-length hex", algorithm: "hmac-sha256", prevHash: strings.Repeat("a", 63), wantErr: true},
		{name: "valid sha512 hex under sha512", algorithm: "hmac-sha512", prevHash: validSha512, wantErr: false},
		{name: "sha256 length under sha512", algorithm: "hmac-sha512", prevHash: validSha256, wantErr: true},
		{name: "empty under sha512 is genesis", algorithm: "hmac-sha512", prevHash: "", wantErr: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, MinKeyLength)
			c, err := NewSinkChain(key, tc.algorithm)
			if err != nil {
				t.Fatalf("NewSinkChain: %v", err)
			}

			// Capture pre-state to assert non-mutation on rejected restore.
			before := c.State()

			err = c.Restore(7, tc.prevHash, false)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Restore(%q): err = nil, want error", tc.prevHash)
				}
				if !errors.Is(err, ErrInvalidChainState) {
					t.Errorf("Restore(%q): err = %v, want errors.Is ErrInvalidChainState", tc.prevHash, err)
				}
				after := c.State()
				if after != before {
					t.Errorf("rejected Restore mutated state: before=%+v after=%+v", before, after)
				}
				return
			}

			if err != nil {
				t.Fatalf("Restore(%q): unexpected err = %v", tc.prevHash, err)
			}
			after := c.State()
			if after.Generation != 7 || after.PrevHash != tc.prevHash || after.Fatal {
				t.Errorf("after Restore: state = %+v, want {Generation:7 PrevHash:%q Fatal:false}", after, tc.prevHash)
			}
		})
	}
}

// TestSinkChain_Commit_BackwardsGenerationLatchesFatal verifies that a Commit
// whose ComputeResult was produced before a generation rollover (i.e. its
// generation is older than the chain's current generation) latches the chain
// fatal and returns an error. Silently no-op'ing this would hide an integrity
// divergence: the durable write would have succeeded but the in-memory
// prev_hash would lag, breaking subsequent Compute calls without signal.
func TestSinkChain_Commit_BackwardsGenerationLatchesFatal(t *testing.T) {
	c, _ := newTestSinkChain(t)

	// Establish chain at gen=2 by Compute+Commit.
	r2, err := c.Compute(IntegrityFormatVersion, 0, 2, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(r2); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	state := c.State()
	if state.Generation != 2 {
		t.Fatalf("setup: chain generation = %d, want 2", state.Generation)
	}

	// Construct a backwards-generation result. Restore the chain to gen=1
	// briefly, Compute under gen=1, then restore back to gen=2 — the result
	// carries result.generation=1 even though the chain is now at gen=2.
	if err := c.Restore(1, "", false); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	older, err := c.Compute(IntegrityFormatVersion, 0, 1, []byte(`{"old":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if older.generation != 1 {
		t.Fatalf("older.generation = %d, want 1", older.generation)
	}
	if err := c.Restore(2, r2.EntryHash(), false); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Commit the backwards result must return an error mentioning
	// "backwards generation" and latch the chain fatal.
	err = c.Commit(older)
	if err == nil {
		t.Fatal("Commit(backwards result): err = nil, want error")
	}
	if !strings.Contains(err.Error(), "backwards generation") {
		t.Errorf("Commit error = %q, want substring 'backwards generation'", err)
	}

	if !c.State().Fatal {
		t.Errorf("State.Fatal = false after backwards-gen Commit; want true")
	}

	// Subsequent Compute must surface the fatal latch.
	if _, err := c.Compute(IntegrityFormatVersion, 1, 2, []byte(`{"x":1}`)); !errors.Is(err, ErrFatalIntegrity) {
		t.Errorf("Compute after backwards-gen Commit: err = %v, want ErrFatalIntegrity", err)
	}
}

// TestSinkChain_Commit_NilResultErrors verifies that Commit rejects a nil
// ComputeResult with an error rather than panicking.
func TestSinkChain_Commit_NilResultErrors(t *testing.T) {
	c, _ := newTestSinkChain(t)

	err := c.Commit(nil)
	if err == nil {
		t.Fatal("Commit(nil): err = nil, want error")
	}

	// nil-result error is a caller bug, not a fatal integrity event — the
	// chain should NOT latch fatal in this case.
	if c.State().Fatal {
		t.Errorf("Commit(nil) latched fatal; want chain unchanged")
	}
}

// TestSinkChain_Commit_AfterFatalReturnsError verifies that Commit on a chain
// that was previously latched Fatal returns ErrFatalIntegrity (replacing the
// earlier silent-no-op behavior). The chain stays latched.
func TestSinkChain_Commit_AfterFatalReturnsError(t *testing.T) {
	c, _ := newTestSinkChain(t)

	result, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}

	c.Fatal(errors.New("ambiguous WAL write"))

	err = c.Commit(result)
	if !errors.Is(err, ErrFatalIntegrity) {
		t.Errorf("Commit after Fatal: err = %v, want ErrFatalIntegrity", err)
	}

	if !c.State().Fatal {
		t.Errorf("State.Fatal = false after Commit-on-fatal-chain; want true (latch must persist)")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/audit/ -run TestSinkChain -v
go test ./internal/audit/ -run TestNewSinkChain -v
```

Expected: build failure ("undefined: NewSinkChain", "undefined: ErrFatalIntegrity"). Type doesn't exist yet.

- [ ] **Step 3: Implement the type**

Create `internal/audit/sink_chain.go`:

```go
package audit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// SinkChain owns prev_hash for one sink. Each chained sink holds one.
// Compute is pure (no mutation); Commit advances prev_hash; Fatal latches
// the chain after an ambiguous durable-write failure.
//
// The same (formatVersion, sequence, prevHash, payload) under different
// keys produces different entryHash values — that is the entire point of
// per-sink chaining.
//
// Concurrency model: single-owner serialized use. SinkChain is mutex-safe,
// and concurrent Compute calls (with no intervening Commit) are pure and
// return identical results — they do not corrupt state. However, callers
// MUST NOT interleave Compute/Commit pairs across goroutines: Commit
// consumes a typed *ComputeResult and validates the result's generation
// against the chain's current generation, but the (sequence, generation)
// tuple alone does not identify which Compute call produced it within the
// same generation. The expected pattern is a single owner that issues
// Compute → durable write → Commit (or Fatal) in sequence per event.
//
// Compute/Commit token contract: Compute returns a *ComputeResult that
// callers MUST pass to Commit unchanged. ComputeResult is opaque
// (unexported fields, accessor methods) and chain-bound — only the
// SinkChain instance that produced the result can commit it. The
// unexported fields make literal construction or post-Compute mutation
// impossible from outside the audit package. Callers that need to persist
// the integrity metadata alongside the payload use EntryHash() and
// PrevHash(); see the lifecycle note below.
//
// Enforced invariants on Commit:
//   - nil ComputeResult → error (no latch).
//   - Post-Fatal Commit → ErrFatalIntegrity (no further latch).
//   - Cross-chain ComputeResult (one produced by a different SinkChain
//     instance) → ErrCrossChainResult, latches fatal on this chain.
//   - Backwards generation → ErrBackwardsGeneration, latches fatal.
//   - Stale prev_hash within the current generation, or non-empty prev_hash
//     on a rollover commit → ErrStaleResult, latches fatal.
//   - Otherwise, generation and prev_hash advance.
//
// Contract — what remains the caller's responsibility:
//
//   - Serialize Compute → durable write → Commit per record. SinkChain
//     does NOT detect concurrent overlapping Compute/Commit pairs from
//     multiple goroutines; the (sequence, generation) tuple is not a
//     unique identifier within a generation.
//   - Do not concurrently Compute+Commit across goroutines. Commit only
//     validates the result against the chain's CURRENT prev_hash; if two
//     goroutines race a Compute → Commit pair, the second Commit will
//     either appear stale (good — caught) or appear fresh (bad — silently
//     accepted) depending on interleaving. The single-owner pattern is
//     the only safe one.
//   - Only call Commit with a result whose durable write actually
//     succeeded. SinkChain has no knowledge of durable state; Commit on a
//     result whose write failed silently advances the in-memory chain
//     past an entry that does not exist in storage.
//
// Lifecycle / serialization boundary:
//
// A ComputeResult is bound to the in-memory SinkChain instance that
// produced it (chain-bound by pointer identity). It cannot be durably
// stored and committed later: a SinkChain reconstructed via NewSinkChain
// + Restore is a new instance and will reject prior tokens with
// ErrCrossChainResult. This is intentional — Compute and Commit are
// designed to be co-located in a single process, with the durable write
// of the integrity metadata happening between them.
//
// EntryHash() and PrevHash() exist so that callers can persist the
// integrity metadata alongside the payload for later VerifyHash. They are
// NOT the input shape for reconstructing a Commit token across process
// boundaries — there is no such API and no such need; the chain itself
// remembers what it has committed via prev_hash, and VerifyHash
// re-derives entry hashes from the persisted metadata.
//
// Recovery — a fatal latch makes the SinkChain instance unusable:
//
//   - All subsequent Compute calls return ErrFatalIntegrity.
//   - All subsequent Commit calls return ErrFatalIntegrity.
//   - The latch survives State()/Restore() round-trips (Fatal is part of
//     SinkChainState).
//   - The instance must be recreated via NewSinkChain (and a fresh
//     generation established externally — typically by rotating the
//     chain key and bumping the SequenceAllocator's generation, then
//     wiring a fresh SinkChain into the sink). There is no in-place
//     reset method by design: a fatal latch indicates an integrity
//     event the operator must observe.
type SinkChain struct {
	mu         sync.Mutex
	key        []byte
	algorithm  string
	generation uint32
	prevHash   string
	fatal      bool
}

// SinkChainState is the persistent state of a SinkChain. The spec calls
// this ChainState; renamed here to avoid colliding with the existing
// audit.ChainState used by IntegrityChain.State().
//
// Fatal is included so persistence round-trips preserve the latch — a
// chain that latched Fatal before a restart must come back latched after
// Restore, otherwise the safety model is defeated.
type SinkChainState struct {
	Generation uint32
	PrevHash   string
	Fatal      bool
}

// ComputeResult is the opaque, chain-bound output of SinkChain.Compute. It is
// the only value Commit will accept, and only the SinkChain instance that
// produced it can commit it. Fields are unexported so callers cannot mutate
// or fabricate one outside the audit package.
//
// Use EntryHash() and PrevHash() to inspect the values for serialization.
//
// Lifecycle / serialization boundary:
//
// A ComputeResult is bound to the in-memory SinkChain instance that
// produced it (chain-bound by pointer identity). It cannot be durably
// stored and committed later: a SinkChain reconstructed via NewSinkChain
// + Restore is a new instance and will reject prior tokens with
// ErrCrossChainResult. This is intentional — Compute and Commit are
// designed to be co-located in a single process, with the durable write
// of the integrity metadata happening between them.
//
// EntryHash() and PrevHash() exist so that callers can persist the
// integrity metadata alongside the payload for later VerifyHash. They are
// NOT the input shape for reconstructing a Commit token across process
// boundaries — there is no such API and no such need; the chain itself
// remembers what it has committed via prev_hash, and VerifyHash
// re-derives entry hashes from the persisted metadata.
type ComputeResult struct {
	entryHash  string
	prevHash   string
	sequence   int64
	generation uint32
	chain      *SinkChain // identity-bound; Commit verifies result.chain == c
}

// EntryHash returns the HMAC entry hash that should be persisted alongside
// the payload for later integrity verification.
func (r *ComputeResult) EntryHash() string { return r.entryHash }

// PrevHash returns the prev_hash the entry was chained against. For the
// genesis entry of a chain or generation, this is "".
func (r *ComputeResult) PrevHash() string { return r.prevHash }

// ErrFatalIntegrity is returned by Compute after Fatal has been called,
// and by Commit when called on a chain that was latched Fatal (either by
// Fatal itself or by a backwards-generation Commit). The chain cannot be
// reused; the sink must be reinitialized (e.g., via generation rotation).
var ErrFatalIntegrity = errors.New("integrity chain latched fatal; sink must be reinitialized")

// ErrMissingChainState is returned by chained sinks when an event arrives
// without ev.Chain set (i.e., composite did not stamp it). Production
// configurations with chained sinks must always run inside a composite
// with a SequenceAllocator.
var ErrMissingChainState = errors.New("event missing Chain field; composite did not stamp it")

// ErrInvalidChainState is returned by Restore when the supplied state
// violates SinkChain invariants (e.g., prevHash is neither empty nor a
// hex string of the algorithm's expected length). The chain is not
// modified on rejected restore.
var ErrInvalidChainState = errors.New("invalid sink chain state")

// ErrBackwardsGeneration is wrapped by Commit when the result's generation
// is older than the chain's current generation. Latches the chain fatal:
// the durable write succeeded for an entry whose generation is no longer
// current, so silently accepting it would leave in-memory prev_hash
// lagging the durable state and corrupt subsequent Compute results.
var ErrBackwardsGeneration = errors.New("backwards-generation Commit: chain latched fatal")

// ErrStaleResult is wrapped by Commit when the result was computed against
// an obsolete chain head. Two cases:
//
//   - same-generation: result.PrevHash != c.prevHash (a prior Commit
//     advanced prev_hash between this result's Compute and Commit).
//   - rollover: result.generation > c.generation but result.PrevHash != ""
//     (rollover results MUST have empty PrevHash; this branch is
//     defense-in-depth).
//
// In either case the chain latches fatal: silently accepting the stale
// result would fork the chain.
var ErrStaleResult = errors.New("stale ComputeResult: caller committed against an obsolete chain head; chain latched fatal")

// ErrCrossChainResult is wrapped by Commit when the supplied ComputeResult
// was produced by a different SinkChain instance. The misuse latches fatal
// on the receiving chain so the programming error becomes loud rather than
// silently corrupting state. The chain that produced the result is
// unaffected.
var ErrCrossChainResult = errors.New("ComputeResult bound to a different SinkChain")

// NewSinkChain creates a new chain keyed by `key` (must be >= MinKeyLength).
// Supported algorithms: "hmac-sha256" (default), "hmac-sha512".
func NewSinkChain(key []byte, algorithm string) (*SinkChain, error) {
	if len(key) < MinKeyLength {
		return nil, fmt.Errorf("key too short: got %d bytes, need at least %d", len(key), MinKeyLength)
	}
	if algorithm == "" {
		algorithm = "hmac-sha256"
	}
	switch algorithm {
	case "hmac-sha256", "hmac-sha512":
		// supported
	default:
		return nil, fmt.Errorf("unsupported algorithm %q: use hmac-sha256 or hmac-sha512", algorithm)
	}
	return &SinkChain{key: key, algorithm: algorithm}, nil
}

// Compute computes the HMAC of (formatVersion, sequence, prev_hash, payload)
// using the chain's key and returns it as a *ComputeResult. Compute is
// PURE: it does not mutate prev_hash. The caller must follow with Commit
// (passing the returned *ComputeResult) on durable-write success or
// discard the result on durable-write failure.
//
// The returned *ComputeResult is bound to this SinkChain instance — only
// Commit on this same chain will accept it. Cross-chain commits fail with
// ErrCrossChainResult and latch the receiving chain fatal.
//
// If `generation` differs from the chain's current generation, prev_hash
// is treated as "" for this Compute (chain rolls automatically). The
// transition is committed only when Commit is called with a result whose
// generation is the new generation.
//
// Returns ErrFatalIntegrity if Fatal was previously called.
func (c *SinkChain) Compute(formatVersion int, sequence int64, generation uint32, payload []byte) (*ComputeResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fatal {
		return nil, ErrFatalIntegrity
	}
	prev := c.prevHash
	if generation != c.generation {
		prev = ""
	}
	hash, err := computeIntegrityHash(c.key, c.algorithm, formatVersion, sequence, prev, payload)
	if err != nil {
		return nil, err
	}
	return &ComputeResult{
		entryHash:  hash,
		prevHash:   prev,
		sequence:   sequence,
		generation: generation,
		chain:      c,
	}, nil
}

// Commit advances prev_hash using the result of a previous Compute on this
// chain. Must be called exactly once per successful Compute, after the
// durable write succeeds. On ambiguous failure (write may or may not have
// landed), the caller MUST call Fatal instead; Commit and Fatal are
// mutually exclusive per Compute.
//
// Returns an error if `result` is nil (caller bug; chain is not modified).
//
// Returns ErrFatalIntegrity if the chain was previously latched Fatal —
// either by an explicit Fatal call, by a prior backwards-generation
// Commit, by a prior stale-result Commit, or by a prior cross-chain
// Commit. The chain stays latched.
//
// Returns an error wrapping ErrCrossChainResult AND latches the chain
// Fatal if the supplied ComputeResult was produced by a different
// SinkChain instance. The cross-chain check runs BEFORE
// generation/prev_hash validation so that mixing tokens between chains is
// always reported as a cross-chain error rather than as a downstream
// invariant violation.
//
// Returns an error wrapping ErrBackwardsGeneration AND latches the chain
// Fatal if the result's generation is older than the chain's current
// generation. Accepting it would leave in-memory prev_hash lagging the
// durable state and silently corrupt subsequent Compute results.
//
// Returns an error wrapping ErrStaleResult AND latches the chain Fatal in
// two cases that both indicate the result was computed against an
// obsolete chain head:
//
//   - result.generation == c.generation and result.PrevHash != c.prevHash:
//     a prior Commit advanced prev_hash between this result's Compute and
//     Commit. Silently accepting would fork the chain.
//   - result.generation > c.generation and result.PrevHash != "": rollover
//     results MUST have empty PrevHash (Compute always sets prev="" on
//     rollover). A non-empty PrevHash here means the result was forged or
//     computed against mismatched state. Defense-in-depth: normal callers
//     cannot construct this via the public API.
func (c *SinkChain) Commit(result *ComputeResult) error {
	if result == nil {
		return errors.New("nil ComputeResult")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fatal {
		return ErrFatalIntegrity
	}
	// Cross-chain check runs first so that mixing tokens between chains
	// always surfaces as ErrCrossChainResult, not as a downstream
	// generation/prev_hash invariant violation.
	if result.chain != c {
		c.fatal = true
		return fmt.Errorf("%w", ErrCrossChainResult)
	}
	if result.generation < c.generation {
		c.fatal = true
		return fmt.Errorf("%w: result.generation=%d < c.generation=%d",
			ErrBackwardsGeneration, result.generation, c.generation)
	}
	// Stale-token detection — fatal latch.
	// Two cases:
	//   * result.generation == c.generation: result.prevHash MUST equal
	//     c.prevHash. Mismatch means the caller computed against an older
	//     chain head and is replaying a stale token.
	//   * result.generation > c.generation: this is a rollover commit. The
	//     result MUST have prevHash == "" because Compute used "" for the
	//     rolled gen. Anything else means the result was forged or computed
	//     against mismatched state.
	if result.generation == c.generation {
		if result.prevHash != c.prevHash {
			c.fatal = true
			return fmt.Errorf("%w: result.prev_hash=%q, current prev_hash=%q",
				ErrStaleResult, result.prevHash, c.prevHash)
		}
	} else { // result.generation > c.generation (rollover)
		if result.prevHash != "" {
			c.fatal = true
			return fmt.Errorf("%w: rollover commit must have empty prev_hash; got %q",
				ErrStaleResult, result.prevHash)
		}
	}
	c.generation = result.generation
	c.prevHash = result.entryHash
	return nil
}

// Fatal latches the chain in an unrecoverable state. All subsequent Compute
// calls return ErrFatalIntegrity. Used when a durable write returned an
// ambiguous error (timeout, partial write detection) — we cannot know whether
// the entry was persisted, so we cannot safely continue chaining.
func (c *SinkChain) Fatal(reason error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fatal = true
	_ = reason // reserved for future telemetry; intentionally unused
}

// State returns the (generation, prev_hash, fatal) for persistence.
func (c *SinkChain) State() SinkChainState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SinkChainState{Generation: c.generation, PrevHash: c.prevHash, Fatal: c.fatal}
}

// Restore rehydrates chain state after restart. Returns ErrInvalidChainState
// if `prevHash` is neither empty (genesis) nor a hex string whose decoded
// length matches the chain's algorithm output (32 bytes for hmac-sha256,
// 64 bytes for hmac-sha512). The chain is not modified on rejected restore.
//
// If `fatal` is true, the chain comes back latched: subsequent Compute calls
// return ErrFatalIntegrity. This is required so persistence round-trips
// preserve the safety latch across restarts.
func (c *SinkChain) Restore(generation uint32, prevHash string, fatal bool) error {
	if err := validatePrevHash(c.algorithm, prevHash); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation = generation
	c.prevHash = prevHash
	c.fatal = fatal
	return nil
}

// validatePrevHash returns nil if prevHash is empty (genesis) or a valid
// hex string of the algorithm's expected output length. Otherwise it
// returns an error wrapping ErrInvalidChainState.
func validatePrevHash(algorithm, prevHash string) error {
	if prevHash == "" {
		return nil
	}
	var wantBytes int
	switch algorithm {
	case "hmac-sha512":
		wantBytes = 64
	default: // hmac-sha256 (also default when algorithm == "")
		wantBytes = 32
	}
	wantHex := wantBytes * 2
	if len(prevHash) != wantHex {
		return fmt.Errorf("%w: prevHash length %d, want %d hex chars for %s", ErrInvalidChainState, len(prevHash), wantHex, algorithm)
	}
	if _, err := hex.DecodeString(prevHash); err != nil {
		return fmt.Errorf("%w: prevHash is not valid hex: %v", ErrInvalidChainState, err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/audit/ -run "TestSinkChain|TestNewSinkChain" -v
```

Expected: all 19 tests PASS.

- [ ] **Step 5: Run the full audit test suite**

```bash
go test ./internal/audit/ -v
```

Expected: all existing audit tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/audit/sink_chain.go internal/audit/sink_chain_test.go
git commit -m "$(cat <<'EOF'
feat(audit): add SinkChain with transactional Compute/Commit/Fatal

Per-sink chain that owns prev_hash and exposes:
- Compute (pure HMAC, no mutation)
- Commit (advances prev_hash on durable-write success)
- Fatal (latches on ambiguous durable-write failure)

Generation rollover is automatic: a Compute call with a new generation uses
prev_hash="" without mutating chain state. The transition is recorded only
when Commit is called with the new generation.

SinkChainState renamed from spec's ChainState to avoid collision with
existing audit.ChainState used by IntegrityChain.State().

Phase 0 — see docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Refactor `IntegrityChain` to compose `SequenceAllocator` + `SinkChain`

The spec says `Wrap()` is preserved verbatim at the source level. This task swaps the internals of `IntegrityChain` so the existing single-sink callers (and the existing test suite) keep working.

**Files:**
- Modify: `internal/audit/integrity.go`

- [ ] **Step 1: Read the current implementation**

```bash
sed -n '34,42p;199,272p' internal/audit/integrity.go
```

Confirm the existing struct fields are `mu`, `key`, `algorithm`, `sequence`, `prevHash` and the methods touched are `NewIntegrityChainWithAlgorithm`, `Wrap`, `State`, `Restore`. The existing public API is what we must preserve.

- [ ] **Step 2: Replace the struct and constructors**

In `internal/audit/integrity.go`, replace the existing `IntegrityChain` struct (currently lines 34-42) with the composed version:

```go
// IntegrityChain is the legacy single-sink composer of SequenceAllocator +
// SinkChain. New code should use those two types directly via the composite
// store's allocator and per-sink chains. Wrap/State/Restore are preserved
// at the source level for existing callers.
//
// Concurrency: Wrap, State, and Restore are serialized by an internal
// mutex so the wrapper preserves the legacy single-mutex atomicity contract:
// concurrent Wrap calls do not race against each other, State returns a
// consistent (sequence, prev_hash) snapshot, and Restore is all-or-nothing
// (a failed Restore leaves the wrapper in its pre-call state).
//
// KeyFingerprint, VerifyHash, and VerifyWrapped do NOT take the wrapper
// mutex — they read immutable key/algorithm via the underlying SinkChain's
// own mutex and have no need for wrapper-level serialization.
type IntegrityChain struct {
	mu    sync.Mutex
	alloc *SequenceAllocator
	chain *SinkChain
}
```

Add `"sync"` to the import block alongside the existing standard-library imports.

Replace the body of `NewIntegrityChainWithAlgorithm` (currently lines 72-91) with:

```go
func NewIntegrityChainWithAlgorithm(key []byte, algorithm string) (*IntegrityChain, error) {
	chain, err := NewSinkChain(key, algorithm)
	if err != nil {
		return nil, err
	}
	return &IntegrityChain{
		alloc: NewSequenceAllocator(),
		chain: chain,
	}, nil
}
```

Note: `NewSinkChain` already does the key length and algorithm validation, so we keep the same error semantics for the `IntegrityChain` constructor.

- [ ] **Step 3: Replace `Wrap()` to use the composed types**

Replace the body of `Wrap()` (currently lines 201-252) with:

```go
// Wrap adds integrity metadata to an event payload.
// The payload must be valid JSON. Returns a new JSON payload with an "integrity" field.
func (c *IntegrityChain) Wrap(payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := parseIntegrityPayloadUseNumber(payload)
	if err != nil {
		return nil, err
	}
	canonicalPayload, err := marshalCanonicalPayload(data)
	if err != nil {
		return nil, err
	}

	seq, gen, err := c.alloc.Next()
	if err != nil {
		return nil, err
	}

	result, err := c.chain.Compute(IntegrityFormatVersion, seq, gen, canonicalPayload)
	if err != nil {
		return nil, err
	}

	data["integrity"] = IntegrityMetadata{
		FormatVersion: IntegrityFormatVersion,
		Sequence:      seq,
		PrevHash:      result.PrevHash(),
		EntryHash:     result.EntryHash(),
	}

	wrapped, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal wrapped payload: %w", err)
	}

	if err := c.chain.Commit(result); err != nil {
		return nil, err
	}
	return wrapped, nil
}
```

Single-sink callers don't expose Compute/Commit because there's no fanout; the legacy contract is "Wrap returns the bytes; if the caller's write fails, the caller never calls Wrap again on the same record." That contract is preserved — Commit happens inside Wrap.

The `c.mu.Lock()`/`defer c.mu.Unlock()` preserves the legacy single-mutex atomicity contract: concurrent Wrap calls cannot interleave `alloc.Next()` from one goroutine with `chain.Compute()`/`chain.Commit()` from another, which would produce ErrStaleResult and latch the chain fatal. The wrapper mutex always wraps calls into `c.alloc` / `c.chain`; there is no path where component code calls back into the wrapper, so no lock-ordering hazard exists.

- [ ] **Step 4: Replace `State()` to delegate**

Replace the body of `State()` (currently lines 254-262) with:

```go
// State returns the last written chain state for persistence.
func (c *IntegrityChain) State() ChainState {
	c.mu.Lock()
	defer c.mu.Unlock()
	allocState := c.alloc.State()
	chainState := c.chain.State()
	return ChainState{
		Sequence: allocState.Sequence,
		PrevHash: chainState.PrevHash,
	}
}
```

The wrapper mutex makes the `(sequence, prev_hash)` snapshot consistent: callers cannot observe a torn read where the allocator has advanced past N but the chain still reports `prev_hash` for N-1 (or vice versa). Without the wrapper mutex, the two component `State()` calls would interleave with concurrent `Wrap()` calls.

- [ ] **Step 5: Replace `Restore()` to delegate**

Replace the body of `Restore()` (currently lines 264-271) with:

```go
// Restore restores the chain state after a restart.
// The sequence must be the last written entry so the next Wrap continues at sequence+1.
//
// Aggregates errors from the underlying allocator and sink chain restores —
// SequenceAllocator.Restore rejects sequence < -1, and SinkChain.Restore
// rejects malformed prev_hash (non-hex or wrong length for the algorithm).
//
// Restore is all-or-nothing: if either component rejects its input, the
// IntegrityChain is left in its pre-call state. The implementation
// snapshots the allocator before mutating and rolls it back if the chain
// restore is rejected. The wrapper mutex serializes Restore against
// concurrent Wrap and State calls.
func (c *IntegrityChain) Restore(sequence int64, prevHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Snapshot allocator state for rollback so Restore is all-or-nothing:
	// if chain restoration fails, the allocator must not be observed as
	// partially restored. SequenceAllocator.Restore validates Sequence >= -1
	// before mutating; SinkChain.Restore validates prevHash format before
	// mutating. We attempt allocator first; if chain restore rejects the
	// prevHash, we restore the allocator to the pre-call snapshot.
	prevAlloc := c.alloc.State()

	if err := c.alloc.Restore(AllocatorState{Sequence: sequence, Generation: 0}); err != nil {
		return fmt.Errorf("restore allocator: %w", err)
	}
	if err := c.chain.Restore(0, prevHash, false); err != nil {
		// Roll back allocator. prevAlloc came from State() so it satisfies
		// the Sequence >= -1 invariant; this rollback cannot fail.
		_ = c.alloc.Restore(prevAlloc)
		return fmt.Errorf("restore chain: %w", err)
	}
	return nil
}
```

Note: legacy `IntegrityChain` does not expose generation (its callers were single-sink with no rotation concept beyond key change, which today is handled via key-fingerprint mismatch detection in `internal/store/integrity_wrapper.go`). We pin generation=0 to keep behavior identical. Fatal is also pinned to false — the legacy single-sink Wrap path has no Fatal latch concept; ambiguous-write recovery is the new `SinkChain.Fatal`/`Compute`/`Commit` API.

The all-or-nothing semantics matter because callers (`internal/store/integrity_wrapper.go`) use Restore both during startup recovery and after a clean-failure write to roll the chain back to its pre-write state. A half-restored wrapper (allocator advanced, chain unchanged) would silently corrupt subsequent Wrap output. Both component `Restore`s validate their input before mutating, so the rollback `c.alloc.Restore(prevAlloc)` cannot itself fail (we are restoring a value we just read from `State()`).

The new error return is a behavior change for existing callers (`internal/store/integrity_wrapper.go` etc.) — those callers must be updated to check the error. The change mirrors what we already did for `SequenceAllocator.Restore` in Task 2.

- [ ] **Step 6: Update `KeyFingerprint()`, `VerifyHash()`, `VerifyWrapped()`, `computeHash()`**

These methods used `c.key` and `c.algorithm` directly. Now they need to access the SinkChain's key. Add accessors on `SinkChain` first — edit `internal/audit/sink_chain.go` to add:

```go
// keyAndAlgorithm exposes the chain's key and algorithm for legacy
// IntegrityChain delegation. NOT part of the public Phase 0 contract;
// future code should use Compute and never reach for raw key material.
func (c *SinkChain) keyAndAlgorithm() ([]byte, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.key, c.algorithm
}
```

Then in `internal/audit/integrity.go`, replace the four affected methods (currently lines 274-339):

```go
// KeyFingerprint returns a stable SHA-256 fingerprint prefix for the chain key.
func (c *IntegrityChain) KeyFingerprint() string {
	key, _ := c.chain.keyAndAlgorithm()
	return KeyFingerprint(key)
}

// VerifyHash recomputes the canonical payload hash using the chain key and format version.
func (c *IntegrityChain) VerifyHash(formatVersion int, sequence int64, prevHash string, payload []byte, expectedHash string) (bool, error) {
	key, alg := c.chain.keyAndAlgorithm()
	return VerifyHash(key, alg, formatVersion, sequence, prevHash, payload, expectedHash)
}

// VerifyWrapped verifies a wrapped payload, including integrity metadata.
func (c *IntegrityChain) VerifyWrapped(wrapped []byte) (bool, error) {
	key, alg := c.chain.keyAndAlgorithm()
	return VerifyWrapped(key, alg, wrapped)
}

// computeHash computes the HMAC of: format_version || sequence || prev_hash || payload
func (c *IntegrityChain) computeHash(formatVersion int, sequence int64, prevHash string, payload []byte) (string, error) {
	key, alg := c.chain.keyAndAlgorithm()
	return computeIntegrityHash(key, alg, formatVersion, sequence, prevHash, payload)
}
```

Note: `c.computeHash()` may be unused after the Wrap refactor (Wrap now calls SinkChain.Compute, which calls computeIntegrityHash internally). Check usages and delete the method if no callers remain:

```bash
grep -rn "\.computeHash(" internal/audit/
```

If no production callers remain, delete the method.

- [ ] **Step 7: Build and run the existing audit test suite**

```bash
go build ./...
go test ./internal/audit/ -v
```

Expected: clean build; existing audit tests for `chain.State()`, `chain.Wrap(...)` round-trips and sequence overflow at MaxInt64 continue to behave identically. Tests that call `chain.Restore(...)` will need a small update to handle the new `error` return — wrap each call with a nil-error check (`if err := chain.Restore(...); err != nil { t.Fatal(err) }`).

If any test fails, the most likely culprits are:
- `Restore` not pinning generation correctly (chain.Restore(0, prevHash, false) is required)
- `State()` returning wrong sequence after Wrap (allocator's `State()` is the last-returned sequence, which matches what the old code stored in `c.sequence`)
- Overflow test expecting `c.sequence == math.MaxInt64` — the new code triggers overflow inside `c.alloc.Next()` and returns `ErrSequenceOverflow` from there, identical to the old behavior

- [ ] **Step 7b: Add regression tests for the wrapper-mutex contract**

Add three regression tests in `internal/audit/integrity_test.go` covering the new failure modes the composition boundary would otherwise introduce:

1. **`TestIntegrityChain_Wrap_ConcurrentSafety`** — fire 50 goroutines × 20 `Wrap()` calls (1000 entries total) with distinct payloads. After all complete, parse each wrapped entry, build `map[seq]entry_hash` and `map[seq]prev_hash`, assert sequences are exactly `{0..999}`, assert `prev_hash[seq] == entry_hash[seq-1]` for `seq > 0` and `prev_hash[0] == ""`, and verify each entry with `chain.VerifyWrapped`. Without the wrapper mutex, concurrent `Wrap` produces ErrStaleResult or breaks chain integrity.
2. **`TestIntegrityChain_State_SnapshotConsistency`** — start a goroutine that calls `Wrap` in a loop (200 iterations) and records `(sequence, entry_hash)` in a `sync.Map`. In parallel, sample `chain.State()` repeatedly (200 times). For each sampled state, assert `entry_hash(state.Sequence) == state.PrevHash` (with `state.Sequence == -1` and empty `PrevHash` as the legitimate pre-Wrap genesis snapshot). Without the wrapper mutex, `State()` returns torn `(sequence, prev_hash)` reads.
3. **`TestIntegrityChain_Restore_PartialFailure_LeavesStateIntact`** — Wrap a few entries, snapshot `S0 = chain.State()`. Call `chain.Restore(99, "not-valid-hex")`; assert the call returns an error wrapping `ErrInvalidChainState`. Then assert `chain.State()` equals `S0` byte-for-byte and that a subsequent `chain.Wrap(...)` produces an entry whose `Sequence == S0.Sequence + 1` and `PrevHash == S0.PrevHash` (proving allocator was not advanced by the rejected Restore).

```bash
go test ./internal/audit/... -count=1 -race -run 'IntegrityChain_Wrap_ConcurrentSafety|IntegrityChain_State_SnapshotConsistency|IntegrityChain_Restore_PartialFailure_LeavesStateIntact'
```

Expected: PASS under `-race`. The `-race` flag is essential because the concurrency tests assert behavior that the data-race detector alone won't surface (the races here are logical, not memory-level).

- [ ] **Step 8: Run the full test suite**

```bash
go test ./...
```

Expected: all tests PASS, including `internal/store/` integrity wrapper tests and any callers of `audit.IntegrityChain`.

- [ ] **Step 9: Commit**

```bash
git add internal/audit/integrity.go internal/audit/sink_chain.go
git commit -m "$(cat <<'EOF'
refactor(audit): IntegrityChain now composes SequenceAllocator + SinkChain

Legacy IntegrityChain.Wrap/State/Restore preserved at the source level.
Internals delegate to the new Phase 0 types so single-sink callers and the
existing test suite continue to work unchanged.

generation is pinned to 0 inside the legacy wrapper — IntegrityChain has
no generation concept; key rotation today is handled by key-fingerprint
mismatch detection in internal/store/integrity_wrapper.go.

Phase 0 — see docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Refactor `composite.Store` to allocate and stamp `ev.Chain`

**Files:**
- Modify: `internal/store/composite/composite.go`
- Test: `internal/store/composite/composite_test.go` (extend)

- [ ] **Step 1: Write the failing test**

Append to `internal/store/composite/composite_test.go`. The test imports `context`, `reflect`, `testing`, and `types` — add `reflect` if not already imported by the file.

```go
type chainCapturingStore struct {
	captured []*types.ChainState
}

func (s *chainCapturingStore) AppendEvent(ctx context.Context, ev types.Event) error {
	// Composite stamps a fresh *ChainState per sink, so the captured
	// pointer is the sink-local copy — distinct from every other sink's.
	s.captured = append(s.captured, ev.Chain)
	return nil
}
func (s *chainCapturingStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return nil, nil
}
func (s *chainCapturingStore) Close() error { return nil }

func TestComposite_StampsChainBeforeFanout(t *testing.T) {
	primary := &chainCapturingStore{}
	other := &chainCapturingStore{}
	s := New(primary, nil, other)

	for i := 0; i < 5; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{ID: "e"}); err != nil {
			t.Fatalf("AppendEvent #%d: %v", i, err)
		}
	}

	if len(primary.captured) != 5 || len(other.captured) != 5 {
		t.Fatalf("captured counts: primary=%d other=%d", len(primary.captured), len(other.captured))
	}
	for i, p := range primary.captured {
		o := other.captured[i]
		if p == nil || o == nil {
			t.Fatalf("event %d: nil Chain — primary=%v other=%v", i, p, o)
		}
		if p.Sequence != uint64(i) || p.Generation != 0 {
			t.Errorf("primary event %d: Chain=(seq=%d,gen=%d) want (seq=%d,gen=0)", i, p.Sequence, p.Generation, i)
		}
		// Per-sink-copy contract: pointer-distinct across sinks but
		// value-equal. Use == on pointers (must differ) and DeepEqual
		// on dereferenced values (must match).
		if p == o {
			t.Errorf("event %d: sinks alias the same *ChainState pointer (%p); composite must stamp fresh per sink", i, p)
		}
		if !reflect.DeepEqual(*p, *o) {
			t.Errorf("event %d: sinks saw different Chain values: primary=%+v other=%+v", i, *p, *o)
		}
	}

	// Mutating one sink's captured ChainState must not affect the other's.
	primary.captured[0].Sequence = 0xDEADBEEF
	if other.captured[0].Sequence == 0xDEADBEEF {
		t.Errorf("per-sink-copy invariant violated: mutating primary leaked into other")
	}
}

func TestComposite_NextGeneration_ResetsSequence(t *testing.T) {
	primary := &chainCapturingStore{}
	s := New(primary, nil)

	for i := 0; i < 3; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{}); err != nil {
			t.Fatalf("AppendEvent #%d: %v", i, err)
		}
	}

	newGen, err := s.NextGeneration()
	if err != nil {
		t.Fatalf("NextGeneration: %v", err)
	}
	if newGen != 1 {
		t.Fatalf("NextGeneration() = %d, want 1", newGen)
	}

	if err := s.AppendEvent(context.Background(), types.Event{}); err != nil {
		t.Fatal(err)
	}

	last := primary.captured[len(primary.captured)-1]
	if last == nil || last.Sequence != 0 || last.Generation != 1 {
		t.Errorf("after rollover: Chain=(seq=%d,gen=%d) want (seq=0,gen=1)", last.Sequence, last.Generation)
	}
}
```

Note: this test imports `reflect` for `reflect.DeepEqual`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/store/composite/ -run "TestComposite_StampsChainBeforeFanout|TestComposite_NextGeneration_ResetsSequence" -v
```

Expected: build failure (`s.NextGeneration` undefined) OR test failure (`Chain` is nil because composite doesn't stamp).

- [ ] **Step 3: Add allocator field and stamp logic**

Edit `internal/store/composite/composite.go`. Add the audit import:

```go
import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
)
```

Replace the `Store` struct and `New` constructor (currently lines 14-23):

```go
type Store struct {
	primary       store.EventStore
	output        store.OutputStore
	others        []store.EventStore
	allocator     *audit.SequenceAllocator
	onAppendError func(error)
}

func New(primary store.EventStore, output store.OutputStore, others ...store.EventStore) *Store {
	return &Store{
		primary:   primary,
		output:    output,
		others:    others,
		allocator: audit.NewSequenceAllocator(),
	}
}
```

Replace `AppendEvent` (currently lines 29-64) — keep all existing error-collection logic, add the allocate+stamp prologue. Note the per-sink-copy pattern: the allocator is called ONCE per AppendEvent so all sinks see the same `(seq, gen)`, but each sink receives its own freshly-allocated `*ChainState` so no two sinks alias the same pointer. This is the runtime guarantee that backs the "Chain MUST be treated as read-only" contract on `pkg/types.ChainState`.

```go
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	// Phase 0: composite allocates the shared (seq, gen) once before fanout.
	seq, gen, err := s.allocator.Next()
	if err != nil {
		return err
	}

	// stampForSink returns ev with a FRESH *ChainState pointer so no two
	// sinks ever alias the same ChainState. This is the per-sink-copy
	// guarantee that prevents one sink's mutation from corrupting another.
	stampForSink := func() types.Event {
		stamped := ev
		stamped.Chain = &types.ChainState{Sequence: uint64(seq), Generation: gen}
		return stamped
	}

	var firstErr error
	var hookErr error
	if s.primary != nil {
		if err := s.primary.AppendEvent(ctx, stampForSink()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if hookErr == nil {
				hookErr = err
			}
			var fatal *store.FatalIntegrityError
			if errors.As(err, &fatal) {
				hookErr = fatal
			}
		}
	}
	for _, o := range s.others {
		if err := o.AppendEvent(ctx, stampForSink()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if hookErr == nil {
				hookErr = err
			}
			var fatal *store.FatalIntegrityError
			if errors.As(err, &fatal) {
				hookErr = fatal
			}
		}
	}
	if hookErr != nil && s.onAppendError != nil {
		s.onAppendError(hookErr)
	}
	return firstErr
}
```

Add `NextGeneration` method (place it directly below `AppendEvent`):

```go
// NextGeneration advances the shared sequence generation. The next
// AppendEvent stamps ev.Chain with (Sequence:0, Generation:newGen).
// Used by the composite owner when the chain key rotates.
//
// Returns ErrGenerationOverflow on uint32 wrap; the allocator is not
// modified in that case (see audit.SequenceAllocator.NextGeneration).
func (s *Store) NextGeneration() (uint32, error) {
	return s.allocator.NextGeneration()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/store/composite/ -v
```

Expected: all composite tests PASS, including the two new ones.

- [ ] **Step 5: Run the full test suite**

```bash
go test ./...
```

Expected: all tests PASS. The existing composite tests (`TestAppendEventCollectsFirstError`, `TestAppendEventErrorHookReceivesFirstError`, etc.) work because they use `fakeEventStore` which ignores `ev.Chain`.

- [ ] **Step 6: Commit**

```bash
git add internal/store/composite/composite.go internal/store/composite/composite_test.go
git commit -m "$(cat <<'EOF'
feat(composite): allocate shared (seq, gen) and stamp ev.Chain before fanout

Composite now owns a SequenceAllocator and stamps every event with the
allocated tuple before invoking sinks. Sinks that chain consume ev.Chain;
sinks that don't ignore it.

Adds NextGeneration() so the composite owner (the daemon) can trigger a
generation rollover; the next AppendEvent stamps (Sequence:0, Generation:N+1).

Phase 0 — see docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Phase 0 verification tests in `sequence_contract_test.go`

These are the three tests called out in the spec's `## Verification` section. They live in their own file because they exercise the contract end-to-end (allocator + chain + composite + a fake "second sink").

**Files:**
- Create: `internal/store/composite/sequence_contract_test.go`

- [ ] **Step 1: Write all three contract tests**

Create `internal/store/composite/sequence_contract_test.go`:

```go
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
// using a stable canonical encoding (id + seq + gen + payload) and runs
// each event through its own SinkChain. Every accepted event also produces
// a record so tests can compare what each sink saw.
type chainingFakeSink struct {
	chain      *audit.SinkChain
	mu         sync.Mutex
	records    []chainRecord
	failNext   error // if set, the next AppendEvent fails clean (no chain advance)
	failFatal  bool  // if set, the next AppendEvent fails ambiguously (Fatal)
	failedSeq  int64 // sequence at which failure was injected
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
```

- [ ] **Step 2: Run the contract tests**

```bash
go test ./internal/store/composite/ -run TestPhase0 -v
```

Expected: all 4 tests PASS (the spec calls #3 a single test but it's cleaner to split clean and ambiguous into two; both are listed under verification #3).

- [ ] **Step 3: Run the full test suite one more time**

```bash
go test ./...
```

Expected: all tests PASS across the repo.

- [ ] **Step 4: Verify Windows cross-compile per CLAUDE.md**

```bash
GOOS=windows go build ./...
```

Expected: clean build. Phase 0 changes are pure Go stdlib, no OS-specific code.

- [ ] **Step 5: Commit**

```bash
git add internal/store/composite/sequence_contract_test.go
git commit -m "$(cat <<'EOF'
test(composite): Phase 0 sequence-contract verification tests

Three (split into four) tests covering the spec's verification matrix:
1. Cross-sink (seq, gen) convergence over 10k events
2. Generation roll consistency: both sinks observe rollover at the same
   boundary; each sink's prev_hash independently resets to "".
3a. Clean durable failure does NOT advance prev_hash.
3b. Ambiguous failure latches Fatal; next Compute returns ErrFatalIntegrity.

Phase 0 — see docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Wrap-up

After all six tasks land, Phase 0 is complete. Verify by running:

```bash
go test ./pkg/types/ ./internal/audit/ ./internal/store/ ./internal/store/composite/ -v
GOOS=windows go build ./...
```

All tests should pass; cross-compile should be clean.

The next plan in this series will implement the WTP client itself — the new `internal/store/wtp/` sink that consumes `ev.Chain` via the contract this plan establishes. That plan has 12 implementation phases per the WTP spec; it will be written separately after Phase 0 lands.
