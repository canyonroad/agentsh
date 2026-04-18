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
- `internal/audit/integrity.go` — refactor `IntegrityChain` internals to compose `SequenceAllocator` + `SinkChain`; preserve all public method signatures (`NewIntegrityChain`, `NewIntegrityChainWithAlgorithm`, `Wrap`, `State`, `Restore`, `KeyFingerprint`, `VerifyHash`, `VerifyWrapped`)
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
	// integrity hashes.
	//
	// json:"-" is load-bearing: this field must never appear in any
	// user-visible serialization. Tested by TestEvent_ChainFieldNotMarshaled.
	Chain *ChainState `json:"-"`
}
```

Then add the `ChainState` type at the end of the file (after the `EventQuery` struct):

```go
// ChainState is the shared (sequence, generation) tuple stamped on each event
// by the composite store before fanout to chained sinks. See
// docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md.
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

Adds pkg/types.ChainState{Sequence, Generation} and an Event.Chain pointer
field with json:"-" so the composite store can stamp the shared sequence
tuple onto events without ever leaking it into JSONL, OTEL, gRPC, webhook
or any future serializer. Tested by TestEvent_ChainFieldNotMarshaled.

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

	newGen := a.NextGeneration()
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
	a.NextGeneration()
	if _, _, err := a.Next(); err != nil {
		t.Fatal(err)
	}
	// State: sequence=0, gen=1.

	state := a.State()
	if state.Sequence != 0 || state.Generation != 1 {
		t.Fatalf("State() = %+v, want {Sequence:0 Generation:1}", state)
	}

	b := NewSequenceAllocator()
	b.Restore(state)
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
	a.Restore(AllocatorState{Sequence: math.MaxInt64, Generation: 0})

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
	"math"
	"sync"
)

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
func (a *SequenceAllocator) NextGeneration() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.generation++
	a.sequence = -1
	return a.generation
}

// State returns the current (sequence, generation) for persistence. After
// Restore(state), the next Next() returns (state.Sequence + 1, state.Generation).
func (a *SequenceAllocator) State() AllocatorState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AllocatorState{Sequence: a.sequence, Generation: a.generation}
}

// Restore rehydrates allocator state after restart.
func (a *SequenceAllocator) Restore(state AllocatorState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sequence = state.Sequence
	a.generation = state.Generation
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

	entryHash, prevHash, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if prevHash != "" {
		t.Errorf("first Compute: prevHash = %q, want empty", prevHash)
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 0, "", payload)
	if entryHash != want {
		t.Errorf("entryHash = %q, want %q", entryHash, want)
	}
}

func TestSinkChain_Compute_IsPure_NoMutationWithoutCommit(t *testing.T) {
	c, _ := newTestSinkChain(t)
	payload := []byte(`{"k":"v"}`)

	first, _, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Compute again without Commit — must produce the SAME entryHash, since
	// prev_hash hasn't moved.
	second, _, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("Compute mutated chain state: first=%q second=%q", first, second)
	}
}

func TestSinkChain_Commit_AdvancesPrevHash(t *testing.T) {
	c, key := newTestSinkChain(t)

	first, _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	c.Commit(0, first)

	second, prev, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if prev != first {
		t.Errorf("after Commit: prev_hash = %q, want %q", prev, first)
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 1, first, []byte(`{"b":2}`))
	if second != want {
		t.Errorf("second entryHash = %q, want %q", second, want)
	}
}

func TestSinkChain_Compute_GenerationRollover_ResetsPrevToEmpty(t *testing.T) {
	c, key := newTestSinkChain(t)

	// Establish gen=0 chain with one committed entry.
	h0, _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	c.Commit(0, h0)

	// Compute at gen=1 — prev_hash should be "" automatically.
	h1, prev, err := c.Compute(IntegrityFormatVersion, 0, 1, []byte(`{"y":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if prev != "" {
		t.Errorf("after gen rollover: prev_hash = %q, want empty", prev)
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 0, "", []byte(`{"y":2}`))
	if h1 != want {
		t.Errorf("rolled entryHash = %q, want %q", h1, want)
	}

	// Until Commit(1, h1), the chain's recorded generation is still 0.
	state := c.State()
	if state.Generation != 0 {
		t.Errorf("State.Generation before Commit = %d, want 0", state.Generation)
	}

	c.Commit(1, h1)
	state = c.State()
	if state.Generation != 1 {
		t.Errorf("State.Generation after Commit = %d, want 1", state.Generation)
	}
	if state.PrevHash != h1 {
		t.Errorf("State.PrevHash = %q, want %q", state.PrevHash, h1)
	}
}

func TestSinkChain_Fatal_LatchesAndBlocksFurtherCompute(t *testing.T) {
	c, _ := newTestSinkChain(t)

	if _, _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}

	c.Fatal(errors.New("ambiguous WAL write"))

	_, _, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if !errors.Is(err, ErrFatalIntegrity) {
		t.Fatalf("Compute after Fatal: err = %v, want ErrFatalIntegrity", err)
	}
}

func TestSinkChain_State_Restore_RoundTrip(t *testing.T) {
	c, _ := newTestSinkChain(t)

	h0, _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	c.Commit(0, h0)
	h1, _, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	c.Commit(0, h1)

	state := c.State()
	if state.Generation != 0 || state.PrevHash != h1 {
		t.Fatalf("State() = %+v, want {Generation:0 PrevHash:%q}", state, h1)
	}

	d, _ := newTestSinkChain(t)
	d.Restore(state.Generation, state.PrevHash)

	// Continue the chain from d — same key, so same entry hash as if c
	// had continued.
	cNext, _, err := c.Compute(IntegrityFormatVersion, 2, 0, []byte(`{"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	dNext, _, err := d.Compute(IntegrityFormatVersion, 2, 0, []byte(`{"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	if cNext != dNext {
		t.Errorf("after Restore: entryHash mismatch %q vs %q", cNext, dNext)
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

func TestSinkChain_Concurrent_ComputeCommit_NoChainBreakage(t *testing.T) {
	c, key := newTestSinkChain(t)

	// Single owner serializes Compute+Commit pairs; this test asserts that
	// repeated Compute under contention with Commit does not produce a
	// chain that fails verification when replayed in committed order.
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
			entry, prev, err := c.Compute(IntegrityFormatVersion, i, 0, payload)
			if err != nil {
				t.Errorf("Compute %d: %v", i, err)
				return
			}
			c.Commit(0, entry)
			mu.Lock()
			records = append(records, record{seq: i, payload: payload, entryHash: entry, prevHash: prev})
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
// Concurrency-safe. Compute+Commit pairs must be issued by a single
// goroutine in order; concurrent Compute calls with interleaved Commits
// is supported but each Commit applies to the most recent Compute that
// observed the same prev_hash.
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
type SinkChainState struct {
	Generation uint32
	PrevHash   string
}

// ErrFatalIntegrity is returned by Compute after Fatal has been called.
// The chain cannot be reused; the sink must be reinitialized (e.g., via
// generation rotation).
var ErrFatalIntegrity = errors.New("integrity chain latched fatal; sink must be reinitialized")

// ErrMissingChainState is returned by chained sinks when an event arrives
// without ev.Chain set (i.e., composite did not stamp it). Production
// configurations with chained sinks must always run inside a composite
// with a SequenceAllocator.
var ErrMissingChainState = errors.New("event missing Chain field; composite did not stamp it")

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
// using the chain's key. Compute is PURE: it does not mutate prev_hash. The
// caller must follow with Commit on durable-write success or discard the
// result on durable-write failure.
//
// If `generation` differs from the chain's current generation, prev_hash
// is treated as "" for this Compute (chain rolls automatically). The
// transition is committed only when Commit is called with the new generation.
//
// Returns ErrFatalIntegrity if Fatal was previously called.
func (c *SinkChain) Compute(formatVersion int, sequence int64, generation uint32, payload []byte) (entryHash string, prevHash string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fatal {
		return "", "", ErrFatalIntegrity
	}
	prev := c.prevHash
	if generation != c.generation {
		prev = ""
	}
	hash, err := computeIntegrityHash(c.key, c.algorithm, formatVersion, sequence, prev, payload)
	if err != nil {
		return "", "", err
	}
	return hash, prev, nil
}

// Commit advances prev_hash to entryHash and records the generation. Must be
// called exactly once per successful Compute, after the durable write
// succeeds. On ambiguous failure (write may or may not have landed), the
// caller MUST call Fatal instead; Commit and Fatal are mutually exclusive
// per Compute.
func (c *SinkChain) Commit(generation uint32, entryHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fatal {
		return
	}
	c.generation = generation
	c.prevHash = entryHash
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

// State returns the (generation, prev_hash) for persistence.
func (c *SinkChain) State() SinkChainState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SinkChainState{Generation: c.generation, PrevHash: c.prevHash}
}

// Restore rehydrates chain state after restart.
func (c *SinkChain) Restore(generation uint32, prevHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation = generation
	c.prevHash = prevHash
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/audit/ -run "TestSinkChain|TestNewSinkChain" -v
```

Expected: all 9 tests PASS.

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
type IntegrityChain struct {
	alloc *SequenceAllocator
	chain *SinkChain
}
```

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

	entryHash, prevHash, err := c.chain.Compute(IntegrityFormatVersion, seq, gen, canonicalPayload)
	if err != nil {
		return nil, err
	}

	data["integrity"] = IntegrityMetadata{
		FormatVersion: IntegrityFormatVersion,
		Sequence:      seq,
		PrevHash:      prevHash,
		EntryHash:     entryHash,
	}

	result, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal wrapped payload: %w", err)
	}

	c.chain.Commit(gen, entryHash)
	return result, nil
}
```

Single-sink callers don't expose Compute/Commit because there's no fanout; the legacy contract is "Wrap returns the bytes; if the caller's write fails, the caller never calls Wrap again on the same record." That contract is preserved — Commit happens inside Wrap.

- [ ] **Step 4: Replace `State()` to delegate**

Replace the body of `State()` (currently lines 254-262) with:

```go
// State returns the last written chain state for persistence.
func (c *IntegrityChain) State() ChainState {
	allocState := c.alloc.State()
	chainState := c.chain.State()
	return ChainState{
		Sequence: allocState.Sequence,
		PrevHash: chainState.PrevHash,
	}
}
```

- [ ] **Step 5: Replace `Restore()` to delegate**

Replace the body of `Restore()` (currently lines 264-271) with:

```go
// Restore restores the chain state after a restart.
// The sequence must be the last written entry so the next Wrap continues at sequence+1.
func (c *IntegrityChain) Restore(sequence int64, prevHash string) {
	c.alloc.Restore(AllocatorState{Sequence: sequence, Generation: 0})
	c.chain.Restore(0, prevHash)
}
```

Note: legacy `IntegrityChain` does not expose generation (its callers were single-sink with no rotation concept beyond key change, which today is handled via key-fingerprint mismatch detection in `internal/store/integrity_wrapper.go`). We pin generation=0 to keep behavior identical.

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

Expected: clean build; all existing audit tests PASS without modification. Tests that exercise `chain.Restore(...)`, `chain.State()`, `chain.Wrap(...)` round-trips, sequence overflow at MaxInt64 — all of these continue to behave identically.

If any test fails, the most likely culprits are:
- `Restore` not pinning generation correctly (chain.Restore(0, prevHash) is required)
- `State()` returning wrong sequence after Wrap (allocator's `State()` is the last-returned sequence, which matches what the old code stored in `c.sequence`)
- Overflow test expecting `c.sequence == math.MaxInt64` — the new code triggers overflow inside `c.alloc.Next()` and returns `ErrSequenceOverflow` from there, identical to the old behavior

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

Append to `internal/store/composite/composite_test.go`. No new imports needed — the test uses only `context`, `testing`, and `types` (all already imported).

```go
type chainCapturingStore struct {
	captured []*types.ChainState
}

func (s *chainCapturingStore) AppendEvent(ctx context.Context, ev types.Event) error {
	if ev.Chain != nil {
		copy := *ev.Chain
		s.captured = append(s.captured, &copy)
	} else {
		s.captured = append(s.captured, nil)
	}
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
			t.Errorf("primary event %d: Chain=%+v want {Sequence:%d Generation:0}", i, p, i)
		}
		if *p != *o {
			t.Errorf("event %d: sinks saw different Chain: primary=%+v other=%+v", i, p, o)
		}
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

	newGen := s.NextGeneration()
	if newGen != 1 {
		t.Fatalf("NextGeneration() = %d, want 1", newGen)
	}

	if err := s.AppendEvent(context.Background(), types.Event{}); err != nil {
		t.Fatal(err)
	}

	last := primary.captured[len(primary.captured)-1]
	if last == nil || last.Sequence != 0 || last.Generation != 1 {
		t.Errorf("after rollover: Chain=%+v want {Sequence:0 Generation:1}", last)
	}
}
```

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

Replace `AppendEvent` (currently lines 29-64) — keep all existing error-collection logic, add the allocate+stamp prologue:

```go
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	seq, gen, err := s.allocator.Next()
	if err != nil {
		return err
	}
	ev.Chain = &types.ChainState{
		Sequence:   uint64(seq),
		Generation: gen,
	}

	var firstErr error
	var hookErr error
	if s.primary != nil {
		if err := s.primary.AppendEvent(ctx, ev); err != nil {
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
		if err := o.AppendEvent(ctx, ev); err != nil {
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
func (s *Store) NextGeneration() uint32 {
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
	canonical := []byte(`{"id":"` + ev.ID + `","seq":` + strconv.FormatUint(ev.Chain.Sequence, 10) + `,"gen":` + strconv.FormatUint(uint64(ev.Chain.Generation), 10) + `}`)

	entryHash, prevHash, err := s.chain.Compute(audit.IntegrityFormatVersion, int64(ev.Chain.Sequence), ev.Chain.Generation, canonical)
	if err != nil {
		return err
	}

	s.mu.Lock()
	failClean := s.failNext
	failAmbiguous := s.failFatal
	if failClean != nil {
		s.failedSeq = int64(ev.Chain.Sequence)
		s.failNext = nil
	}
	if failAmbiguous {
		s.failedSeq = int64(ev.Chain.Sequence)
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
		s.chain.Commit(ev.Chain.Generation, entryHash)
		s.mu.Lock()
		s.records = append(s.records, chainRecord{
			Sequence:   ev.Chain.Sequence,
			Generation: ev.Chain.Generation,
			EntryHash:  entryHash,
			PrevHash:   prevHash,
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

	gen := s.NextGeneration()
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
