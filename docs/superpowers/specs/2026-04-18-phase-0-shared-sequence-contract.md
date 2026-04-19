# Phase 0: Shared Sequence Allocator + Sink-Local Chain Contract

**Date:** 2026-04-18
**Status:** Draft (contract specification; implementation tracked separately)
**Scope:** Defines the contract that the composite store and per-sink integrity chains must implement so multiple sinks can attest to the *same* logical event using a *shared* `(sequence, generation)` allocated once, with each sink computing its own *sink-local* hash.
**Related:**
- `docs/superpowers/specs/2026-04-18-wtp-client-design.md` (consumer of this contract)
- `docs/superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md` (existing single-sink chain)
- `docs/superpowers/specs/2026-04-11-hmac-chain-tamper-evidence-design.md` (sidecar, recovery)
- `internal/audit/integrity.go` (current implementation; refactor target)
- `internal/store/composite/composite.go` (current fanout; refactor target)
- `pkg/types/events.go` (target of typed `Chain` field)

## Why

Today, `internal/audit/integrity.IntegrityChain.Wrap()` does three things atomically under one mutex:

1. **Allocate** the next sequence (`c.sequence + 1`).
2. **Compute** the HMAC over `(format_version, sequence, prev_hash, canonical_payload)`.
3. **Commit** the result by updating `c.prevHash` to the new entry hash.

This is correct for a single sink, but two structural problems block multi-sink chaining:

1. **Allocation and hashing are conflated.** Multiple sinks need to attest to the same logical event. They must all see the same `(sequence, generation)` but compute *different* `entry_hash` values (different keys → different outputs). Today's API can't separate "who owns the counter" from "who owns the hash."
2. **Computation and commit are conflated.** If a sink writes the hashed payload to durable storage and the write fails *after* `prev_hash` was already updated, the chain is corrupted: the next event will hash against an entry that was never persisted. The existing `internal/store/integrity_wrapper.go` already handles this for the single-sink case via snapshot/restore + a fatal-latch on ambiguous failures; we need to inherit that discipline for every chained sink.

This contract solves both by introducing two distinct types and a transactional compute/commit protocol.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Where sequence advances** | A new `audit.SequenceAllocator` owned by composite. Allocates `(seq, gen)` exactly once per event, before fanout. | Single source of truth. Sinks never disagree on `(seq, gen)`. Allocator has no hash state; it only counts. |
| **Where prev_hash lives** | A new `audit.SinkChain` owned by each chained sink. Computes per-sink `entry_hash` from externally-supplied `(seq, gen, prev_hash, payload)`. | Lets each sink hash its own canonical payload with its own key. No shared mutable state across sinks. |
| **How sinks learn `(seq, gen)`** | A typed `Chain *ChainState` field on `pkg/types.Event` (not via `ev.Fields`). | Typed → can't accidentally leak into user-visible payloads. Untyped `_integrity_*` map keys would need a strip helper at every serializer; a typed field that's `json:"-"` cannot leak. |
| **Compute/commit split** | `SinkChain` exposes `Compute` (pure: returns `entryHash`, no mutation) and `Commit` (mutator: advances `prev_hash`). Caller does Compute → durable write → only-on-success Commit. | Clean failure of the durable write rolls back trivially (no commit, retry safe). Ambiguous failure latches `FatalIntegrityError` and locks the chain. |
| **Where the chain key lives** | Each sink resolves its own key (via existing `internal/audit/kms`). Composite knows nothing about sink keys. | Different sinks may use different keys. The Phase 0 contract is purely about `(seq, gen)` allocation, not key management. |
| **Refactor of `audit.IntegrityChain`** | Preserved as a convenience wrapper that internally composes a `SequenceAllocator` + `SinkChain`. The existing `Wrap()` method is unchanged at the source level. | Single-sink callers (today's JSONL primary when not in composite) keep working without code changes. |
| **Generation semantics** | Allocator owns generation; sequence resets to 0 on `NextGeneration()`. Each `SinkChain` resets its `prev_hash` to `""` when it first sees a new generation (signalled via the typed `Chain` field). | Matches WTP spec §6.4. Generation is a property of the shared allocator, not of any sink. |
| **Per-sink `TransportLoss` doesn't perturb the shared sequence** | Sinks that drop locally emit their own marker. The allocator does not roll back. | The shared sequence reflects what the system *produced*, not what each sink *delivered*. |

## Typed `Chain` Field

A typed field on `pkg/types.Event` carries the per-event chain state stamped by the composite store:

```go
// pkg/types/events.go (additive change)

type Event struct {
    // … existing fields unchanged …

    // Chain is the shared (sequence, generation) allocated by the composite
    // store before fanout. It is used by chained sinks to produce sink-local
    // integrity hashes.
    //
    // The field is intentionally json:"-" — it must never appear in any
    // user-visible serialization (audit log, query result, OTEL export).
    // Sinks that need it consume it directly; sinks that don't ignore it.
    //
    // Nil if composite did not stamp the event (e.g., test fixtures, single-
    // sink installations where chaining is disabled).
    Chain *ChainState `json:"-"`
}

type ChainState struct {
    Sequence   uint64
    Generation uint32
}
```

The `json:"-"` tag means the field is invisible to every JSON-based serializer in the codebase: JSONL store, OTEL export, webhook, gRPC stream (which uses protobuf, not JSON, but cannot accidentally include a Go field that's marked unexported-from-JSON for the JSONL fallback). The leak risk that motivates many of these protocols disappears at the type level.

### Backwards compatibility

- Adding a field to `types.Event` is source-compatible with all existing code.
- The field is `nil` when not set; chained sinks check for nil and either ignore (single-sink mode) or return `ErrMissingChainState` (multi-sink mode).
- No JSONL or OTEL output changes byte-for-byte for existing installations.

## API Refactor

### `internal/audit` — new types

```go
package audit

// SequenceAllocator owns the shared (sequence, generation) tuple. It has no
// hash state. Composite holds exactly one allocator.
type SequenceAllocator struct { /* mu, sequence int64, generation uint32 */ }

func NewSequenceAllocator() *SequenceAllocator

// Next returns the next (sequence, generation) and advances. Sequence is
// monotonic within a generation; generation does not change here.
// ErrSequenceOverflow if sequence == math.MaxInt64.
func (a *SequenceAllocator) Next() (sequence int64, generation uint32, err error)

// NextGeneration increments generation and resets sequence to -1, so the
// next Next() returns (0, new_generation). Used by the composite when the
// chain key rotates.
func (a *SequenceAllocator) NextGeneration() (generation uint32)

// State returns the current (sequence, generation) for persistence.
func (a *SequenceAllocator) State() AllocatorState

// Restore restores allocator state after restart. The next Next() returns
// (sequence + 1, generation).
func (a *SequenceAllocator) Restore(state AllocatorState)

type AllocatorState struct {
    Sequence   int64
    Generation uint32
}
```

```go
package audit

// SinkChain owns prev_hash for one sink. Each chained sink holds one.
// It is keyed: the same (seq, gen, prev_hash, payload) under different keys
// produces different entry_hash values, which is the entire point.
type SinkChain struct { /* mu, key, algorithm, generation, prevHash, fatal */ }

func NewSinkChain(key []byte, algorithm string) (*SinkChain, error)

// ComputeResult is the opaque, chain-bound token returned by
// SinkChain.Compute and consumed by SinkChain.Commit. All fields are
// unexported so callers cannot mutate or fabricate one outside the audit
// package; EntryHash() and PrevHash() expose the values for serialization.
// The result is identity-bound to the SinkChain instance that produced it
// (chain pointer pinned at Compute time); only that same chain's Commit
// will accept it. Commit enforces five invariants — nil result, post-fatal
// commit, cross-chain misuse, backwards-generation, and stale-token (same-
// generation prev_hash mismatch OR rollover-with-nonempty-prev) — with all
// integrity-affecting violations latching fatal rather than silently
// corrupting the chain.
//
// Lifecycle / serialization boundary: a ComputeResult is bound to the
// in-memory SinkChain instance that produced it. It is NOT a durable
// token — a SinkChain reconstructed via NewSinkChain + Restore is a new
// instance and will reject prior tokens with ErrCrossChainResult. Compute
// and Commit are designed to be co-located in a single process, with the
// durable write of the integrity metadata happening between them.
// EntryHash() and PrevHash() exist so that callers can persist the
// integrity metadata alongside the payload for later VerifyHash; they are
// NOT the input shape for reconstructing a Commit token across process
// boundaries.
type ComputeResult struct {
    // unexported: entryHash, prevHash, sequence, generation, chain
}

// EntryHash returns the HMAC entry hash that should be persisted alongside
// the payload for later integrity verification.
func (r *ComputeResult) EntryHash() string

// PrevHash returns the prev_hash the entry was chained against. For the
// genesis entry of a chain or generation, this is "".
func (r *ComputeResult) PrevHash() string

// Compute computes the HMAC over (formatVersion, sequence, prev_hash,
// canonical_payload) using the chain's key and returns it as an opaque,
// chain-bound *ComputeResult. PURE: it does not mutate prev_hash. The
// returned result is bound to this SinkChain instance — only Commit on
// this same chain will accept it; cross-chain commits fail with
// ErrCrossChainResult and latch the receiving chain fatal. The caller
// must follow with Commit on durable success or discard the result on
// durable failure.
//
// If generation differs from the chain's current generation, Compute
// treats prev_hash as "" (chain rolls automatically). The transition is
// committed only when Commit is called with the rollover result.
func (c *SinkChain) Compute(formatVersion int, sequence int64, generation uint32, payload []byte) (*ComputeResult, error)

// Commit advances prev_hash using the result of a previous Compute on
// this chain. Must be called exactly once per successful Compute, after
// the durable write succeeds. On ambiguous failure, the caller MUST call
// Fatal instead; Commit and Fatal are mutually exclusive per Compute.
//
// Four failure modes latch the chain Fatal and return a typed error
// (callers use errors.Is to detect):
//   - result.chain != c (ComputeResult was produced by a different
//     SinkChain instance) → wraps ErrCrossChainResult. Checked FIRST so
//     mixing tokens between chains always surfaces as cross-chain misuse,
//     not as a downstream invariant violation. Latches the receiving
//     chain only; the producing chain is unaffected.
//   - result.generation < c.generation → wraps ErrBackwardsGeneration.
//   - result.generation == c.generation but result.PrevHash() != c.prevHash
//     (stale token: a prior Commit advanced prev_hash) → wraps ErrStaleResult.
//   - result.generation > c.generation but result.PrevHash() != "" (rollover
//     results MUST have empty prev_hash) → wraps ErrStaleResult.
//
// nil result returns an error WITHOUT latching fatal (caller bug, not an
// integrity event). Calling Commit on an already-fatal chain returns
// ErrFatalIntegrity.
func (c *SinkChain) Commit(result *ComputeResult) error

// Fatal latches the chain in an unrecoverable state. All subsequent Compute
// calls return ErrFatalIntegrity. Used when a durable write returned an
// ambiguous error (timeout, partial write detection) — we cannot know
// whether the entry was persisted, so we cannot safely continue chaining.
func (c *SinkChain) Fatal(reason error)

// State returns (generation, prev_hash, fatal) for persistence. Fatal is
// included so a chain that latched before a restart comes back latched.
func (c *SinkChain) State() SinkChainState

// Restore restores chain state after restart. Validates prev_hash against
// the algorithm's expected hex length; rejects malformed input without
// mutating the chain.
func (c *SinkChain) Restore(generation uint32, prevHash string, fatal bool) error

type SinkChainState struct {
    Generation uint32
    PrevHash   string
    Fatal      bool
}

var (
    ErrFatalIntegrity      = errors.New("integrity chain latched fatal; sink must be reinitialized")
    ErrMissingChainState   = errors.New("event missing Chain field; composite did not stamp it")
    ErrInvalidChainState   = errors.New("invalid sink chain state")
    ErrBackwardsGeneration = errors.New("backwards-generation Commit: chain latched fatal")
    ErrStaleResult         = errors.New("stale ComputeResult: caller committed against an obsolete chain head; chain latched fatal")
    ErrCrossChainResult    = errors.New("ComputeResult bound to a different SinkChain")
)
```

### `audit.IntegrityChain.Wrap()` — preserved

The existing `Wrap()` is preserved verbatim as a convenience for single-sink callers:

```go
// IntegrityChain is the legacy single-sink composer of SequenceAllocator +
// SinkChain. New code should use the two types directly via the composite
// store's allocator and per-sink chains. Wrap/State/Restore are preserved
// at the source level for existing callers.
//
// Concurrency: Wrap, State, and Restore are serialized by an internal
// mutex so the wrapper preserves the legacy single-mutex atomicity
// contract. KeyFingerprint, VerifyHash, and VerifyWrapped do NOT take the
// wrapper mutex (they read immutable fields via the chain's own mutex).
type IntegrityChain struct {
    mu    sync.Mutex
    alloc *SequenceAllocator
    chain *SinkChain
}

func (c *IntegrityChain) Wrap(payload []byte) ([]byte, error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    seq, gen, err := c.alloc.Next()
    if err != nil { return nil, err }
    canonical := canonicalize(payload)
    result, err := c.chain.Compute(IntegrityFormatVersion, seq, gen, canonical)
    if err != nil { return nil, err }
    wrapped := buildJSON(payload, IntegrityMetadata{
        FormatVersion: IntegrityFormatVersion,
        Sequence:      seq,
        PrevHash:      result.PrevHash(),
        EntryHash:     result.EntryHash(),
    })
    if err := c.chain.Commit(result); err != nil {
        return nil, err
    }
    return wrapped, nil
}

func (c *IntegrityChain) State() ChainState {
    c.mu.Lock()
    defer c.mu.Unlock()
    a := c.alloc.State()
    s := c.chain.State()
    return ChainState{Sequence: a.Sequence, PrevHash: s.PrevHash}
}

func (c *IntegrityChain) Restore(sequence int64, prevHash string) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    // All-or-nothing: snapshot allocator, advance it, then attempt chain
    // restore. If chain restore rejects the prevHash, roll the allocator
    // back to its pre-call snapshot. Both component Restores validate
    // their input before mutating, so rolling back to a State() snapshot
    // cannot itself fail.
    prevAlloc := c.alloc.State()
    if err := c.alloc.Restore(AllocatorState{Sequence: sequence, Generation: 0}); err != nil {
        return fmt.Errorf("restore allocator: %w", err)
    }
    if err := c.chain.Restore(0, prevHash, false); err != nil {
        _ = c.alloc.Restore(prevAlloc) // rollback; cannot fail
        return fmt.Errorf("restore chain: %w", err)
    }
    return nil
}
```

For single-sink callers, durable success is implicit (Wrap returns the bytes; the caller writes them; if the write fails the caller never calls Wrap again on the same record). The single-sink case does not need the Compute/Commit split exposed because there is no fanout — but composite-mode callers absolutely do.

**Wrapper-level atomicity contract.** `IntegrityChain` holds a single `sync.Mutex` around `Wrap`, `State`, and `Restore`. This preserves the legacy single-mutex contract verbatim, even though the internals now compose two independently-locked components:

- **Concurrent `Wrap` calls serialize.** Two callers cannot interleave `alloc.Next()` from one with `chain.Compute()` / `chain.Commit()` from another, so chained sequences cannot end up linked to the wrong predecessor and the wrapper cannot latch fatal via `ErrStaleResult` from a benign concurrent caller.
- **`State` returns a consistent snapshot.** `(sequence, prev_hash)` is always observed at the same point in the chain — never a torn read where one value is from a Wrap that has not finished committing.
- **`Restore` is all-or-nothing.** If either the allocator or the chain rejects its input, the wrapper is left in its pre-call state. Implementation snapshots the allocator before mutating and rolls it back on chain-restore failure; the rollback restores a value that came from `State()` and therefore satisfies the allocator's `Sequence >= -1` invariant by construction.

`KeyFingerprint`, `VerifyHash`, and `VerifyWrapped` do NOT take the wrapper mutex. They read immutable key/algorithm material via the underlying `SinkChain`'s own mutex (`keyAndAlgorithm()`) and have no need for wrapper-level serialization. Adding the wrapper mutex there would be a lock-ordering risk and serves no purpose.

### `internal/store/composite/composite.go` — allocate + stamp + fanout

```go
type Store struct {
    primary       store.EventStore
    output        store.OutputStore
    others        []store.EventStore
    allocator     *audit.SequenceAllocator   // NEW: shared allocator
    onAppendError func(error)
}

func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
    // Phase 0: composite allocates the shared (seq, gen) before fanout.
    seq, gen, err := s.allocator.Next()
    if err != nil {
        return err  // typically ErrSequenceOverflow; caller treats as fatal
    }
    ev.Chain = &types.ChainState{
        Sequence:   uint64(seq),
        Generation: gen,
    }

    // Fan out — each sink that chains computes its own hash; the others ignore.
    var firstErr, hookErr error
    if s.primary != nil {
        if err := s.primary.AppendEvent(ctx, ev); err != nil {
            firstErr, hookErr = collectErr(firstErr, hookErr, err)
        }
    }
    for _, o := range s.others {
        if err := o.AppendEvent(ctx, ev); err != nil {
            firstErr, hookErr = collectErr(firstErr, hookErr, err)
        }
    }
    if hookErr != nil && s.onAppendError != nil {
        s.onAppendError(hookErr)
    }
    return firstErr
}

// NextGeneration is called by the composite owner (the daemon) when the
// chain key rotates. All chained sinks observe the new generation on the
// next event.
func (s *Store) NextGeneration() uint32 {
    return s.allocator.NextGeneration()
}
```

The error-hook semantics (`onAppendError`, `FatalIntegrityError` detection) of the current composite are preserved verbatim; only the sequence-allocation step is added.

### Sink integration — the transactional pattern

Sinks that chain (JSONL primary in composite mode, WTP, any future chained sink) follow this exact pattern:

```go
func (s *MySink) AppendEvent(ctx context.Context, ev types.Event) error {
    if ev.Chain == nil {
        return audit.ErrMissingChainState
    }
    canonical := s.encode(ev)

    // Step 1: pure compute — no chain mutation yet. Returns a typed
    // *ComputeResult that Commit will validate.
    result, err := s.chain.Compute(
        formatVersion, int64(ev.Chain.Sequence), ev.Chain.Generation, canonical,
    )
    if err != nil {
        return err  // includes ErrFatalIntegrity if a previous append latched fatal
    }

    // Step 2: durable write. Failure modes split three ways.
    werr := s.writeDurable(canonical, result.EntryHash(), result.PrevHash())
    switch {
    case werr == nil:
        // Step 3a: clean success → commit. A non-nil error from Commit means
        // the chain just latched fatal (backwards generation, stale token, or
        // rollover-with-nonempty-prev) and must be surfaced to the caller.
        if err := s.chain.Commit(result); err != nil {
            return err
        }
        return nil

    case errors.Is(werr, errCleanFailure):
        // Step 3b: clean failure → no commit, chain unchanged. Caller may retry.
        return werr

    default:
        // Step 3c: ambiguous failure → latch fatal. We cannot know whether
        // the write landed, so any future chaining would be unsound.
        s.chain.Fatal(werr)
        return werr
    }
}
```

The classification of `errCleanFailure` vs ambiguous is sink-specific and must be documented per sink. For example:

- **WAL.Append**: a returned error from `os.Write` *before* the system call has been issued (parameter validation, closed file) is clean. An error from `os.Write` itself, or from `f.Sync()`, is ambiguous — the bytes may have hit the platter. Default: ambiguous.
- **Network sends** (no chained sink does this synchronously; WTP buffers via WAL first): always ambiguous.
- **In-memory checks before any I/O**: clean.

Sinks that do not chain (OTel, webhook in non-chained configurations) ignore `ev.Chain` entirely.

## Generation Roll

When the composite owner rotates the chain key:

1. Owner calls `composite.NextGeneration()` → returns new generation.
2. Next `AppendEvent` call allocates `(seq=0, gen=new)`.
3. Each chained sink observes `ev.Chain.Generation` differs from its `SinkChain.State().Generation`. `SinkChain.Compute` automatically uses `prev_hash = ""` for the new generation and returns a `*ComputeResult` whose `PrevHash()` is `""` — the rollover signal. `Commit(result)` records the new generation.
4. Per-sink work (e.g., WTP forces a batch flush + WAL segment roll + `SessionUpdate`) is triggered by the sink observing the generation change in `ev.Chain.Generation`.

Generation is a property of the *shared allocator*, not of any individual sink. All sinks roll on the same logical event boundary — the first event with the new generation.

## TransportLoss Semantics

Per-sink loss does not perturb the shared sequence. Example:

- Composite allocates seq=100 (gen=7).
- JSONL writes seq=100 successfully.
- WTP cannot write seq=100 (WAL full): drops it locally, emits a `TransportLoss{from_seq:100, to_seq:100, generation:7}` marker into its own WAL.
- Composite allocates seq=101 (gen=7).
- Both sinks write seq=101.

An auditor reconstructing the WTP stream sees `..., 99, TransportLoss(100), 101, ...` — the gap is explicit. An auditor reconstructing the JSONL stream sees `..., 99, 100, 101, ...` — no gap, because that sink delivered. Cross-correlating reveals which sink lost what.

The shared sequence is therefore a property of *what the system produced*, not of *what each sink delivered*. This is the only consistent interpretation that lets sinks have different durability profiles.

## Migration

This refactor is **invisible** to single-sink installations:

- The legacy `audit.IntegrityChain.Wrap()` API is unchanged at the source level. Existing callers compile and run without modification.
- The new `Chain` field on `types.Event` is `json:"-"` and additive; existing JSON output is byte-identical.
- Only when composite is configured with a chained sink besides the primary, *or* when WTP is enabled, does the composite begin allocating and stamping `ev.Chain`. Until that moment, `ev.Chain` is `nil` and chained sinks fall back to either erroring (strict mode) or behaving as ungrounded (lenient mode, dev only).

## Verification

Three new tests in `internal/store/composite/sequence_contract_test.go`:

1. **Cross-sink `(seq, gen)` convergence:** With two chained sinks (JSONL + a fake WTP using identical canonical encoding and the same key), every record's `(seq, gen)` matches between the two. Run for 10,000 events. `entry_hash` is *not* asserted equal in the general case — sinks that hash different canonical bytes will produce different entry hashes by design; the assertion narrows to "if both sinks hash the same canonical bytes with the same key, then `entry_hash` matches."
2. **Generation roll consistency:** After a `composite.NextGeneration()` call, both sinks observe the rollover at the same event boundary; sequence resets to 0 in both; each sink's `prev_hash` resets to `""` independently.
3. **Transactional rollback:** A fake sink that fails its durable write with `errCleanFailure` does NOT advance its `SinkChain.prev_hash`. After the failure, a successful write of a NEW event uses the previous (pre-failure) `prev_hash` — proving rollback is correct. A second test injects an ambiguous failure and asserts `SinkChain.Compute` returns `ErrFatalIntegrity` on every subsequent call.

## Out-of-Scope

- The actual WTP client implementation (separate doc).
- KMS-backed key rotation automation (existing `internal/audit/kms` is unchanged; the *trigger* for `composite.NextGeneration()` is operator-driven for now).
- Surfacing `Chain` in any user-visible API. The field is `json:"-"` and used only by chained sinks internally.
