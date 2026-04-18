# Phase 0: Shared Sequence + Generation Contract

**Date:** 2026-04-18
**Status:** Draft (contract specification; implementation tracked separately)
**Scope:** Defines the contract that the composite store and per-sink integrity chains must implement so that multiple sinks can chain over a *shared* sequence/generation while computing *sink-local* hashes.
**Related:**
- `docs/superpowers/specs/2026-04-18-wtp-client-design.md` (consumer of this contract)
- `docs/superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md` (existing single-sink chain)
- `docs/superpowers/specs/2026-04-11-hmac-chain-tamper-evidence-design.md` (sidecar, recovery)
- `internal/audit/integrity.go` (current implementation; refactor target)
- `internal/store/composite/composite.go` (current fanout; refactor target)

## Why

Today, `internal/audit/integrity.IntegrityChain.Wrap()` does two things atomically under one mutex:

1. **Advance** the chain's sequence (`c.sequence + 1`) and update `c.prevHash`.
2. **Compute** the HMAC over `(format_version, sequence, prev_hash, canonical_payload)`.

This works for a single sink. It does not work when multiple sinks need to attest to the *same* logical event with their *own* HMAC keys, because:

- Each sink computes its own `entry_hash` (different key → different output).
- All sinks must agree on `(sequence, generation)` so an auditor can correlate records across sinks.
- The composite store must therefore advance `(sequence, generation)` *once*, then hand them to every sink for its own hashing.

WTP (the new Watchtower sink) is the immediate consumer of this refactor, but the contract is general: any future sink that chains will use it the same way.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Where sequence advances** | In `composite.Store.AppendEvent`, *once*, before fanout. | Single source of truth. Sinks can never disagree on what `(seq, gen)` an event has. |
| **How sinks learn `(seq, gen)`** | Via well-known `ev.Fields` keys (`_integrity_seq`, `_integrity_generation`). | Doesn't require changing `store.EventStore` interface. Sinks that don't care can ignore the fields. |
| **Field name prefix** | `_integrity_` | Underscore prefix marks "internal/transport metadata", consistent with how OTel SDKs mark non-user attrs. We document that fields starting with `_` are reserved. |
| **Field types** | `uint64` for sequence, `uint32` for generation. | Matches WTP wire format. JSON encoders that round-trip via `float64` will lose precision near the top of uint64 — sinks must use the typed accessor (a small helper in `internal/store`) to read these. |
| **Where the chain key lives** | Composite holds a single shared key resolver; injects per-sink `chain.Key` at sink construction. | Different sinks may use different keys (or the same key); composite is the only place that knows about all of them. |
| **Refactor of `audit.IntegrityChain`** | Split `Wrap` into `AdvanceSequence` + `ComputeHash`. Existing `Wrap` becomes a convenience wrapper that calls both atomically (preserves all current call sites). | Lets composite call `AdvanceSequence` once and pass `(seq, gen)` to each sink for `ComputeHash`. Existing single-sink callers (the JSONL primary) continue to use `Wrap` unchanged. |
| **Generation semantics** | Generation increments on key rotation. Sequence resets to 0 on a new generation. `prev_hash = ""` on the first record of a new generation. | Matches WTP spec §6.4 (`generation` field) and the existing rotation expectation in the integrity-tamper-evidence doc. |
| **TransportLoss on shared sequence** | Each sink that drops records (e.g., WTP WAL overflow) emits its *own* TransportLoss marker locally. The shared sequence is **not** affected by per-sink loss. | Loss is per-sink. The shared sequence reflects what the system *produced*, not what each sink *delivered*. An auditor reconstructing the chain across sinks correlates by `(seq, gen)`; gaps in one sink reveal gaps in delivery, not in production. |

## Field Contract

The composite store stamps two fields on every `types.Event` *before* fanning out to sinks:

```go
ev.Fields["_integrity_seq"]        = uint64(seq)   // monotonic, gap-free per generation
ev.Fields["_integrity_generation"] = uint32(gen)   // increments on key rotation; seq resets to 0
```

### Reserved field-name prefix

Field names starting with `_integrity_` are reserved for the composite store and must not be set by event producers. Sinks must treat them as transport metadata and not surface them as user-visible event fields. (For example, the WTP `compact.Encoder` strips `_integrity_*` before projecting into the OCSF payload.)

### Reading the fields

Sinks use a typed helper in `internal/store/chainstate` (new package, ~40 lines):

```go
package chainstate

import "github.com/agentsh/agentsh/pkg/types"

type State struct {
    Sequence   uint64
    Generation uint32
}

// FromEvent extracts the shared chain state stamped by the composite store.
// Returns (State, true) if both fields are present and well-typed; (State, false)
// otherwise. Sinks should treat (State, false) as a programming error and emit
// a counter rather than guessing.
func FromEvent(ev types.Event) (State, bool)

// MustFromEvent panics if either field is missing. For tests only.
func MustFromEvent(ev types.Event) State
```

The helper handles JSON-decoded variants (`float64`, `json.Number`) the same way `internal/audit/integrity.go`'s `jsonInt64` does, so a sink that receives an event from JSONL replay (where the field came back as `float64`) and a sink that receives it directly from the in-memory composite both see the same `State`.

## API Refactor

### `internal/audit/integrity.go` — split Wrap

Today:

```go
// Wrap adds integrity metadata to an event payload. Advances sequence and
// computes hash atomically.
func (c *IntegrityChain) Wrap(payload []byte) ([]byte, error)
```

After Phase 0:

```go
// AdvanceSequence allocates the next (sequence, generation) under the chain's
// mutex and returns it. Does not compute or update prev_hash. The caller is
// responsible for calling ComputeHash with the returned sequence.
func (c *IntegrityChain) AdvanceSequence() (sequence int64, generation uint32, err error)

// ComputeHash computes the HMAC over (format_version, sequence, prev_hash,
// canonical_payload) and updates the chain's prev_hash. Must be called
// exactly once per AdvanceSequence call, with the same sequence value.
// If a caller fails to call ComputeHash after AdvanceSequence, the chain
// becomes inconsistent — callers should treat this as a fatal condition.
func (c *IntegrityChain) ComputeHash(formatVersion int, sequence int64, payload []byte) (prevHash, entryHash string, err error)

// Wrap is preserved for backwards compatibility. It internally calls
// AdvanceSequence + ComputeHash + builds the JSON payload.
func (c *IntegrityChain) Wrap(payload []byte) ([]byte, error)
```

The mutex is still held across the *pair* of operations when called via `Wrap` (composite path will not use Wrap; it will hold its own mutex around the pair). This is necessary because `prev_hash` depends on the previous `entry_hash`.

### `internal/store/composite/composite.go` — advance + fanout

```go
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
    // Phase 0: composite owns sequence advancement.
    seq, gen, err := s.chain.AdvanceSequence()
    if err != nil {
        return err
    }
    ev.Fields = ensureFields(ev.Fields)
    ev.Fields["_integrity_seq"]        = uint64(seq)
    ev.Fields["_integrity_generation"] = gen

    // Fan out — each sink computes its own hash from (seq, gen).
    var firstErr error
    if s.primary != nil {
        if err := s.primary.AppendEvent(ctx, ev); err != nil && firstErr == nil {
            firstErr = err
        }
    }
    for _, o := range s.others {
        if err := o.AppendEvent(ctx, ev); err != nil && firstErr == nil {
            firstErr = err
        }
    }
    return firstErr
}
```

The error-hook semantics (`onAppendError`, `FatalIntegrityError` detection) of the current composite are preserved verbatim; only the sequence-advance position changes.

### Sink integration

Sinks that chain (JSONL primary, WTP, any future chained sink) read `(seq, gen)` from `ev.Fields` and compute their own hash:

```go
func (s *MySink) AppendEvent(ctx context.Context, ev types.Event) error {
    state, ok := chainstate.FromEvent(ev)
    if !ok {
        return ErrMissingChainState  // composite did not stamp the event
    }
    canonicalPayload := s.encode(ev)
    prevHash, entryHash, err := s.chain.ComputeHash(formatVersion, int64(state.Sequence), canonicalPayload)
    if err != nil {
        return err
    }
    return s.write(state, prevHash, entryHash, canonicalPayload)
}
```

Sinks that don't chain (OTel, webhook) ignore the fields entirely.

## Generation Roll

When the composite's chain key rotates:

1. Composite calls `chain.NextGeneration()` (new helper) which:
   - Acquires the chain mutex.
   - Increments `c.generation`.
   - Resets `c.sequence = -1` (so the next `AdvanceSequence` returns 0).
   - Sets `c.prevHash = ""`.
   - Releases the mutex.
2. The next `AdvanceSequence` returns `(0, new_gen)`.
3. Sinks observe the new generation in `ev.Fields["_integrity_generation"]`. Each sink takes its own action:
   - JSONL: writes a marker line.
   - WTP: forces a batch flush, segment roll, and `SessionUpdate`.

Generation is a property of the *shared* chain, not of any sink. All sinks see the same rollover at the same logical event boundary.

## TransportLoss Semantics

Per-sink loss does not perturb the shared sequence. Example:

- Composite advances seq=100 (gen=7).
- JSONL writes seq=100 successfully.
- WTP cannot write seq=100 (WAL full): it drops it locally and emits a `TransportLoss{from_seq:100, to_seq:100, generation:7}` marker into its own WAL.
- Composite advances seq=101 (gen=7).
- Both sinks write seq=101.

An auditor reconstructing the WTP stream sees: `..., 99, TransportLoss(100), 101, ...` — the gap is explicit. An auditor reconstructing the JSONL stream sees: `..., 99, 100, 101, ...` — no gap, because that sink delivered. Cross-correlating the two streams reveals which sink lost what.

The shared sequence is therefore a property of *what the system produced*, not of *what each sink delivered*. This is the only consistent interpretation that lets sinks have different durability profiles.

## Migration

This refactor is **invisible** to single-sink installations:

- `Wrap()` is preserved unchanged. Callers using `Wrap` (today: the integrity wrapper around JSONL when there's only one sink) continue to work.
- Only when the composite store is configured with `>1` chained sink, or when WTP is enabled, does the new `AdvanceSequence + ComputeHash` path activate.
- The reserved `_integrity_*` field prefix is new — we add a startup check that rejects user-supplied event fields starting with `_integrity_` (today no such fields exist; this is purely defensive).

## Verification

The refactor is self-verifying via existing tests if we add three new ones:

1. **Cross-sink convergence:** With two chained sinks (JSONL + a fake WTP using the same key), every record's `(seq, gen, entry_hash)` matches between the two. Run for 10,000 events.
2. **Per-sink divergence with different keys:** With two chained sinks using *different* keys, `(seq, gen)` matches but `entry_hash` differs.
3. **Generation roll consistency:** After a `NextGeneration()` call, both sinks observe the rollover at the same event boundary; sequence resets to 0 in both.

These live in `internal/store/composite/sequence_contract_test.go` (new file) and use a fake `EventStore` that records the `(seq, gen)` it sees per event.

## Out-of-Scope

- The actual WTP client implementation (separate doc).
- KMS-backed key rotation automation (existing `internal/audit/kms` is unchanged).
- Surfacing `_integrity_*` fields in any user-visible API (they are strictly internal transport metadata).
