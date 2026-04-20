# Watchtower Transport Protocol (WTP) Client Design

**Date:** 2026-04-18
**Status:** Draft
**Spec:** AgentSH → Watchtower Transport Protocol v0.4.9-draft
**Scope:** Phase 2 only — client library (no server, no OCSF mapper, no composite refactor)
**Related:**
- `docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md` (sequence/generation contract)
- `docs/superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md` (existing chain wiring)
- `docs/superpowers/specs/2026-04-11-hmac-chain-tamper-evidence-design.md` (sidecar, recovery)
- `docs/superpowers/specs/2026-04-13-deferred-sync-audit-write-design.md` (deferred-sync model reused for WAL)

## Problem

AgentSH today persists audit events to local sinks: SQLite (queryable, optional), JSONL (durable, append-only), OTEL (export to collector), and webhook (HTTP push). For Watchtower — the agentic-fleet console — we need a fifth sink that ships events over a long-lived gRPC connection with the WTP wire protocol: TLS 1.3, OCSF-aligned `CompactEvent`, HMAC chain with sink-local hashes over a shared sequence, WAL-backed at-least-once delivery, batching, compression, reconnect with replay, and `TransportLoss` markers when the WAL must drop records.

This design covers the **client library only**. The server side, the OCSF schema mapper (Phase 1), and the composite-store sequence refactor (Phase 0) are prerequisites whose contracts are documented but whose implementation is not part of this work.

## Goals

- New sink `internal/store/watchtower/` implementing `store.EventStore`.
- Faithful implementation of WTP v0.4.9 §6 (integrity), §7 (wire format), §8 (transport), §10 (config).
- Survives network failures, server restarts, segment loss, and process crashes without corrupting the integrity chain or losing events that were durably accepted.
- Cross-platform Go build (Linux/macOS/Windows). No CGo dependencies.
- Testable end-to-end with an in-tree `bufconn`-based test server that simulates drops, GOAWAYs, ack delays, and stale watermarks — no external Watchtower instance required to run the test suite.

## Non-Goals

- Server implementation (Watchtower).
- OCSF schema mapper (Phase 1) — assumed available via a `Mapper` interface that this client consumes.
- Composite-store refactor to advance a shared sequence/generation before fanout (Phase 0) — assumed; this client reads the contract via well-known `ev.Fields` keys.
- Live key rotation while connected (deferred Open Question).
- mTLS automation / SPIFFE / cert rotation hooks beyond reading static cert/key files (deferred).
- HTTP/2 fallback transport (deferred).
- Multi-tenant routing.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Scope** | Phase 2 only (client library) | Server is owned by another team; Phase 0 (composite refactor) and Phase 1 (OCSF mapper) are prerequisites. Client can be built and tested in isolation given a contract for both. |
| **Architecture** | Layered sub-packages under `internal/store/watchtower/` | Each layer has one responsibility (chain, compact, wal, transport) and can be unit-tested without the others. Wire types live in a separate `proto/canyonroad/wtp/v1/` tree to be regeneratable. |
| **WAL framing** | 4-byte length + 4-byte CRC32C-Castagnoli + protobuf record bytes; 16-byte segment header (WTP1 magic, version, flags, generation) | CRC32C catches segment corruption (truncated tail, bit-flips). Castagnoli has hardware acceleration on x86 and arm64. Length prefix allows streaming reads without protobuf parse. |
| **Concurrency model** | WAL is the queue; one transport goroutine drives a `select{}` state machine; small recv-goroutine reads ACKs from the gRPC stream | `AppendEvent` never blocks on network — it returns as soon as the WAL fsync completes (or fast path: page cache + background sync, matching `2026-04-13-deferred-sync`). The transport goroutine owns all session/connection state, eliminating lock contention. |
| **Backpressure** | WAL bounded by `max_total_bytes`; overflow → drop oldest unacked + emit `TransportLoss` marker | Matches spec §8.5. AppendEvent never fails due to a slow server. Loss is observable to the operator and to the server (gap in sequences). |
| **Testing** | In-tree `testserver` package using `bufconn`; scenario hooks for Drop/Goaway/AckDelay/stale watermark | Hermetic, fast, deterministic. Integration tests against real Watchtower instances are out of scope for this work. |
| **Open questions** | Defer all three (key rotation pause/resume, OCSF version negotiation, sub-second timestamp granularity) | Spec is explicit they are unresolved. Each gets a code comment marking the integration point so a follow-up PR can wire them in without restructuring. |

## Architecture

### Package layout

```
internal/store/watchtower/
  store.go                  // implements store.EventStore; orchestrates the others
  config.go                 // Config struct, applyDefaults, validate
  errors.go                 // typed errors (ErrShuttingDown, ErrWALOverflow, …)

  chain/
    chain.go                // SinkChain (advance hash given shared seq+gen)
    canonical.go            // IntegrityRecord canonical-JSON encoder (custom, not encoding/json)
    context.go              // ContextDigest computation per spec §6.4.6
    testdata/
      vectors.json          // golden vectors: input record → expected canonical bytes → expected hash

  compact/
    encoder.go              // events.EventType → wtpv1.EventClass + Activity + payload
    encoder_test.go         // golden vectors per event type
    payload/
      file.go process.go network.go …  // per-class field projection
      testdata/             // golden JSON projections per OCSF class

  wal/
    wal.go                  // WAL writer + reader; segment lifecycle
    segment.go              // header layout, INPROGRESS suffix, atomic seal
    meta.go                 // meta.json (atomic temp+rename + dir fsync)
    framing.go              // length+CRC32C+payload; readers verify CRC
    testdata/               // golden segment bytes for cross-version compat

  transport/
    transport.go            // Conn interface, gRPC implementation
    state.go                // state machine: connecting/replaying/live/shutdown
    batcher.go              // assembles EventBatch under invariants
    replayer.go             // post-reconnect replay from WAL up to ack watermark
    heartbeat.go            // periodic Heartbeat send + miss-detection
    metrics.go              // wtp_* counters/gauges/histograms (slog or expvar)

  testserver/
    server.go               // bufconn-based in-process WTP server stub
    scenarios.go            // hooks: Drop, Goaway, AckDelay, StaleWatermark
    dialer.go               // returns a transport.Dialer wired to bufconn
    matcher.go              // helpers: WaitForBatch(...), AssertSequenceRange(...)

proto/canyonroad/wtp/v1/
  wtp.proto                 // service + messages from spec §7
  wtp.pb.go wtp_grpc.pb.go  // generated
  testdata/
    *.bin                   // canonical wire-format goldens for parity with other implementations
```

### Layer responsibilities

| Package | Responsibility | Touches network? | Touches disk? |
|---|---|---|---|
| `watchtower` (root) | Implements `store.EventStore`, owns lifecycle (Start/Close), wires the others together. | No directly | No directly |
| `chain` | Pure: advance a sink-local entry hash from `(seq, gen, prev_hash, canonical_record)`. Computes context digest. | No | No |
| `compact` | Pure: project an `events.Event` into a `CompactEvent` (OCSF class + activity + payload). | No | No |
| `wal` | Append+fsync records, seal+roll segments, replay records on startup, GC after ack. | No | Yes |
| `transport` | One goroutine state machine: dial, SessionInit, send batches, replay on reconnect, heartbeat. | Yes | No |
| `testserver` | bufconn stub of the WTP server; scriptable scenarios. | In-process only | No |

The root `store.go` is small (~150 lines): it constructs a `Config`, builds the `chain`, opens the `wal`, starts the `transport`, and forwards `AppendEvent` calls. Everything else is delegated.

## Data Flow

### Steady state — `AppendEvent` (transactional pattern)

```
caller (composite store)
  │  composite has already allocated (seq, gen) and stamped ev.Chain
  │  via the typed pkg/types.Event.Chain *ChainState field (Phase 0).
  ▼
watchtower.Store.AppendEvent(ctx, ev)
  │
  │ 1. validate: ev.Chain != nil, else propagate compact.ErrMissingChain
  │      (wrapped as `watchtower: %w` from compact.Encode; loud failure
  │      because composite-store regressions must surface to the caller).
  │      Note: although the upstream Phase 0 contract documents the
  │      composite-store side as `audit.ErrMissingChainState`, the WTP
  │      sink boundary surfaces `compact.ErrMissingChain` because the
  │      check is performed inside `compact.Encode` against the typed
  │      `ev.Chain == nil` predicate (composite stamps `ev.Chain` rather
  │      than returning an error). `compact.Encode` performs `errors.Is`
  │      against `compact.ErrMissingChain` only — it does not consult
  │      `audit.ErrMissingChainState`. The two sentinels intentionally
  │      live in separate packages: audit owns the composite-store
  │      contract; compact owns the per-sink encode boundary.
  │
  │ 2. compact.Encode(ev) → wtpv1.CompactEvent
  │
  │ 3. canonicalize → bytes for hashing
  │
  │ 4. SinkChain.Compute(formatVersion, seq, gen, payload)
  │      → *ComputeResult (opaque, chain-bound; EntryHash() and
  │        PrevHash() accessors expose values for serialization;
  │        sequence, generation, chain pointer tracked internally for
  │        Commit-time validation)
  │        PURE, no chain mutation
  │
  │ 5. wal.Append(seq, gen, record_bytes)
  │      → (a) clean failure: return err, no Commit, chain unchanged
  │      → (b) ambiguous failure: SinkChain.Fatal(err); return ErrFatalIntegrity
  │      → (c) success: continue
  │
  │ 6. SinkChain.Commit(result) — chain advances; non-nil error means the
  │      chain just latched fatal (backwards generation, stale token, or
  │      rollover-with-nonempty-prev) and must be surfaced
  │
  │ 7. transport.Notify() → wake transport goroutine (non-blocking)
  │
  └─ return nil
```

The WTP `AppendEvent` follows the transactional Compute → durable-write → Commit pattern from §"Sink integration" of the Phase 0 contract. Failure modes:

| WAL failure | Action | Chain state | Caller-visible error |
|---|---|---|---|
| Clean (e.g., overflow detected before any I/O, validation error) | No Commit. Caller may retry. | Unchanged. | The clean error. |
| Ambiguous (write returned, fsync returned, partial write possible) | `SinkChain.Fatal(err)`. Subsequent appends return `ErrFatalIntegrity`. | Latched fatal. | The ambiguous error wrapped in `FatalIntegrityError`. |
| Success | `Commit`. | `prev_hash := entry_hash`, `generation := ev.Chain.Generation`. | nil. |

The `wal.Append` function is the only place that classifies WAL failures into clean vs ambiguous. The classification is documented in §4 below.

### Transport loop (single goroutine)

```
                ┌─────────────────────────────┐
                │  state = stateConnecting    │
                └──────────────┬──────────────┘
                               │ Dial + SessionInit (wal_high_watermark_seq +
                               │   generation seeded from `wal.Meta`
                               │   AckHighWatermarkSeq + AckHighWatermarkGen,
                               │   carrying AckRecorded → Present so the
                               │   first-apply branch of the clamp doesn't
                               │   trip on a legitimate zero seed)
                               │ server returns ack_high_watermark_seq
                               ▼
                ┌─────────────────────────────┐
   ┌───────────►│  state = stateReplaying     │
   │            └──────────────┬──────────────┘
   │                           │ replayer reads wal records (ack_hw, wal_hw], sends them
   │                           │ in batches; each batch obeys all invariants
   │                           ▼
   │            ┌─────────────────────────────┐
   │   notify   │  state = stateLive          │
   │   (append) │  - select { wakeup, hb,     │
   │            │    recv ack, recv goaway,   │
   │            │    flush timer, ctx done }  │
   │            └──────┬──────────┬──────┬────┘
   │      goaway/loss  │          │      │ shutdown
   │      /timeout     │          │      │ (Close)
   └───────────────────┘          │      ▼
                                  │   stateShutdown: drain in-flight, close stream
                                  │   gracefully, close wal, close conn
                                  ▼
                         (back to connecting)
```

### Generation roll (WAL-driven, not transport-driven)

Generation boundaries are detected and enforced inside `wal.Append`, *before* the record is written. This is the only place that can guarantee "single generation per segment" because the WAL writes records to the segment file before the transport ever sees them.

```
wal.Append(seq, gen, payload):
  if gen != currentSegment.generation:
    seal currentSegment (rename .INPROGRESS → .seg, fsync parent)
    open new segment with header.generation = gen
    fsync new segment header
    enqueue an internal "GENERATION_ROLL" notification record so the
      transport knows to flush the current batch and emit SessionUpdate
      before sending the first record of the new generation.
  write framed record into currentSegment
  fsync per policy
```

The transport, on observing the GENERATION_ROLL notification in the WAL stream, performs the protocol-level work (flush current batch, send `SessionUpdate` with new context digest, then begin batching new-generation records). The chain itself resets per-sink: `SinkChain.Compute` automatically uses `prev_hash = ""` when it sees a new generation, and `Commit` records the new generation.

### WAL overflow → TransportLoss

When `wal.Append` would push total disk usage past `max_total_bytes`:
1. Drop the oldest *unacked* segment(s) until under budget.
2. Emit a synthetic `TransportLoss{from_seq, to_seq, dropped_count, generation}` record into the WAL.
3. Increment `wtp_transport_loss_total`.
4. The marker is sent like any other batch when the transport reaches it; the server learns about the gap via the marker, not via a missing sequence number alone.

CRC-corruption recovery emits `TransportLoss` with a *coarse* range: when a record fails CRC verification on read, we report `TransportLoss{from_seq: last_good_seq + 1, to_seq: segment_max_seq_estimate, generation: segment.generation}`. The estimate is computed as `last_good_seq + (segment_remaining_bytes / typical_record_size)`. This is best-effort but bounded: corruption in practice almost always means a truncated tail, where the gap extends to the segment end. A v2 enhancement (per-record sequence in the frame header, +8 bytes/record) would enable exact gap reporting; deferred until operators report imprecise ranges in practice.

## Phase 0 Contract (consumed, not implemented)

The composite store allocates a shared `(sequence, generation)` *once* via a `audit.SequenceAllocator` and stamps it onto the typed `ev.Chain *types.ChainState` field *before* fanning the event out to sinks. The WTP client reads it via:

```go
if ev.Chain == nil {
    return audit.ErrMissingChainState  // composite did not stamp
}
seq := ev.Chain.Sequence    // uint64
gen := ev.Chain.Generation  // uint32
```

The field is `json:"-"` on `pkg/types.Event` — it cannot leak into JSONL, OTEL, or any other JSON-based serializer. Per-sink hashing is the responsibility of each sink's own `audit.SinkChain` instance, using the shared `(seq, gen)` from `ev.Chain`.

The full contract — `SequenceAllocator` + `SinkChain` types, the transactional Compute/Commit protocol, generation semantics, `TransportLoss` semantics on the shared sequence, and the `types.Event.Chain` field — is documented in `docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md`. That doc is the source of truth; this design depends on it but does not change it.

## Chain Package (`internal/store/watchtower/chain`)

The WTP sink uses `audit.SinkChain` from the Phase 0 contract directly — there is no WTP-specific chain wrapper. This package contains only the helpers `audit.SinkChain` does not provide: canonical-record encoding (the byte-exact format that gets hashed) and the WTP-specific context digest.

### Helpers (not a new chain type)

```go
package chain

// IntegrityRecord is the WTP-specific structure that gets canonical-encoded
// and passed as the payload to audit.SinkChain.Compute. The on-the-wire
// integrity_record JSON object in WTP CompactEvent has these fields.
type IntegrityRecord struct {
    FormatVersion  uint32   // = 2 (spec §6.4); bump on any canonical-encoding or field-set change
    Sequence       uint64   // shared, from ev.Chain.Sequence; layered contract — see note below
    Generation     uint32   // shared, from ev.Chain.Generation
    PrevHash       string   // sink-local; provided by audit.SinkChain
    EventHash      string   // sha256(canonical_compact_event_bytes)
    ContextDigest  string   // bound at SessionInit/Update/rotation
    KeyFingerprint string
}

// EncodeCanonical produces the byte-exact JSON encoding mandated by spec §6.4
// (sorted keys, no insignificant whitespace, ASCII-escaped non-ASCII, decimal
// numbers). This output is the payload passed to audit.SinkChain.Compute and
// is the contract surface for cross-implementation parity.
func EncodeCanonical(rec IntegrityRecord) ([]byte, error)

// ComputeContextDigest returns the SHA-256 of the canonical encoding of the
// SessionContext fields the spec lists. Bound into every event hash in the
// session/segment. Returns ErrInvalidUTF8 if any string field contains
// invalid UTF-8 (see "Canonical encoding" subsection for rationale).
func ComputeContextDigest(ctx SessionContext) (string, error)

// ComputeEventHash returns sha256(canonical_compact_event_bytes). Used to
// populate IntegrityRecord.EventHash before passing the canonical-encoded
// IntegrityRecord to audit.SinkChain.Compute.
func ComputeEventHash(canonicalEvent []byte) string
```

The actual chain mutations (Compute/Commit/Fatal/State/Restore) all live on `audit.SinkChain`; we do not re-implement them. The transactional pattern from §"Steady state" calls into `audit.SinkChain` directly.

#### Sequence-width layered contract

The sequence value participates in three different width contracts as it flows through the system, and each layer has a different range:

| Layer | Type | Range |
|---|---|---|
| WTP wire format (`CompactEvent.sequence`, `IntegrityRecord.sequence`, this struct) | `uint64` | full uint64 |
| Phase 0 audit chain (`audit.SinkChain.Compute(formatVersion int, sequence int64, ...)`) | `int64` | 0..math.MaxInt64 |
| Composite-store source (`ev.Chain.Sequence`, `pkg/types.ChainState`) | `uint64` | 0..math.MaxInt64 (constrained by Phase 0 spec) |

The constraint surfaces at one place: `watchtower.Store.AppendEvent` (Task 23, Phase 10) bounds-checks `ev.Chain.Sequence <= math.MaxInt64` before converting to int64 and calling into the chain. Sequences exceeding the cap are dropped (counter `wtp_dropped_sequence_overflow_total`, structured log) **before WAL admission** — no segment write, no WAL accounting impact, no replay considerations. Drops do NOT crash or panic. The encoder in `chain/canonical.go` accepts the full uint64 range so wire-format conformance vectors can exercise it; constraint enforcement is the boundary's job.

The same boundary handles `chain.ErrInvalidUTF8` for **per-record encodes only** — i.e., the SinkChain.Compute call inside AppendEvent that wraps EncodeCanonical for the current event's IntegrityRecord. Drop semantics: counter `wtp_dropped_invalid_utf8_total`, structured log, no WAL admission, no chain advance (the SinkChain Compute call returns the error before mutating prev_hash). The drop leaves a sequence gap visible to the server, since other sinks (JSONL, OTEL) have already committed the allocated sequence — whether to surface that gap as a `TransportLoss` marker (and with what reason code) is deferred to Phase 8 when the per-sink batching layer lands.

Session-lifecycle ErrInvalidUTF8 (`ComputeContextDigest` failing at SessionInit, SessionUpdate, or chain rotation) follows a different contract — see "Context digest" below — because no shared sequence has been allocated yet, so there is no gap to manage.

### Canonical encoding — non-negotiable byte parity

Spec §6.4 mandates a canonical JSON encoding with sorted keys, no insignificant whitespace, ASCII-escaped non-ASCII, and decimal numbers (no scientific notation). `encoding/json` does *not* guarantee any of these invariants across versions, and a single byte difference breaks every other implementation's verification.

Invalid UTF-8 in any string field is **rejected** with `ErrInvalidUTF8`, not silently replaced with U+FFFD. Substitution would produce different canonical bytes (and therefore different SHA-256 hashes) for the same input depending on which language's encoder ran — the worst kind of cross-implementation drift, since both sides would be "valid". Callers MUST handle `ErrInvalidUTF8` as a record-level drop with a counter increment, not a session-level abort.

We hand-roll the encoder in `chain/canonical.go`:

```go
func EncodeCanonical(rec IntegrityRecord) ([]byte, error)
```

The encoder is exhaustively tested against `chain/testdata/vectors.json`, which is also published as the cross-implementation conformance suite for the spec. Vectors include UTF-8 edge cases (escaped non-ASCII, surrogate pairs), large numbers near uint64 max, and empty strings.

**Negative vectors.** Invalid UTF-8 cannot be expressed as a JSON string, so negative cases use a different schema: `{"name", "kind", "input": {<other fields>}, "input_b64": "<base64-encoded raw bytes>", "input_field": "<canonical wire field name>", "expected_error": "ErrInvalidUTF8"}`.

The `input_field` value is the **canonical wire/JSON field name** (snake_case), NOT the language-specific struct field name. Valid values for `kind: "integrity_record"` are `prev_hash`, `event_hash`, `context_digest`, `key_fingerprint`. Valid values for `kind: "context_digest"` are `session_id`, `agent_id`, `agent_version`, `ocsf_version`, `algorithm`, `key_fingerprint`. Each implementation maps these to its local struct field names inside its test harness; the published vectors stay language-neutral.

The test harness applies the decoded bytes to the named field after parsing the rest of `input` normally. Cross-language implementations MUST implement the `input_b64` schema to claim WTP-spec-conformance — the negative cases are part of the contract surface, not optional. As a temporary fallback during initial bring-up, an implementation MAY skip negative entries and substitute per-language unit tests; once the implementation reaches "WTP-conformant" status, the negative vectors must be honored end-to-end.

**Raw-byte injection is mandatory harness behavior.** Negative vectors carry intentionally-invalid byte sequences via the `input_b64` + `input_field` channel rather than embedding raw bytes in the JSON `input` object, because most JSON parsers either reject or silently transcode non-UTF-8 strings. Every conforming harness MUST implement this side-channel injection: decode `input_b64` as base64, then write the resulting bytes (without any UTF-8 validation or transcoding) into the local struct field named by `input_field`. Skipping or "sanitizing" this step would mask exactly the failure mode these vectors test.

Positive-vector `input` objects also use the canonical snake_case wire keys (e.g., `format_version`, `sequence`, `session_id`); each implementation maps these to its local struct fields inside its test harness. The vectors are language-neutral — they reference the wire format, never any implementation's internal naming.

**Lossless integer parsing.** Conformance harnesses MUST parse `sequence`, `format_version`, and `generation` JSON numbers losslessly. Implementations whose default JSON parser does not preserve full uint64 precision (notably JavaScript / TypeScript using `JSON.parse`, which materializes numeric tokens as IEEE-754 `Number` before any reviver runs and so cannot recover precision after the fact) MUST use a BigInt-aware parser library (e.g., `json-bigint`, `lossless-json`) or a streaming/tokenizing parser that exposes raw numeric lexemes before numeric coercion. Validating against the `uint64_max_sequence` vector is the canonical gate for this requirement.

**Duplicate-key policy.** Conformance vector files MUST NOT contain duplicate JSON keys at any nesting level. This is a **review-time discipline** for the published file — the Go reference harness uses `encoding/json` with `DisallowUnknownFields`, which rejects unknown keys but accepts duplicate keys with last-value-wins semantics. Cross-language harnesses SHOULD use a strict parser that rejects duplicates where the standard library exposes one (e.g., Python `json.loads(..., object_pairs_hook=...)`). A future revision of this spec may introduce a CI-level vectors lint that rejects duplicate keys at publication time; until then, treat the policy as a normative requirement on the file, not as something the reference harness mechanically enforces at load time.

**Vector schema versioning.** The `input_field` + `input_b64` schema and the snake_case `input` keys are the **v1** published conformance vector format. Pre-v1 (Go-shaped) vectors were never published to external consumers; this is a pre-release tightening, not a migration. The v1 schema is the contract from this point forward.

**v1 (current) file shape:** the file is a bare JSON array of vector objects.

**v2+ (future) file shape:** the file is an object: `{"schema_version": 2, "vectors": [ ... ]}`. Future versions follow the same envelope; only `schema_version` changes.

**Detection rule:** if the top-level JSON value is an array, the harness MUST treat it as v1 (no `schema_version` field is present or expected). If the top-level value is an object, the harness MUST read `schema_version`. Any value the harness does not recognize MUST be rejected — the harness MUST refuse to load the file with a clear error (fail-closed). This prevents a future incompatible vector set from being silently treated as conformant.

**Compatibility:** when v2 ships, v1 must keep working alongside it for at least one minor release. New harness implementations supporting only v2 are not WTP-conformant until they also accept v1.

**Unknown-field policy.** Both the v1 (bare-array) and v2+ (envelope) loader paths reject unknown fields — at the envelope level (`schema_version`, `vectors` are the only accepted keys) and at the per-entry level (every key on a `vectorEntry` must be one the harness recognizes). Implementations MUST configure their JSON decoder to fail on unknown fields (e.g., `dec.DisallowUnknownFields()` in Go) on every decode in the loader so that typos and forward-incompatible vectors fail loudly rather than being silently dropped. This complements the strict envelope `schema_version` check above with the same fail-closed posture at the entry level.

**Trailing content.** The loader MUST treat any non-whitespace content after the top-level JSON value (array or envelope) as a parse error. Both paths enforce this — `json.Unmarshal` natively rejects trailing data, and the envelope path additionally checks `dec.Decode(&struct{}{})` returns `io.EOF` after the envelope. This catches accidental concatenation and forward-incompatible streaming formats.

#### Canonical-format versioning

`IntegrityRecord.FormatVersion` is the canonical-encoding version. Any of the following changes MUST bump it in the same commit:

- Adding, removing, or renaming a field in `IntegrityRecord` or `SessionContext`.
- Changing the canonical key order (currently lexicographic), the whitespace policy (currently none), the number format (currently decimal-only), or the string-escape policy (currently lowercase \uXXXX with surrogate pairs for non-BMP, invalid UTF-8 rejected).
- Changing `ComputeContextDigest`'s field set or encoding rules.

The version is consumed by verifiers to pick the right canonical-encoder and reject older/newer records they do not understand. Version-mixed chains are not supported.

### Context digest (§6.4.6)

```go
func ComputeContextDigest(ctx SessionContext) (string, error)
```

Computed once on `SessionInit`, again on `SessionUpdate`, and again on chain rotation. Bound into every event hash in that segment. Implemented as SHA-256 of the canonical encoding of the SessionContext fields the spec lists.

Callers MUST handle the error path. Unlike per-record `EncodeCanonical` failures (which drop one event and continue — see "Sequence-width layered contract" above), `ComputeContextDigest` failures abort the lifecycle operation that triggered them:

- **SessionInit**: connect attempt fails fast, no session is established, the agent surfaces a fatal config error (counter `wtp_session_init_failures_total{reason="invalid_utf8"}`, structured log with the offending field name from the wrapped error). The transport does NOT auto-retry — invalid identifiers come from agent config and won't fix themselves.
- **SessionUpdate / chain rotation**: rotation aborts, the existing chain stays bound to the prior context, and the operator gets a structured warn log (counter `wtp_session_rotation_failures_total{reason="invalid_utf8"}`). The session continues with the old context until the operator either fixes the identifier or restarts the agent.

Both cases use the wrapped error text from `ErrInvalidUTF8` (which contains the offending field name in its message) for diagnostics — see Metrics section for the exact log shape.

### What this package does NOT do

- Advance the shared sequence (composite owns the `audit.SequenceAllocator`).
- Mutate `prev_hash` (lives on `audit.SinkChain`).
- Persist any state (root `store.go` reconstructs `audit.SinkChain` from WAL on startup via `Restore`).
- Talk to the network or to a KMS (the key is passed in already-resolved at construction).

## WAL Package (`internal/store/watchtower/wal`)

### Directory layout

```
$state_dir/wtp/
  meta.json                      // atomic temp+rename, fsync(parent)
  segments/
    0000000000.seg.INPROGRESS    // currently being written
    0000000001.seg                // sealed
    0000000002.seg                // sealed
    …
```

### Segment header (16 bytes)

```
offset  size  field
0       4     magic     = "WTP1"
4       2     version   = 1
6       2     flags     (bit 0: gen_init, others reserved 0)
8       4     generation
12      4     reserved
```

Header is fsync'd at segment creation. A reader rejects segments with unknown magic, unknown version, or non-zero reserved bits.

### Record framing (per record)

```
offset  size      field
0       4         length     (uint32 BE; bytes after this field, excluding the CRC and including payload)
4       4         crc32c     (Castagnoli, computed over payload)
8       length-4  payload    (protobuf-encoded WAL record; carries seq + gen)
```

Sequence and generation are encoded inside the protobuf payload (not in the frame header), so a per-record scan after CRC failure can recover them when the record itself parses cleanly. When CRC fails, the record bytes are unsafe to parse — the recovery path below uses the segment header's generation and the last-good record's sequence to bound the lost range.

The CRC is the last line of defense against truncated tails (crash mid-fsync). Reader behaviour on bad CRC: log + emit `TransportLoss` marker with a coarse range (see "CRC corruption recovery" below) + skip to next valid record.

### `Append` — clean vs ambiguous failure classification

`wal.Append` is the only place that decides whether a write failure is recoverable. The classification feeds directly into the WTP `AppendEvent` transactional pattern (clean → no Commit, ambiguous → Fatal).

```go
func (w *WAL) Append(seq int64, gen uint32, payload []byte) (AppendResult, error)

type AppendResult struct {
    GenerationRolled bool   // true iff this Append rolled the segment for a new generation
}
```

Failure classification:

| Failure source | Classification | Why |
|---|---|---|
| `payload` exceeds segment-size budget | Clean | Validated before any I/O. |
| WAL is in `closed` state | Clean | Validated before any I/O. |
| `MaxTotalBytes` exceeded after attempting overflow GC | Clean (loss marker emitted instead of returning error) | We drop oldest segments and emit `TransportLoss`. The Append itself succeeds. |
| `os.Write` returns short write or io error | Ambiguous | Bytes may have hit the filesystem buffer or the platter. |
| `f.Sync()` returns error | Ambiguous | Sync may have partially flushed. |
| Segment-roll rename fails after seal | Ambiguous | Old segment may or may not have been removed; new segment may or may not exist. |
| `meta.json` atomic-rename fails on watermark update (on Ack path, not Append) | Ambiguous | meta.json may be in either old or new state. |

A clean failure leaves the WAL in a consistent state: the partial frame (if any) is truncated back to the last good byte, the segment file's logical size is restored, and `Append` returns the error. The caller (WTP `AppendEvent`) does NOT call `SinkChain.Commit`, so the chain stays at the previous `prev_hash` and the next event hashes against the same prev_hash. If the caller retries with a new event allocation, the `(seq, gen)` differs but `prev_hash` is unchanged — which is correct, because the failed event was never durably persisted.

An ambiguous failure latches the WAL in `degraded` state. Any subsequent `Append` returns `ErrFatalIntegrity` immediately. The WTP `AppendEvent` calls `SinkChain.Fatal(err)` and returns. The composite store's `onAppendError` hook is invoked and the daemon decides whether to halt the agent (default) or continue with the WTP sink disabled (operator opt-in).

### Generation roll happens INSIDE Append

`Append` detects generation transitions and seals/rolls segments before writing the new record. This is the only place that can guarantee "single generation per segment" because the WAL writes records before the transport ever sees them.

```
Append(seq, gen, payload):
  if gen != currentSegment.generation:
    seal currentSegment:
      truncate to actual length
      fsync segment file
      rename .INPROGRESS → .seg
      fsync(segments/)
    open new segment with header.generation = gen
    fsync new segment header
    fsync(segments/)
    set AppendResult.GenerationRolled = true
  write framed record into currentSegment
  fsync per policy
  return AppendResult, nil
```

When `AppendResult.GenerationRolled == true`, the WTP `AppendEvent` notifies the transport to flush its current batch and emit a `SessionUpdate` with the new context digest before the new-generation batch begins. The chain itself rolls inside `audit.SinkChain.Compute` (it sees the new generation and uses `prev_hash = ""`).

### Lifecycle

| Event | Action |
|---|---|
| Open | Scan `segments/`. Last `*.INPROGRESS` is the live segment; reopen for append. Replay all records, verifying CRCs and rebuilding `audit.SinkChain.prev_hash`. |
| Append | Detect generation change → seal/roll if needed. Write framed record. Fsync per policy (immediate, or deferred per `2026-04-13-deferred-sync`). |
| Segment full | Truncate to actual length, fsync, rename `.INPROGRESS` → `.seg`, open new `.INPROGRESS`. |
| Generation change | Detected inside Append (see above). |
| `SessionUpdate` write | Force fsync of live segment + meta.json. |
| `TransportLoss` write | Force fsync (operator visibility into loss must be durable). |
| Ack received | Update `meta.json` with new `ack_high_watermark`. GC fully-acked segments via `os.Remove` after fsync(parent). |
| Close | Fsync live segment, leave `.INPROGRESS` suffix in place (will be reopened on restart). |

### CRC corruption recovery

When a record fails CRC verification on read:

1. Log the corruption with segment file, offset, expected/actual CRC.
2. Compute coarse range: `from_seq = last_good_seq + 1`, `to_seq = last_good_seq + max(1, segment_remaining_bytes / typical_record_size)`. The estimate uses the segment's average record size from records read so far.
3. Emit `TransportLoss{from_seq, to_seq, generation: segment.generation, reason: "crc_corruption"}` into the WAL stream.
4. Increment `wtp_wal_corruption_total`.
5. Skip to the next segment (we do not attempt to scan-and-resync within a corrupted segment; the most common cause is a truncated tail, which extends to the segment end by definition).

This is best-effort. A v2 enhancement (per-record sequence in the frame header, +8 bytes/record overhead) would enable exact gap reporting and is deferred until operators report imprecise ranges in practice. Documented in §8.

### meta.json schema

```json
{
  "format_version": 2,
  "ack_high_watermark_seq": 12345,
  "ack_high_watermark_gen": 7,
  "ack_recorded": true,
  "session_id": "01J...ulid",
  "key_fingerprint": "sha256:abcd…"
}
```

Fields:

- `format_version` — schema version. Current writers MUST emit `2`. v1 readers (which only ever stored `(seq, gen)` because pre-v2 only `MarkAcked` wrote meta.json) are accepted on read; see "Migration / backcompat" below.
- `ack_high_watermark_seq` / `ack_high_watermark_gen` — the last `(generation, sequence)` tuple persisted via `MarkAcked`. Meaningless in isolation: the `ack_recorded` flag below is what makes this tuple "Present" for the §Effective-ack tuple and clamp's first-apply branch.
- `ack_recorded` — boolean mirror of `wal.Meta.AckRecorded`. **Required in v2.** False means "no ack has ever been recorded for this WAL directory; the ack-tuple fields above are zero-valued and meaningless." Maps directly to the AckTuple `Present` flag the cold-start seed passes into the transport (see §Effective-ack tuple and clamp): `Present == ack_recorded`. The first-apply branch of `applyServerAckTuple` is taken iff `ack_recorded == false` so the clamp does not trip on a legitimate zero seed.
- `session_id` / `key_fingerprint` — identity fields used by the cold-start seed safety check below. A stale meta.json from a previous installation cannot be silently consumed.

Atomically written via `os.WriteFile` on a temp + `os.Rename` + `fsync(parent)` using the existing `internal/audit/fsync_dir_unix.go` and `fsync_dir_windows.go` helpers.

**Migration / backcompat.** A v1 meta.json (no `ack_recorded` field) MUST be treated as `ack_recorded: true` on read regardless of the persisted ack-tuple values, because in pre-v2 only `MarkAcked` wrote meta.json — the file's existence implied an ack was persisted. (The implementation lives in `wal.ReadMeta`: see `internal/store/watchtower/wal/meta.go`.) After the next successful WAL flush, the meta.json is rewritten as v2 with the correct `ack_recorded` value (always true on the rewrite path because the rewrite happens through `MarkAcked`). v0 (no meta.json on disk) is the cold-cold-start case: callers receive `os.ErrNotExist` from `ReadMeta` and pass `Options.InitialAckTuple = nil`, which the §Effective-ack tuple and clamp's first-apply branch handles wholesale.

#### Cold-start seed safety / stale meta detection

Before constructing `Options.InitialAckTuple`, the caller (Store-wiring layer) MUST compare `wal.Meta.SessionID` and `wal.Meta.KeyFingerprint` against the values configured for the current process. The fields exist explicitly to defend against silently consuming meta from a different installation or a rotated key — the persisted state could otherwise be cryptographically un-attributable to the current key, or could carry an ack history that belongs to a different session entirely.

Identity is ESTABLISHED on first writer (first-writer-wins immutability): a fresh WAL directory adopts whatever `(SessionID, KeyFingerprint)` the first writer presents and persists it via the next meta.json rewrite. Once persisted, identity is **immutable** for the lifetime of the WAL directory; later writers presenting different values are rejected via the **quarantine policy** below. `wal.OpenWAL` is responsible for the comparison; its caller passes the configured identity through `Options.SessionID` and `Options.KeyFingerprint`, and `OpenWAL` returns a typed `wal.ErrIdentityMismatch{Field, Persisted, Expected}` error on mismatch (so the wiring layer can branch on the typed error rather than string-match).

**Quarantine policy (mismatch handling).** When `OpenWAL` returns `ErrIdentityMismatch` (either `session_id` or `key_fingerprint` differs from the persisted meta.json values), the wiring layer's recovery action is to **rename the entire WAL directory** to `<dir>.quarantine.<unix-ts>` (where `<unix-ts>` is the seconds-since-epoch at the moment of the rename) and **open a fresh WAL** at the original path. The fresh WAL has no persisted meta.json, so the cold-start path passes `Options.InitialAckTuple = nil` and the transport adopts the server's tuple wholesale on the first SessionAck (the first-apply branch in §Effective-ack tuple and clamp). Increment `wtp_wal_quarantine_total{reason="session_id_mismatch"|"key_fingerprint_mismatch"}` (a counter — see Task 22b). Log a one-time WARN naming the field that mismatched, the persisted vs. expected values, the path the directory was renamed to, and the action taken ("quarantined; opened fresh WAL").

**Fate of buffered-but-unsent data in the quarantined WAL.** Records that were buffered in the old WAL but had not yet been acknowledged are **NOT recovered** — the quarantine path does not attempt to drain or replay them through the fresh WAL. The quarantined directory is preserved on disk for **operator inspection only** (it can be opened manually with the `wal` package's read-only Reader API or examined with the existing audit tooling); there is no automatic replay path back into the live stream. The data is not deleted on its own — operators decide when to remove the quarantine directory after extracting whatever forensics they need.

**Operator story.** The quarantine policy is deliberately conservative: it preserves all on-disk state for forensics, never silently consumes a meta from a foreign installation, and never auto-merges. There is **no automatic cleanup** of `<dir>.quarantine.*` directories — operators must clear them manually (or via an out-of-band cron) once the contents have been inspected. There is **no built-in recovery** of buffered-but-unsent records from a quarantined WAL into the live stream — if those records matter, operators extract them via the audit tooling and re-inject them through the appropriate replay path (which is out of scope for the WTP client phase). The `wtp_wal_quarantine_total` counter is the operator-visible signal that a quarantine has happened and the WAL has been re-cold-started; any non-zero rate warrants investigation of the source of the identity drift (key rotation procedure, session-rotation handoff, accidental WAL directory reuse across deployments).

A `wal.Meta` v1 file (no identity fields) is treated by `OpenWAL` as a successful identity match — the v1-to-v2 migration is the only path that adopts the configured identity into the persisted meta on its first rewrite. After the next ack-driven `MarkAcked` rewrites meta.json as v2, the configured identity becomes the immutable persisted identity from that point on.

### Reader API

```go
type Reader struct { /* private */ }

func (w *WAL) NewReader(start uint64) (*Reader, error)
func (r *Reader) Notify() <-chan struct{}    // signaled when new records appended
func (r *Reader) Next() (Record, error)      // io.EOF when caught up
func (r *Reader) Close() error

func (w *WAL) MarkAcked(seq uint64) error    // GC fully-acked segments
```

The transport goroutine consumes via the reader; it does not poll. Notifications coalesce naturally — one wakeup may correspond to many appended records. The reader surfaces `TransportLoss` and generation-roll markers as ordinary records (with a typed kind field) so the transport state machine handles them in the same select branch as data records.

## Transport Package (`internal/store/watchtower/transport`)

### Conn interface and Dialer pattern

```go
type Conn interface {
    Send(ctx context.Context, msg *wtpv1.ClientMessage) error
    Recv(ctx context.Context) (*wtpv1.ServerMessage, error)
    CloseSend() error
    Close() error
}

type Dialer interface {
    Dial(ctx context.Context) (Conn, error)
}
```

Production: `GRPCDialer` wraps `grpc.NewClient` with TLS 1.3 credentials, ALPN `wtp/1`, configured timeouts, and the bidi stream `Watchtower/Stream`. Tests: `testserver.NewDialer()` returns a `Dialer` backed by `bufconn` and a scenario script.

The transport package never references `grpc-go` types in its own API surface, so tests don't need a real network listener.

### State machine (single goroutine)

```go
type state int

const (
    stateConnecting state = iota
    stateReplaying
    stateLive
    stateShutdown
)
```

The goroutine runs `for { select { … } }`. The set of events depends on state:

| State | select branches |
|---|---|
| `stateConnecting` | `dialResult`, `ctx.Done()` |
| `stateReplaying`  | `replayDone`, `replayBatchSent`, `recv`, `ctx.Done()` |
| `stateLive`       | `walReader.Notify()`, `flushTimer.C`, `heartbeatTimer.C`, `recv`, `ctx.Done()` |
| `stateShutdown`   | `drainDone`, `gracefulCloseTimeout`, `ctx.Done()` |

`recv` is fed by a small companion goroutine that calls `Conn.Recv` in a loop; this is the only other goroutine in the package. It exits when the stream closes.

### Batcher invariants (per spec §7)

A `Batcher` accumulates `CompactEvent`s and flushes when **any** of the following triggers:

- Generation change: next event's generation differs from current batch.
- Time span: oldest event in batch is older than `max_event_timespan` (default 5s).
- Event count: `>= max_events_per_batch` (default 256).
- Byte budget (post-compression): estimated `>= max_batch_bytes` (default 256 KiB).
- Flush timer: `flush_interval` elapsed (default 1s; 200ms in ephemeral mode).
- Generation rollover (sequence wrap): forces a fresh batch.

Each invariant is enforced by a single function (`Batcher.Add` returns `(addedToBatch, shouldFlush)`); making the Batcher entirely table-test-driven.

### Replayer

On `stateReplaying`:

```go
for seq := ackHighWatermark + 1; seq <= walHighWatermark; seq++ {
    rec := walReader.Next()
    batcher.Add(rec)
    if batcher.ShouldFlush() {
        send(batcher.Drain())
        if err { goto reconnect }
    }
}
sendFinalBatchIfAny()
state = stateLive
```

Replay batches obey the same invariants as live batches; the only difference is the source of records. The server may legitimately return a stale (lower) ack watermark during gradual rollout or partition recovery; the replayer treats the ack watermark as a `(generation, sequence)` TUPLE and applies the lex-`(gen, seq)` clamp described under §"Acknowledgement model" below. The clamp is type-enforced — the two fields move together or neither does — because the WAL's segment GC sorts by lex `(gen, seq)` and mixing local-seq with server-gen would create an impossible state.

### Heartbeat

A `heartbeatTimer` ticks at `heartbeat_interval` (default 30s; 10s in ephemeral mode). On tick: send `Heartbeat`. If two consecutive heartbeats elapse with no inbound message (ack or ServerHeartbeat), set `state = stateConnecting` (reconnect with backoff).

### Acknowledgement model

WTP uses three distinct server→client acknowledgement messages with disjoint semantics. Conflating them is a common source of bugs in early implementations.

| Message | When sent | What it advances |
|---|---|---|
| `SessionAck` | Once, immediately after the server validates `SessionInit`. | Both the session lifecycle (the client moves out of Connecting) AND both ack cursors. `accepted=false` terminates the session — the client MUST disconnect and surface `reject_reason`. On `accepted=true`, the carried `(generation, ack_high_watermark_seq)` is fed through the SAME clamp as `BatchAck` and `ServerHeartbeat` (see §"Effective-ack tuple and clamp" below). Session lifecycle and cursor advancement happen in the same handler. |
| `BatchAck` | Per batch the server has durably accepted (or batched into a single ack covering several client batches). Carries `ack_high_watermark_seq` and `generation`. | Both ack cursors per the §"Effective-ack tuple and clamp" rules: server-higher advances `persistedAck` (driving WAL segment GC and `wtp_ack_high_watermark`) AND `remoteReplayCursor`; server-lower advances ONLY `remoteReplayCursor` (no `wal.MarkAcked` call), so the next replay window re-sends the gap. |
| `ServerHeartbeat` | Periodic, even when the client is idle. Carries the server's current `ack_high_watermark_seq`. | Same clamp as `BatchAck`. Used to confirm liveness AND catch up the client after long idle periods (the heartbeat may carry an ack-watermark advance the client has not seen via BatchAck — e.g. when a previous BatchAck was lost on a stream reset). |

`SessionUpdate` is NOT an acknowledgement — it is a control frame for key or generation rotation, sent by either side. The `ack_timeout` reconnect reason fires when no `BatchAck` (NOT `SessionUpdate`, NOT `ServerHeartbeat`) arrives within the configured window for in-flight batches.

#### Effective-ack tuple and clamp

The effective ack watermark is split into TWO distinct cursors held on the client. They diverge ONLY during stale-server recovery; the rest of the time they hold the same tuple value.

1. **`persistedAck` (gen, seq)** — the *durable* ack watermark. Mirror of the WAL's `meta.json` `(AckHighWatermarkGen, AckHighWatermarkSeq, AckRecorded)` triple, advanced via `wal.MarkAcked`. **Monotonic only**: under lex `(gen, seq)` it never moves backward, because (a) the WAL implementation enforces this directly in `wal.MarkAcked` (`internal/store/watchtower/wal/wal.go` — the `advance` predicate is one-way) and (b) WAL segment GC keys off this tuple — once a segment is GC'd at watermark `W`, the records it held cannot be re-materialised, so any "rolled-back" persistedAck would be a lie. Seeded on cold start from `wal.ReadMeta` (gated by the §"Cold-start seed safety / stale meta detection" identity checks). The Transport mirror lives in `t.persistedAck (gen, seq)` plus a `t.persistedAckPresent` flag (mirrors `wal.Meta.AckRecorded`).

2. **`remoteReplayCursor` (gen, seq)** — the *server-belief* cursor. Where the server thinks its ack watermark sits. May be lex-LOWER than `persistedAck` if the server (gradual rollout or partition recovery) presents a stale tuple **with the same generation as `persistedAck`**. Drives the **Replaying state's reader-start calculation**: the replay reader opens at `remoteReplayCursor + 1` (NOT `persistedAck + 1`) so the gap between the cursors is re-sent. Lives in `t.remoteReplayCursor (gen, seq)` on Transport. The `gen` field is retained for logging/metrics symmetry; the WAL Reader API today is sequence-keyed (`(*WAL).NewReader(start uint64)` in `internal/store/watchtower/wal/reader.go:116`) and operates within whatever generation the segments on disk encode, so the cursor's `gen` is informational on the replay-start path.

In the steady state `remoteReplayCursor == persistedAck`. They diverge briefly during stale-server recovery and reconverge on the next `BatchAck` for the re-sent records. **Cross-generation regressions are out of scope for this phase.** The Reader API does not accept a `(gen, seq)` start tuple — it accepts only `start uint64` and filters by sequence within the segments it walks, and segment sequences reset on every generation roll (so a generation-blind seq compare across generations would silently drop or re-send records). The `LossRecord` carried by `wal.AppendLoss` carries a single `Generation`, so a cross-generation gap cannot be represented cleanly in one marker either. Generation-aware replay would require a generation-aware Reader API and multi-generation loss markers — neither exists today, and adding both is out-of-scope for the WTP client phase. The clamp helper therefore restricts the legitimate `ResendNeeded` outcome to the same-generation case (see below); cross-generation server tuples take the anomaly path.

Every server-supplied watermark — `SessionAck`, `BatchAck`, and `ServerHeartbeat` — is applied through the same clamp helper (`applyServerAckTuple`). The helper's outcomes:

- **First apply (no prior `persistedAck` recorded, i.e., `t.persistedAckPresent == false`)**: ADOPT the server tuple wholesale into BOTH `persistedAck` AND `remoteReplayCursor`. Call `wal.MarkAcked(serverGen, serverSeq)`. No anomaly log, no WARN — first contact between client and server cannot be classified as anomalous because there is no local baseline. The first-apply path is generation-agnostic; the WAL accepts any (gen, seq) tuple as the seed.
- **Same generation, server > local (`server_gen == local persistedAck.gen` AND `server_seq > local persistedAck.seq`)**: ADVANCE BOTH cursors. Call `wal.MarkAcked(serverGen, serverSeq)`. The clamp helper additionally guards against fabricated futures by requiring `server_seq <= wal.highSeq`; a higher-than-WAL claim takes the Anomaly path (see "True anomaly" sub-case 1). This is the normal, healthy ack-advance path.
- **Same generation, server < local (`server_gen == local persistedAck.gen` AND `server_seq < local persistedAck.seq`)**: SET `remoteReplayCursor = (serverGen, serverSeq)`; LEAVE `persistedAck` UNCHANGED. Do NOT call `wal.MarkAcked`. This is the legitimate stale-watermark recovery path. The next replay window opens at `serverSeq + 1` and re-sends the gap to the server. Log INFO (NOT WARN) with both tuples (`server_gen`, `server_seq`, `local_persisted_gen`, `local_persisted_seq`) — this is normal recovery, not an anomaly. The persistedAck stays put because the WAL has already GC'd or may GC at any time the segments at that watermark; the in-memory mirror MUST stay in lock-step with the on-disk meta.json so a future restart re-seeds correctly. Increment `wtp_resend_needed_total` (a counter — see Task 22b and the Operational signals subsection below).
- **Same generation, equal (`server_gen == local persistedAck.gen` AND `server_seq == local persistedAck.seq`)**: no-op on both cursors.
- **Cross-generation (`server_gen != local persistedAck.gen`, either direction)**: take the Anomaly path. The clamp helper returns the typed `Anomaly` outcome and the caller logs WARN + increments `wtp_anomalous_ack_total{reason="stale_generation"|"future_generation"}` per "True anomaly" sub-cases 2 and 3 below. NEITHER cursor moves; `wal.MarkAcked` is NOT called. Cross-generation `ResendNeeded` is **deliberately out of scope** for this phase (see the §"Effective-ack tuple and clamp" rationale immediately above and Task 15.1 / Task 17.X "Scope: same-generation only" headers).

**True anomaly (every case here produces a rate-limited WARN; local cursors are kept unchanged in all sub-cases).** Under the two-cursor model the anomaly bucket covers three disjoint shapes; all of them KEEP local cursors unchanged and emit a rate-limited WARN with FULL tuple context (`server_gen`, `server_seq`, `local_persisted_gen`, `local_persisted_seq`, `wal_high_water_seq`).

1. **`serverGen == local persistedAck.gen` AND `serverSeq > wal.highSeq`** — same generation, sequence beyond anything the WAL has ever appended. The server is ahead of physically-emitted history; this is the classic anomaly shape and is most often a test/replay misconfiguration or a server-side state corruption.
2. **`serverGen < local persistedAck.gen`** — server is on an older generation than the client's persistedAck. The client cannot legitimately replay across generations under the WAL Reader API today (sequence-keyed reader, sequences reset on every generation roll, single-`Generation` `LossRecord`), so a stale-generation server tuple cannot be expressed as a `ResendNeeded` outcome. This is the "stale-server crossed a key/generation rotation" shape — the operator-visible signal is that the server has not yet caught up to a SessionUpdate the client already advanced past. Increment `wtp_anomalous_ack_total{reason="stale_generation"}`.
3. **`serverGen > local persistedAck.gen`** — server claims a generation the client has not yet rolled to. The local WAL cannot have records under that generation (only the writer ever rolls), so the claim is fabricated relative to local history. Increment `wtp_anomalous_ack_total{reason="future_generation"}`.

In all three cases `t.persistedAck`, `t.remoteReplayCursor`, and the WAL meta are left untouched. The clamp helper returns the typed `Anomaly` outcome (see the helper signature below). Most production deployments will never hit these cases; if they do, the WARN log is the trigger for operator investigation. Cross-generation `ResendNeeded` is **deliberately out of scope** for this phase per the §"Effective-ack tuple and clamp" rationale above — the WAL Reader API would need a `(gen, seq)` start tuple and `LossRecord` would need a multi-generation range to express it cleanly, and neither change is in the WTP client phase scope.

**Loss between replay cursor and persisted ack.** When the server presents a lex-lower tuple **with the same generation as `persistedAck`** AND the WAL has already GC'd the segments holding records `(remoteReplayCursor, persistedAck]` (because GC was driven by an earlier higher ack), the data the server is asking for is permanently gone. The transport detects this BEFORE opening the replay reader: it queries `wal.WAL.EarliestDataSequence()` (a new accessor introduced in Task 14a — returns the lowest user sequence still on disk) and compares against `remoteReplayCursor.seq + 1`. If `earliestOnDisk > remoteReplayCursor.seq + 1`, the gap `[remoteReplayCursor.seq + 1, earliestOnDisk - 1]` has been GC'd and the transport synthesizes a single `wal.AppendLoss(LossRecord{FromSequence: remoteReplayCursor.seq + 1, ToSequence: earliestOnDisk - 1, Generation: persistedAck.gen, Reason: "ack_regression_after_gc"})` BEFORE opening the replay reader (so the loss marker is durably persisted in the WAL stream and reaches the server through the same `TransportLoss` propagation path the existing CRC-corruption / overflow markers use, per Task 13). The transport then opens the replay reader at `earliestOnDisk`. Increment `wtp_ack_regression_loss_total` (a counter — see Task 22b). This is permanent loss — the gap is unrecoverable from local state — but the protocol surface (`TransportLoss`) makes it visible to operators rather than silently swallowing the records.

**Operational signals subsection.** Two operator-visible counters surface ack-related misbehaviour and warrant alert rules:

- `wtp_resend_needed_total` (counter) — incremented every time `applyServerAckTuple` returns `ResendNeeded`. A sustained rate above ~5/min indicates the server is repeatedly presenting stale ack tuples, which usually points at server-side ack-persistence issues (lost durability, restart loss, or replication lag). Operators should investigate the server's ack-watermark store before chasing client-side issues. Steady-state expected rate is zero — `ResendNeeded` is the legitimate stale-recovery path, not the steady-state path.
- `wtp_ack_regression_loss_total` (counter) — incremented every time the transport synthesizes an `ack_regression_after_gc` loss marker. Any non-zero rate is operator-visible: it means a server presented a stale ack tuple AND the WAL had already GC'd the requested records. The data is permanently gone; the marker exists to make that visible to the server. Recurring increments suggest aggressive WAL `MaxTotalBytes` tuning relative to server ack lag, or a server that consistently lags far behind the client.

The two fields of EACH cursor move TOGETHER or neither does. Mixing local-seq with server-gen (or vice versa) creates an impossible state under the WAL's lex-`(gen, seq)` GC semantics — segments are sorted and reclaimed by lex tuple, so a half-applied server watermark would either silently retain unacked segments (data wedge) or silently drop in-flight segments (data loss). The clamp is type-enforced via `applyServerAckTuple`; no other code path advances either cursor. `SessionUpdate` is NOT an acknowledgement — it is a control frame for key/generation rotation per §"Acknowledgement model" above; it never advances either cursor.

`wal.Meta.AckRecorded == false` is a legitimate state, not a bug: it simply means "no ack has ever been persisted for this WAL directory." No production writer creates `AckRecorded=false` explicitly; the absence of `MarkAcked` calls leaves the field implicitly false on a fresh WAL. The cold-start seed maps it directly to `t.persistedAckPresent=false`, routing the next SessionAck through the first-apply branch.

The state-handler cases READ the appropriate cursor:

- **Replaying** opens its WAL `Reader` at `remoteReplayCursor + 1` (or 1 on first-apply when neither cursor is present) — this is the cursor that may have regressed, and the replayer re-sends the gap to the server.
- **Live** opens its WAL `Reader` at `max(remoteReplayCursor + 1, replayerLastEmittedSeq + 1)` — the same cursor, but bounded by where the replayer left off so we do not re-send records the replayer already shipped.

Neither state advances either cursor, and neither re-clamps. The clamp lives in the SessionAck / BatchAck / ServerHeartbeat handlers, not the state-handler cases.

### Frame validation and forward compatibility

Schema-valid but semantically invalid frames (e.g., `EventBatch.body` unset, `compression == COMPRESSION_UNSPECIFIED`, `algorithm == HASH_ALGORITHM_UNSPECIFIED`) are protocol-level errors. Receivers MUST:

1. Drop the offending frame.
2. Increment `wtp_dropped_invalid_frame_total{reason}` with the appropriate frame-validation reason. The reasons split into two categories with disjoint provenance:

   - **Validator-emitted reasons** (proto-side `wtpv1.ValidationReason` constants, returned by `ValidateEventBatch`/`ValidateSessionInit` as `*wtpv1.ValidationError`): `event_batch_body_unset`, `event_batch_compression_unspecified`, `event_batch_compression_mismatch` (uncompressed body declares non-NONE compression, or compressed_payload body declares NONE), `session_init_algorithm_unspecified`, `payload_too_large` (compressed_payload exceeds `MaxCompressedPayloadBytes`, matches `wtpv1.ErrPayloadTooLarge`), and `unknown` (forward-compat catch-all RESERVED for the validator-emitted `ReasonUnknown` case — a new oneof discriminator added to the proto schema before `validate.go` is updated to classify it; see the "MUST return `*ValidationError`" contract below). These reasons MUST appear in BOTH the proto-side `wtpv1.ValidationReason` enum and the metrics-side `WTPInvalidFrameReason` enum, with byte-equal string values so receivers can do `metrics.WTPInvalidFrameReason(ve.Reason)` safely.
   - **Metrics-only reasons** (incremented by code paths downstream of the validator, with no proto-side counterpart): `decompress_error` — incremented by the streaming-decompression code (NOT by `ValidateEventBatch`) when zstd/gzip framing fails or `MaxDecompressedBatchBytes` is exceeded. Decompression runs after `ValidateEventBatch` accepts the frame envelope, so a streaming-decode failure is not a "frame-validation" failure in the validator sense — it has no `wtpv1.ValidationReason` constant and exists only on the metrics side. `classifier_bypass` — incremented by the receiver-side `errors.As`-false defense-in-depth guard described below; signals a programming bug where a non-validator caller returned an `ErrInvalidFrame`-related error WITHOUT wrapping it in `*wtpv1.ValidationError`. Also has no proto-side counterpart because by definition the validator never emits it.

   The label key is `reason` to match the existing `wtp_reconnects_total{reason}` convention (and the planned `wtp_session_init_failures_total{reason}` / `wtp_session_rotation_failures_total{reason}` families introduced in Task 22a). The `unknown` reason and the `classifier_bypass` reason are deliberately split so operators can distinguish two very different failure modes without log correlation: `unknown` means schema drift on a peer (validator returned `ReasonUnknown` for a new oneof arm), while `classifier_bypass` means a code-path bug on the local side (an `ErrInvalidFrame`-related error reached the receiver classifier WITHOUT a `*ValidationError` wrapper). A non-zero `wtp_dropped_invalid_frame_total{reason="unknown"}` series MUST be treated as an operator-visible signal that a new validator failure class has shipped without being added to the enum; the next maintenance cycle MUST extend the enum (both `wtpv1.ValidationReason` and `WTPInvalidFrameReason`) to classify it under a dedicated label. A non-zero `wtp_dropped_invalid_frame_total{reason="classifier_bypass"}` series is by contrast a defect indicator — operators MUST find and fix the non-validator code path that bypassed the typed classifier (see the runbook subsection below).

   **Reason classification (validator contract).** `ValidateEventBatch` and `ValidateSessionInit` MUST return `*wtpv1.ValidationError` for every failure path, including the forward-compat unknown-oneof case (which returns `&ValidationError{Reason: ReasonUnknown, Inner: fmt.Errorf("unknown body oneof case")}`). A bare `fmt.Errorf("%w: ...", wtpv1.ErrInvalidFrame, ...)` return from a validator is a CONTRACT VIOLATION — there is no escape hatch from the typed boundary, and the `unknown` reason exists explicitly so the validator never has to fall back to a non-typed return. Receivers consume the reason via `errors.As(err, &ve)` and forward `ve.Reason` directly into `IncDroppedInvalidFrame`. Receivers MUST NOT inspect `err.Error()` or any substring of the formatted message to derive a reason — the typed boundary is the contract; the formatted message embeds peer-supplied byte counts and oneof discriminators that violate the sanitization rule.

   **Receiver-side defense in depth (should never trigger in production).** Receivers SHOULD nonetheless implement an `errors.As`-false guard that classifies a non-`*ValidationError` return as `reason="classifier_bypass"` (NOT `reason="unknown"` — those are now disjoint reasons with disjoint operator interpretations) and emits a WARN-level diagnostic (with `err_type` from `fmt.Sprintf("%T", err)` and `reason="classifier_bypass"`). This guard exists for the case where a non-validator caller passes a bare error into the receiver-side classifier (e.g., a unit-test mock or a future code path that bypasses `ValidateEventBatch`). For validator-returned errors `errors.As` SHOULD always succeed; if a deployed binary ever logs `non-typed frame validation error`, the validator path was bypassed and operators MUST investigate.
3. For client-side frames, send `Goaway{code: GOAWAY_CODE_UNSPECIFIED, message: "frame validation failed: <detail>"}` and close the session. For server-side frames, the client triggers a reconnect with reason `stream_recv_error`.

**Invalid-frame log sanitization.** Frame contents come from untrusted peers, so receivers MUST log only (a) the `reason` enum value and (b) a fixed-length hex prefix (≤16 bytes) of the offending frame's serialized representation. Receivers MUST NOT log the raw protobuf payload, claimed-but-unverified field values from the offending frame, or unbounded peer-supplied strings (e.g., a peer-controlled `message` field, a peer-controlled session ID echoed back, or any other byte slice that the validator has by definition not yet trusted). The same rationale that bans payload bytes from mapper-error strings (see "Mapper error sanitization" below) applies here: the structured log is emitted verbatim and may be ingested into operator-facing pipelines, so the validator must not become a data-exfiltration vector for the peer.

Sanitization applies to ALL log emission paths, not just the structured drop-class record at the receiver. The contract is type-enforced: every validator failure path returns `*wtpv1.ValidationError` (per the "MUST return `*ValidationError`" rule above), whose `Error()` method returns ONLY the canonical reason string. Outer log paths that log the bare error therefore receive only the reason string, not peer-derived content. Transport-layer interceptors (gRPC unary/stream interceptors, panic-recovery handlers, debug-trace formatters) and any other code that touches a `*wtpv1.ValidationError` or its `Inner` error MUST log only the `Reason` field. The `Inner` error MUST NOT be passed to any logger that emits to production sinks because its formatted message embeds the same peer-supplied byte counts and oneof discriminators the structured-log rule excludes; routing it through a different logger does not change the threat model. The `unknown` reason exists explicitly so the validator never has to fall back to a non-typed return — there is no escape hatch.

Implementations MUST make this enforceable at the type level by giving `*ValidationError` an `Error() string` method that returns ONLY the canonical reason value (no peer-derived content) — this means even a naive `slog.Error("...", "err", ve)` or `fmt.Sprintf("%s", ve)` cannot leak peer bytes. Combined with the validator's all-paths-return-`*ValidationError` contract, this means EVERY validator-returned error has a peer-safe `Error()` method by construction. The `Inner` error remains accessible via `Unwrap()` for in-memory inspection during tests (and for `errors.Is` / `errors.As` chain traversal), but is never serialized to logs. The TDD test for `ValidationError.Error()` MUST assert e.g. `(&ValidationError{Reason: ReasonPayloadTooLarge, Inner: fmt.Errorf("32MiB exceeds 8MiB cap")}).Error() == "payload_too_large"` to lock the behavior in.

**Stable production API.** `ValidationReason`, the constant set (`Reason*`), and the `AllValidationReasons() []ValidationReason` getter are STABLE PRODUCTION API — not test-only helpers. Any code that wires validator errors into metrics, alerting, or operator dashboards needs the canonical enumeration. The metrics package consumes `AllValidationReasons()` for its parity test, and external operators may consume it for dashboard generation or alert templating. The getter MUST remain stable across versions: appending a new reason is non-breaking; renaming or removing a reason is a breaking change that requires a coordinated metrics + dashboards migration. The getter returns a fresh copy on each call so callers cannot mutate the underlying enumeration — see the implementation note in the plan (Task 17 Step 4).

**EXCEPTION (carve-out within an unstable-until-1.0 package).** The `canyonroad.wtp.v1` package as a whole is pre-1.0 unstable per the §"Schema stability" section immediately below — tag numbers, field types, and enum values may change between commits, and there are no live deployments to break. The reason classification surface above is explicitly carved out from that pre-1.0 instability: `ValidationReason`, the `Reason*` constants, and `AllValidationReasons()` are STABLE within the otherwise-unstable package. Additions are non-breaking; removals or renames of existing reason constants require a coordinated metrics + dashboards migration and are treated as breaking changes regardless of pre-1.0 status. The rest of the proto package retains its current pre-1.0 instability — only the reason classification surface is locked. This carve-out exists because operators and external dashboard consumers depend on the reason string values being durable: a reason rename silently breaks every dashboard panel keyed on the old label value, and a removal silently drops alert rules. The §"Schema stability" rules below apply to everything else in the package; this paragraph is the sole exception.

**Validator coverage by phase.** Phase 4a-ii ships validators for the two frames the client already constructs and the server-side test fixtures already accept: `EventBatch` (body presence, body/compression agreement, payload cap) and `SessionInit` (algorithm enum). The remaining frame validators — `TransportLoss`, `Goaway`, `Heartbeat`, `ServerHeartbeat`, `BatchAck`, `SessionAck`, `SessionUpdate`, `ClientShutdown` — land alongside the receivers that consume them in **Phase 8** (transport state machine, where the client interprets every inbound `ServerMessage`) and **Phase 9** (in-tree testserver, where the server side validates inbound `ClientMessage`). Until those phases land, schema-valid frames of those types are accepted as-is.

#### Schema stability

The `canyonroad.wtp.v1` package is **unstable until the first tagged 1.0 release of the WTP protocol** (separate from the agentsh release version), with ONE exception: the reason classification surface (`ValidationReason`, the `Reason*` constants, and `AllValidationReasons()`) is carved out as STABLE within this otherwise-unstable package — see the §"Stable production API" paragraph immediately above for the carve-out details. Pre-1.0 (everything OTHER than the carved-out reason surface):

- Tag numbers, field types, and enum values may change between commits with no migration burden. There are no live deployments to break.
- Generated `.pb.go` is regenerated on every change. Goldens (Phase 4b) are regenerated to match.
- Mixed client/server versions are NOT supported; both sides must be built from the same commit.

Post-1.0, the forward-compatibility rules below take effect:

- Existing tag numbers MUST be preserved. Removed fields are marked `reserved`.
- Wire-incompatible changes (type change, tag reassignment, enum-value reuse) require a fresh package version (`canyonroad.wtp.v2`) and a per-side migration plan.
- The 1.0 cut is gated on (a) at least one external implementation having validated the conformance vectors and (b) the decision being recorded in this spec under `#### Stability cut`.

Forward compatibility (post-1.0):

- Unknown enum values MUST be treated as `*_UNSPECIFIED` and produce the same drop-and-error path. Adding a new enum value is therefore a wire break for older clients/servers; bump `format_version` in the same change.
- New oneof arms in `ClientMessage`/`ServerMessage` are forward-compatible only if the receiver tolerates the unset case as a no-op rather than a protocol error. We declare new arms NON-forward-compatible until per-arm rollout policy is added in a future spec revision.
- New fields with new tags are forward-compatible only if they default to a meaningful zero value. Adding required-meaning fields is a wire break.

### Compression safety

**MVP scope.** The Phase 4a-ii client always emits `Compression_COMPRESSION_NONE`; no compression encode or decode path ships in this implementation cycle. The caps below are documentation contracts that any future decompression code MUST honor. Wire goldens (Phase 4b) cover only the uncompressed body shape.

When `EventBatch.compression` is `COMPRESSION_ZSTD` or `COMPRESSION_GZIP`, receivers MUST enforce two independent caps before decompression:

1. **Compressed-payload cap**: `len(compressed_payload) <= 8 MiB`. Larger payloads are rejected with `Goaway{code: GOAWAY_CODE_UNSPECIFIED, message: "compressed payload exceeds cap"}` and the session closed.
2. **Decompressed-size cap**: streaming decoder configured with a hard limit of `64 MiB` per batch. Exceeding the cap aborts decompression and triggers the same Goaway path. Decoders MUST stream-and-cap, not allocate up-front from a header.

Malformed compressed payloads (zstd/gzip framing errors) are protocol-level errors handled identically to schema-valid-but-semantically-invalid frames per "Frame validation" above. Receivers MUST NOT log or surface decompressed payload bytes when rejecting; only the framing error category is recorded.

The 8 MiB / 64 MiB caps are conservative defaults sized so that a single batch fits in CPU L3 plus some slack on commodity hardware; future revisions may raise them but receivers MUST always apply some cap (no `0 = unlimited` semantic).

### Backoff

Exponential with jitter: `min(base * 2^n, max) ± 30%`. Defaults: base=500ms, max=30s. Reset on successful SessionInit + first ack received.

### Metrics

All exposed via slog at debug + as structured counters consumable by the existing `internal/metrics` registry:

- `wtp_events_appended_total` (counter)
- `wtp_events_acked_total` (counter)
- `wtp_batches_sent_total` (counter)
- `wtp_bytes_sent_total` (counter, post-compression)
- `wtp_transport_loss_total` (counter)
- `wtp_reconnects_total` (counter, labeled by reason; reason is one of: `dial_failed`, `stream_recv_error`, `send_error`, `ack_timeout`, `heartbeat_timeout`, `server_goaway`, `unknown`)
  - `dial_failed`: gRPC `Dial`/`NewClient` failed before any stream opened.
  - `stream_recv_error`: stream `Recv` returned a non-EOF error after a session was established.
  - `send_error`: stream `Send`/`CloseSend` returned an error.
  - `ack_timeout`: no `BatchAck` received within the configured ack-timeout window for in-flight batches.
  - `heartbeat_timeout`: no `ServerHeartbeat` received within the configured heartbeat-timeout window.
  - `server_goaway`: server sent a `Goaway` frame requesting reconnect.
  - `unknown`: catch-all when the reconnect cause cannot be classified.
- `wtp_session_state` (gauge: 0=connecting, 1=replaying, 2=live, 3=shutdown)
- `wtp_wal_segments` (gauge)
- `wtp_wal_bytes` (gauge)
- `wtp_ack_high_watermark` (gauge)
- `wtp_dropped_invalid_mapper_total` (counter; increments when `compact.Encode` returns `ErrInvalidMapper` — defense in depth, normally 0 because `Store.New` rejects the same condition at construction time; non-zero indicates a code path mutated the mapper post-construction; structured log with fields {session_id, sequence, generation, err})
- `wtp_dropped_invalid_timestamp_total` (counter; increments when `compact.Encode` returns `ErrInvalidTimestamp` because `ev.Timestamp` is zero or pre-epoch; structured log with fields {session_id, sequence, generation, err})
- `wtp_dropped_mapper_failure_total` (counter; increments when `compact.Encode` returns a wrapped mapper-side error — i.e., `mapper.Map()` returned a non-sentinel error and `Encode` wrapped it as `compact mapper: %w`; this is the catch-all for mapper-internal failures and falls through the default branch of the `errors.Is` classification switch in `AppendEvent`; structured log with fields {session_id, sequence, generation, err})
- `wtp_dropped_invalid_utf8_total` (counter; increments when `chain.ErrInvalidUTF8` surfaces from the canonical encoder for any record-level encode — record is dropped, structured log emitted with fields {session_id, sequence, generation, err}; the offending field name appears as text inside the wrapped error message — `chain: invalid utf-8 in string field: field "<name>"` — operators grep `err` for diagnostics rather than relying on a separate structured attribute)
- `wtp_dropped_invalid_frame_total{reason}` (counter labeled by frame-validation reason; increments when a schema-valid but semantically invalid protocol frame is dropped per the "Frame validation and forward compatibility" section above; reasons follow the same fixed-enum + escapeLabelValue pattern as `wtp_session_init_failures_total{reason}`. The reason set splits into two disjoint categories: **validator-emitted reasons** (proto-side `wtpv1.ValidationReason` constants returned by `ValidateEventBatch`/`ValidateSessionInit` as `*wtpv1.ValidationError`) — `event_batch_body_unset`, `event_batch_compression_unspecified`, `session_init_algorithm_unspecified`, `event_batch_compression_mismatch`, `payload_too_large`, and `unknown` — these MUST appear in BOTH the proto-side `ValidationReason` enum and the metrics-side `WTPInvalidFrameReason` enum with byte-equal string values; and **metrics-only reasons** — `decompress_error` (streaming decompression fails or exceeds `MaxDecompressedBatchBytes` — emitted by the streaming-decompression code downstream of `ValidateEventBatch`, with no proto-side counterpart) and `classifier_bypass` (incremented by the receiver-side `errors.As`-false defense-in-depth guard when a non-validator caller passes a bare `ErrInvalidFrame`-related error into the classifier — also no proto-side counterpart by definition because the validator never emits it). The `unknown` reason is RESERVED for the validator-emitted forward-compat unknown-oneof case (validator returns `&ValidationError{Reason: ReasonUnknown, ...}` rather than a bare `fmt.Errorf`); a non-zero `wtp_dropped_invalid_frame_total{reason="unknown"}` series remains operator-visible signal that a new validator failure class has shipped without a dedicated label and the next maintenance cycle MUST extend the enum to cover it. A non-zero `wtp_dropped_invalid_frame_total{reason="classifier_bypass"}` series is by contrast a code-path defect indicator — see the "Operator runbook" subsection below for triage guidance. Structured log emitted with fields {session_id, reason, hex_prefix} where `session_id` is the local session UUID (NOT peer-supplied), `reason` is the canonical enum value (NOT peer-supplied), and `hex_prefix` is a hex-encoded prefix of the offending frame's serialized representation capped at 16 input bytes (so 32 hex chars output) per the "Invalid-frame log sanitization" rule. The raw `err` returned by `wtpv1.ValidateEventBatch` / `ValidateSessionInit` MUST NOT be logged because its formatted message embeds peer-supplied byte counts and oneof discriminators that violate the sanitization rule; if implementers need debug visibility for a specific failure class they SHOULD bump the validator log level locally during diagnosis, not change the production field set. Chain/sequence are NOT logged because frame-validation failures occur before per-record drop bookkeeping. See "Operator runbook: invalid-frame reason interpretation" below for triage guidance per reason.)
- `wtp_session_init_failures_total{reason}` (counter labeled by reason; reason `invalid_utf8` increments when ComputeContextDigest at SessionInit returns ErrInvalidUTF8; structured log with same `err`-string convention)
- `wtp_session_rotation_failures_total{reason}` (counter labeled by reason; reason `invalid_utf8` increments when ComputeContextDigest during SessionUpdate or chain rotation returns ErrInvalidUTF8; structured log with same `err`-string convention)
- `wtp_dropped_sequence_overflow_total` (counter; increments when `ev.Chain.Sequence > math.MaxInt64` at the store-integration boundary — record is dropped before WAL admission, structured log emitted with fields {session_id, sequence, generation})
- `wtp_wal_corruption_total` (counter; CRC corruption events during WAL replay)
- `wtp_send_latency_seconds` (histogram, per batch)

Dashboard/alerting impact. The new sink-failure metrics — five unlabeled counters (`wtp_dropped_invalid_mapper_total`, `wtp_dropped_invalid_timestamp_total`, `wtp_dropped_mapper_failure_total`, `wtp_dropped_invalid_utf8_total`, `wtp_dropped_sequence_overflow_total`) plus three labeled families (`wtp_dropped_invalid_frame_total{reason}`, `wtp_session_init_failures_total{reason}`, `wtp_session_rotation_failures_total{reason}`) — all follow the always-emit contract: the families appear at zero on every scrape regardless of activity, so adding them does not change cardinality at quiescence. Rollout phasing is reason-aware (see "Rollout phasing" subsection below) — newly added always-emit metric NAMES are zero-rollout-friendly because no existing dashboard/alert can be keyed on a metric name that did not exist; semantic narrowing of an EXISTING label value or REMOVAL of an existing series is operator-facing and requires monitoring preflight. New alerting rules can be added at operator discretion. Suggested alerting (the labeled `wtp_dropped_invalid_frame_total{reason}` family is reason-aware — see "Alerting policy (per reason) for `wtp_dropped_invalid_frame_total`" below; `wtp_dropped_invalid_frame_total` (without a `reason` label) MUST NOT have a blanket alert, because the appropriate operator action depends on the reason value):
- Page on `rate(wtp_session_init_failures_total[5m]) > 0` — unrecoverable misconfiguration.
- Alert-not-page on `rate(wtp_dropped_invalid_utf8_total[5m]) > 0.01` — event source corruption.
- Alert-not-page on `rate(wtp_dropped_invalid_mapper_total[5m]) > 0` — defense-in-depth tripwire; non-zero means a code-path bug bypassed `Store.New` validation.
- Alert-not-page on `rate(wtp_dropped_invalid_timestamp_total[5m]) > 0` — producers emitting zero or pre-epoch timestamps; usually benign but indicates upstream stamping is missing.
- Alert-not-page on `rate(wtp_dropped_mapper_failure_total[5m]) > 0.01` — mapper implementation returning errors; investigate the wrapped `err` in the structured log.

#### Alerting policy (per reason) for `wtp_dropped_invalid_frame_total`

`wtp_dropped_invalid_frame_total{reason}` MUST be alerted per-reason — a single blanket rule against `wtp_dropped_invalid_frame_total` (without the `reason` label) would conflate operationally distinct failure modes and produce the wrong page/alert decision. The runbook below ("Operator runbook: invalid-frame reason interpretation") is the source of truth for how to triage each reason; the policy summary here MUST stay aligned with it.

- **`unknown`**: ALERT (do not page) on `rate(wtp_dropped_invalid_frame_total{reason="unknown"}[5m]) > 0` sustained over 5 min. Triage during business hours. Action: a peer rolled out a new schema and the local validator does not recognize the new `body` oneof discriminator; extend `ValidationReason` (and its metrics-side mirror `WTPInvalidFrameReason`) to cover the new case.
- **`classifier_bypass`**: PAGE on the first non-zero observation (`increase(wtp_dropped_invalid_frame_total{reason="classifier_bypass"}[5m]) > 0`). This counter is a local-bug indicator — the validator contract was violated. Action: identify and fix the offending caller immediately (search recent WARN logs for either `err_type` (receiver-side path) or `raw_reason` (metrics-side label-collapse path) — see runbook below).
- **`decompress_error`**: ALERT (do not page) on `rate(wtp_dropped_invalid_frame_total{reason="decompress_error"}[5m]) > 1/min` sustained over 5 min. Triage during business hours. Action: peer-side compression bug or misconfigured payload cap (`MaxDecompressedBatchBytes`); inspect peer logs for the encoder version and configured caps.
- **`event_batch_body_unset`, `event_batch_compression_unspecified`, `event_batch_compression_mismatch`, `session_init_algorithm_unspecified`, `payload_too_large`** (validator-emitted, peer-side schema-valid-but-semantically-broken frames): ALERT (do not page) on `rate(wtp_dropped_invalid_frame_total{reason="<value>"}[5m]) > 1/min` sustained over 5 min. Triage during business hours. Action: peer-side bug; cross-reference the peer's `agent_version` (from `SessionInit`) and notify the peer team to align their frame construction with the spec.

The aggregate-rate metric `wtp_dropped_invalid_frame_total` (without a `reason` label) MUST NOT have a blanket alert — alerting is reason-aware per the matrix above. Operators with prior dashboards keyed on the unlabeled aggregate MUST migrate to per-reason rules; see "Migration from pre-split `unknown`" below for the migration recipe (the same caveat applies in the opposite direction: a single rule against the family-without-label collapses the runbook's action mapping into one alert text).

#### Operator runbook: invalid-frame reason interpretation

The `wtp_dropped_invalid_frame_total{reason}` family carries three operator-actionable reason values whose semantics differ enough that a single alert text cannot describe the right response. The runbook below maps each reason value to the underlying failure mode, the operator action, and a per-reason alert threshold. (The remaining validator-emitted reasons — `event_batch_body_unset`, `event_batch_compression_unspecified`, `event_batch_compression_mismatch`, `session_init_algorithm_unspecified`, `payload_too_large` — share the same generic interpretation: a peer is sending a schema-valid but semantically broken frame, identified by the reason label; the action is to inspect peer logs for the offending frame and align the peer with the spec. The three reasons below are called out separately because their interpretation is non-obvious or actionable in a non-generic way.)

- **`unknown`** — Validator returned `ReasonUnknown`. This means a peer has sent an `EventBatch` with a `body` oneof discriminator that the local validator does not recognize — typically a schema drift where the peer is on a newer protobuf version than the local binary. Action: cross-reference the peer's `agent_version` (from `SessionInit`), check the proto schema at that version, and add the missing case to `ValidateEventBatch` (which entails extending `ValidationReason` with a new dedicated constant and mirroring it into the metrics-side `WTPInvalidFrameReason` enum — see §"Stable production API"). While unaddressed, peers using the new discriminator will be rejected and disconnected. Alert threshold: any non-zero rate sustained over 5 min indicates a peer rolled out a new schema and the receiver needs an update.
- **`classifier_bypass`** — Local-side defect indicator. Two code paths feed this reason and BOTH emit a WARN-level structured log when triggered (operators MUST grep recent WARN logs to determine which path fired):
  - **Receiver path** (defense-in-depth `errors.As`-false guard): a code path returned an `ErrInvalidFrame`-related error WITHOUT wrapping it in `*wtpv1.ValidationError`. Log line: `slog.Warn("non-typed frame validation error", "err_type", fmt.Sprintf("%T", err), "reason", "classifier_bypass")` — grep recent WARN logs for `non-typed frame validation error` and inspect `err_type` to identify the offending caller's error type.
  - **Metrics path** (`IncDroppedInvalidFrame` invalid-label collapse): a caller passed a `WTPInvalidFrameReason` value that is not in the canonical `wtpInvalidFrameReasonsValid` set. Log line: `slog.Warn("invalid invalid-frame reason label", "raw_reason", reason, "reason", "classifier_bypass")` where `raw_reason` is the unknown string the caller passed (this string is internal — caller-controlled, NEVER peer-derived — so it is safe to log verbatim per the invalid-frame log sanitization rule). Grep recent WARN logs for `invalid invalid-frame reason label` and inspect `raw_reason` to identify the offending callsite.

  Both paths are programming bugs — the validator contract requires every failure to be a typed `*ValidationError`, and metrics callers MUST use the canonical `WTPInvalidFrameReason*` constants. Action: search for non-`*ValidationError` returns of `ErrInvalidFrame` in the codebase (`rg -n "fmt.Errorf.*ErrInvalidFrame" proto/ internal/`) AND for any `IncDroppedInvalidFrame` callers that construct a `WTPInvalidFrameReason` from a string literal or peer-supplied value rather than a constant. Use the WARN log discriminator above to narrow the search to the path that actually fired. Alert threshold: ANY non-zero increment is a bug — this counter should be permanently zero in healthy production. Page (do not just alert-not-page) on the first non-zero observation; the longer the bug runs unfixed, the more drift accumulates between the typed boundary contract and actual code.

  **WARN rate-limit (both `classifier_bypass` paths).** Both `classifier_bypass` WARN log paths (the receiver-side `non-typed frame validation error` and the metrics-side `invalid invalid-frame reason label`) MUST be rate-limited to AT MOST 10 emissions per minute per process. Without rate-limiting, a hot-path bug (e.g., a tight loop calling `IncDroppedInvalidFrame` with a bad string, or a receive-loop returning a bare `ErrInvalidFrame`-related error on every frame) would turn a runtime defect into a log-storage incident. Implementation: a SHARED package-level token bucket (e.g., `golang.org/x/time/rate.NewLimiter(rate.Every(6*time.Second), 1)`) lives in the metrics package and is consumed by BOTH code-paths so a single bursty caller does not starve the other path's diagnostic; the limiter starts full so the first emission per process burst is always allowed. The COUNTER (`wtp_dropped_invalid_frame_total{reason="classifier_bypass"}`) tracks the true volume regardless of throttling — operators read the metric for the rate signal and the (sampled) WARN log for the diagnostic discriminator (`err_type` for receiver path, `raw_reason` for metrics path).

  When the rate-limiter throttles a WARN, the suppressed event is NOT counted by any auxiliary "logs dropped" metric — operators reading the throttled WARN see the actual error type and the corresponding counter rate gives them the volume signal. The first emission per process burst is always allowed (token bucket starts full). The rate-limit applies ONLY to `classifier_bypass` WARN paths; other validator-emitted-reason WARN logs (the receiver path that emits per-frame logs for legitimate validator failures) follow the existing per-frame logging contract — those are already gated by the receiver tearing down the stream and entering reconnect/Goaway, so log volume is bounded by the peer disconnecting.

- **`decompress_error`** — Streaming decompression failed (corrupt zstd/gzip stream, exceeded `MaxDecompressedBatchBytes`). Action: peer is sending malformed or oversized payloads. Check peer logs for compression configuration (encoder version, payload caps configured). Alert threshold: sustained non-zero rate indicates a peer-side compression bug or a misconfigured payload cap; one-off spikes during normal operation are expected at low rates due to network corruption.

#### Migration from pre-split `unknown`

Prior versions of this spec used a single `reason="unknown"` value to cover both validator schema drift and defense-in-depth bypass. The split into `unknown` (validator-emitted, schema drift) and `classifier_bypass` (metrics-only, local-side bug) means any existing queries, dashboards, or alerts keyed on `reason="unknown"` will under-count after the split — they will silently miss the `classifier_bypass` cases (and a `classifier_bypass`-keyed query will silently miss the schema-drift cases). Operators MUST audit their alert/dashboard definitions before rollout and update each `reason="unknown"` reference to one of the following, depending on the original intent:

- `reason="unknown"` (unchanged label string, narrowed semantics) — keep this if the intent was to detect schema drift only. Recommended for capacity-planning panels where the operationally interesting signal is "the peer rolled out a newer protobuf schema than the local binary supports".
- `reason=~"unknown|classifier_bypass"` — use this if the intent was to detect ALL un-classified frame failures (the pre-split semantic). Recommended for legacy dashboards being migrated incrementally; pair with a follow-up split into the two reason-specific panels per the alerting policy above so the page/alert decision can diverge.
- `reason="classifier_bypass"` — use this if the intent was specifically to alert on local code-path bypass. This SHOULD be a high-severity page per the "Alerting policy (per reason)" subsection above; in healthy production this counter is permanently zero.

The pre-split `unknown` series is NOT preserved; there is no shim, alias, or zero-emit deprecation window for the old combined semantic. This is a breaking change for any panels/alerts that depend on a single `unknown` value covering both meanings — the rollout will silently change the semantics of existing `reason="unknown"` queries unless the operator audits and updates them. Cross-reference: the runbook entries for `unknown` and `classifier_bypass` above are the source of truth for the post-split semantics.

Migration guidance: removed `wtp_dropped_missing_chain_total`. The earlier Task 3 metric inventory shipped a `wtp_dropped_missing_chain_total` counter that tracked missing-chain as a silent drop. The semantics changed in Round 4: missing-chain is now propagated from `AppendEvent` as a wrapped `compact.ErrMissingChain` error rather than silently dropped, so the underlying event class the counter tracked no longer exists and the counter is removed (Task 22a Step 3.5 in the implementation plan). Operators should plan accordingly:

- Operators currently scraping `wtp_dropped_missing_chain_total` will see the series disappear from `/metrics` after the rollout. There is no zero-emit deprecation window — the field, accessor, and emit lines are all deleted in the same change.
- The closest replacements depend on what operators were using the old counter for:
  - If the dashboard/alert was watching for composite-store regressions, the **only guaranteed emission signal** is the ERROR-severity structured log emitted by `AppendEvent` per §"Caller contract for propagated `compact.ErrMissingChain`" — there is NO guaranteed metric-side surface, because per that contract clause (b) the sink MUST NOT auto-disable or self-shutdown and clause (c) the caller MAY log-and-continue without tearing the WTP stream down. Operators MUST therefore replace the metric-based alert with one of:
    - **Log-based alert/SLO** (recommended). Alert on the ERROR-severity structured log entry whose `err` field equals the exact sentinel string `"compact.Encode: ev.Chain is nil; composite did not stamp"` (the value of `compact.ErrMissingChain.Error()` — see `internal/store/watchtower/compact/encoder.go`'s `ErrMissingChain` definition). The trigger contract is the `err` sentinel match plus a component-source-scoping clause when required by the field-preservation classification (see below). The full field set emitted by `AppendEvent` is `{event_id, session_id, event_type, err}` per §"Caller contract for propagated `compact.ErrMissingChain`" clause (a), but the auxiliary fields (`event_id`, `session_id`, `event_type`) play a DIAGNOSTIC role only — they give the on-call engineer per-event context after the alert fires; they are not part of the alert-trigger predicate. Whether the alert query may also bind `event_type` / `session_id` / `event_id` as predicates depends on the field-preservation classification below: under `ok`, all four are queryable; under `err-only`, only `err` plus the source-scoping clause are guaranteed-queryable; under `msg-only`, only the rendered message body plus the source-scoping clause are. The `err` string is part of the operator-facing contract — it MUST NOT be silently rewritten without a coordinated monitoring migration, and any future change requires a paired update to this section. Pair the alert with the runbook section that covers missing-chain composite-store regressions; pin the runbook URL in the log-alert/SLO artifact's annotation/description field equivalent (see Task 27a Step 4 for the per-stack mapping). Implementations of the operator monitoring stack (Loki, Splunk, Elastic, Datadog Logs, etc.) all support field-matched alerts on structured log entries; the exact query syntax is operator-stack-specific and not prescribed here. **Field-preservation precondition.** Operators MUST first verify how their production log pipeline preserves the structured field set for this component. Four classifications are supported, of which the first three enable this option:
        - **`field_preservation: ok`.** All four fields (`event_id`, `session_id`, `event_type`, `err`) reach the log-aggregation system as separately queryable / indexed structured fields, AND the `err` value is the exact sentinel string byte-for-byte. The log-based alert MAY use a field-equality predicate on `err` plus the appropriate component scoping (service/logger/source identifier), and MAY additionally bind `event_type` / `session_id` / `event_id` either as alert-trigger predicates or as diagnostic-context labels in the alert payload.
        - **`field_preservation: err-only` (degraded — diagnostic loss only).** The `err` field reaches the log-aggregation system as a separately queryable / indexed structured field with the exact sentinel string byte-for-byte, but one or more of `event_id` / `session_id` / `event_type` is renamed, dropped, or moved into the rendered message body. The alert-trigger surface is unchanged: a structured `err == sentinel` predicate (plus required component source scoping; see msg-only below for why source scoping is mandatory) remains valid AND precise, with no false-positive risk. The cost is purely diagnostic: when the alert fires, operators have less per-event context for triage. Operators choosing this mode MUST record (a) which auxiliary fields are missing, (b) any alternative source the operator can correlate against (e.g. session ID present in the rendered message body, request-trace ID injected by surrounding middleware), and (c) the source-scoping selector — all in the migration tracking artifact, so the on-call runbook can document the diminished context up-front.
        - **`field_preservation: msg-only` (degraded — alert via rendered string).** Neither the structured `err` field NOR a structured replacement is preserved, but the rendered message body still contains the exact sentinel substring byte-for-byte. The log-based alert MAY use a substring/regex predicate against the rendered message body, BUT the predicate MUST also constrain the component source — at minimum a service/logger/source-name match for this binary (e.g. matching the slog logger name for the WTP sink, the OTEL service name, the container/pod label, or the per-stack equivalent). Without source scoping, an unrelated component that happens to log the same sentinel substring will trigger false positives. Operators choosing this degraded mode MUST record the specific scoping selector in the migration tracking artifact alongside the substring predicate.
        - **`field_preservation: broken`.** Neither the structured `err` field NOR the rendered sentinel substring survives end-to-end. This option is NOT available — operators MUST fall back to the **Delete** or **Reconnect-based alert (CONDITIONAL)** options below, OR upgrade their log pipeline before retrying the verification.
        See Task 27a Step 1b in the implementation plan for the canonical verification recipe.
    - **Delete the alert**. Appropriate when the original alert was a coarse catch-all and the team's incident response is keyed on developer-facing diagnostics (the propagated wrapped error in the audit pipeline) rather than per-event monitoring.
    - **Reconnect-based alert (CONDITIONAL — verification required)**. `wtp_reconnects_total{reason="..."}` is a candidate ONLY at sites where the caller wiring DOES tear down the WTP stream on propagated `compact.ErrMissingChain` — the caller contract permits but does NOT require this behavior, so the reconnect family has no contractually guaranteed emission path from this error. Operators choosing this path MUST first verify the caller behavior in their build (inspect the integration code that consumes `AppendEvent`'s returned error, confirm it closes/cancels the WTP stream on `errors.Is(err, compact.ErrMissingChain)`, and record the specific `wtp_reconnects_total{reason}` label the caller emits) AND record the verification reference in the migration tracking artifact alongside the new selector. Without that verification the alert may quietly never fire. The handshake-time families `wtp_session_init_failures_total{reason}` / `wtp_session_rotation_failures_total{reason}` (planned in Task 22a, Phase 8) are NEVER valid redirect targets — those families fire only during the SessionInit/SessionUpdate handshake for context-digest handshake failures (`invalid_utf8` plus the `unknown` catch-all), and there is no defined emission path from a propagated `compact.ErrMissingChain` into them. If a future caller-side wiring change introduces such a path, the design must be extended to declare the new reason label and the source-of-truth contract for it.
  - If the dashboard/alert was watching for protocol-layer drops more broadly, `wtp_dropped_invalid_frame_total{reason="..."}` is the correct replacement family (peer-side semantically-invalid frames). This family is unrelated to `compact.ErrMissingChain` (which is a sink-internal composite-store regression, not a protocol frame failure) and is mentioned here only because operators sometimes co-locate protocol-drop monitoring with composite-regression monitoring on a single panel.
- Recommended operator action as part of the rollout: delete or update any dashboard panel or alerting rule that references `wtp_dropped_missing_chain_total`. The all-zero series can no longer fire by definition; leaving the panel in place produces a misleading "healthy" indicator for a class of failure that is now reported through a different channel.

The rest of the always-emit / zero-init contract for the eight new counters (above) is unchanged — they appear at zero on every scrape from the moment metrics is initialized, regardless of WTP enable state.

#### Rollout phasing

The metrics changes in this design are not uniformly safe to ship without operator coordination. Categorize each change before deciding whether monitoring artifacts must be updated first:

- **No phased rollout required for**: newly added always-emit metric families with new metric NAMES (`wtp_dropped_invalid_mapper_total`, `wtp_dropped_invalid_timestamp_total`, `wtp_dropped_mapper_failure_total`, `wtp_dropped_invalid_utf8_total`, `wtp_dropped_sequence_overflow_total`, `wtp_session_init_failures_total{reason}`, `wtp_session_rotation_failures_total{reason}`, plus newly-named labels added to existing metric names where no operator dashboard/alert is keyed on the new label value). These are zero-rollout-friendly because no existing dashboard or alert can be keyed on a metric name or label value that did not exist before the rollout — they start at zero from the moment code rolls out and acquire operator queries only when operators choose to add them.
- **Phased rollout (or coordinated rollout) REQUIRED for**:
  - `wtp_dropped_invalid_frame_total{reason="unknown"}` semantic narrowing — existing dashboards and alerts keyed on `reason="unknown"` will under-count after rollout because the `classifier_bypass` portion moves out of the `unknown` bucket into a dedicated label value. The label string is unchanged; what changed is what it means. **Monitoring updates MUST ship BEFORE OR WITH the code rollout** — see the "Migration from pre-split `unknown`" subsection above for the per-intent migration recipe.
  - `wtp_dropped_missing_chain_total` removal — the entire series disappears from `/metrics` after rollout. Any dashboard panel or alert rule that references this series will break (no data, or a "no series" error depending on the platform). **Monitoring updates MUST ship BEFORE OR WITH the code rollout** — see the "Migration guidance: removed `wtp_dropped_missing_chain_total`" paragraph above for the redirection map (which existing replacement to use depends on the original intent of the panel).

**Rollout precondition.** All operator-facing monitoring artifacts — Prometheus alerting rules, Grafana panels, runbook URLs in alert annotations — MUST be updated to reference the new reason taxonomy AND to remove or redirect `wtp_dropped_missing_chain_total` references, BEFORE the code rollout reaches production. Ownership split:

- **Implementation team owns** the preflight check that this update has happened in the production monitoring environment.
- **SRE/ops team owns** the actual monitoring artifact updates (Prometheus alerting rules, Grafana panels, runbook URLs).

Both responsibilities MUST be acknowledged with explicit sign-off (a written confirmation in the rollout ticket, or equivalent) before the production code rollout begins. The implementation team SHALL NOT begin the production rollout until SRE/ops has confirmed the migration is complete in production monitoring. Cross-reference: the migration paragraphs above ("Migration from pre-split `unknown`" and "Migration guidance: removed `wtp_dropped_missing_chain_total`") are the source of truth for the artifact-level changes; the corresponding implementation-plan task ("Operator monitoring migration") sequences the work and gates the production-rollout step.

Composite-store regression note. The `compact.Encode` `ErrMissingChain` branch is intentionally NOT a counter. Missing-chain is a programming error — the composite store MUST stamp `ev.Chain` before fanning out to any sink, and a sink reaching `Encode` with a nil chain indicates a composite-store regression that operators should surface loudly. `AppendEvent` therefore propagates `ErrMissingChain` to the caller as a wrapped error (`watchtower: %w`) rather than dropping silently. See the Encode boundary semantics paragraph below for the contrast with the silent-drop classes.

Backwards-compat operator note. Operators enabling WTP after deployment should monitor `wtp_dropped_invalid_timestamp_total` for the first window. Existing producers that previously emitted `types.Event{}` zero-valued (e.g., test-derived paths) will hit `ErrInvalidTimestamp` and be dropped at the WTP boundary. Recommended remediation: stamp `ev.Timestamp = time.Now()` at the producer. The drop is silent (sink-internal — `AppendEvent` returns `nil`, never propagating to the caller), so only the metric and structured WARN log surface it.

Producers with legitimate historical timestamps (e.g., importing audit logs from external systems) MUST clamp or reject pre-epoch values upstream. WTP rejects pre-epoch timestamps unconditionally because the wire format is `uint64` nanoseconds — there is no representation for pre-1970 instants. This is an explicit limitation of the protocol; if pre-epoch ingestion is required, the producer must either offset to a post-epoch value (preserving relative ordering) or use a separate audit pipeline.

Histogram exposition snapshots bucket counts under the latency mutex and writes them unlocked, so a slow scrape never blocks `ObserveSendLatency` callers on the hot send path.

WTP metric series are always emitted, even when the sink is disabled. Zero-valued counters and gauges keep dashboards stable across config changes; presence of the family is not a signal that WTP is enabled (use `wtp_session_state` to detect a live session).

## Configuration & Wiring

### Config struct

Mirrors spec §10.2 verbatim. Loaded by the existing `internal/config` package alongside other sink configs.

```go
type Config struct {
    Enabled bool

    Endpoint   string            // host:port
    SessionID  string            // optional; auto-generated ULID if empty
    StateDir   string            // default: per-OS state dir + "/wtp" (Linux: $XDG_STATE_HOME/agentsh/wtp; macOS: ~/Library/Application Support/agentsh/wtp; Windows: %LOCALAPPDATA%\agentsh\wtp — non-roaming, distinct from APPDATA)
    EphemeralMode bool

    TLS struct {
        InsecureSkipVerify bool   // tests/dev only
        CACertFile         string
        ClientCertFile     string
        ClientKeyFile      string
    }

    Auth struct {
        TokenFile      string    // mutually exclusive with the others
        TokenEnv       string
        ClientCertAuth bool      // use mTLS cert as identity; no bearer
    }

    Chain struct {
        Algorithm string  // hmac-sha256 | hmac-sha512 (default sha256)
        KeyFile   string  // resolved via existing internal/audit/kms LoadKey
        KeyEnv    string
        // KMS sources (AWS, Azure, Vault, GCP) reuse internal/audit/kms
        // config blocks; we share that struct rather than re-declare it.
        // Each sink may use a different key (per Phase 0 contract); only the
        // shared (sequence, generation) is required to match across sinks.
    }

    Batch struct {
        MaxEvents       int           // default 256; ephemeral 64
        MaxBytes        int           // default 256 KiB; ephemeral 64 KiB
        MaxTimespan     time.Duration // default 5s; ephemeral 1s
        FlushInterval   time.Duration // default 1s; ephemeral 200ms
        Compression     string        // "zstd" (default) | "gzip" | "none"
        ZstdLevel       int           // default 3
    }

    WAL struct {
        SegmentSize    int64         // default 16 MiB; ephemeral 4 MiB
        MaxTotalBytes  int64         // default 1 GiB; ephemeral 64 MiB
        SyncMode       string        // "immediate" (default) | "deferred"
        SyncInterval   time.Duration // for deferred; default 100ms
    }

    Heartbeat struct {
        Interval        time.Duration // default 30s; ephemeral 10s
        ReconnectAfterMisses int      // default 2
    }

    Backoff struct {
        Base time.Duration // default 500ms
        Max  time.Duration // default 30s
    }

    Filter wtpfilter.Filter   // see "Filter generalization" below — currently
                              // OTEL has its own private filter type; we
                              // generalize it into a shared package as part
                              // of this work.
}
```

### applyDefaults() and validate()

`applyDefaults()` checks `EphemeralMode` and overrides any zero-valued fields with the ephemeral profile *before* falling back to the standard defaults. `validate()` enforces:

- Exactly one of `Auth.TokenFile`, `Auth.TokenEnv`, `Auth.ClientCertAuth` is set (strict mutual exclusion; configuration ambiguity is a fail-closed error).
- `Endpoint` parses as `host:port`.
- TLS files exist and are readable (early failure beats first-batch failure).
- `StateDir` is writeable.
- `Batch.MaxBytes >= 4 KiB` (avoid pathological tiny batches).
- `WAL.SegmentSize <= WAL.MaxTotalBytes / 2` (need room for at least 2 segments).
- `len(HMACSecret) >= audit.MinKeyLength` (currently 32 bytes for HMAC-SHA256). Mirrors the audit package's precondition so a short key is rejected at watchtower-load time with a watchtower-shaped error rather than surfacing as a generic `audit.NewSinkChain` error mid-construction.

**Watchtower validation vs audit as source of truth.** Watchtower's `Options.validate()` mirrors the audit package's preconditions (currently `MinKeyLength` and the HMAC algorithm whitelist `hmac-sha256` / `hmac-sha512`) so that misconfiguration is caught at watchtower-load time with watchtower-shaped errors, rather than surfacing as a generic audit error mid-construction. If audit's preconditions tighten in the future, watchtower's `validate()` must be updated to match — `audit` remains the canonical source of truth for chain invariants.

### Constructor

```go
func New(ctx context.Context, cfg Config, opts ...Option) (*Store, error)

type Option func(*options)

func WithMapper(m compact.Mapper) Option        // injected from Phase 1
func WithDialer(d transport.Dialer) Option      // injected by tests
func WithMetrics(c *metrics.Collector) Option   // injected by host (internal/metrics.Collector)
func WithLogger(l *slog.Logger) Option          // injected by host
func WithChainKey(key []byte, fp string) Option // injected by composite (Phase 0)
```

The host (the agentsh daemon) is responsible for building the `Store` with the right options. In tests we pass `WithDialer(testserver.NewDialer(...))` and skip TLS entirely.

**Constructor lifecycle — chain init is a precheck.** `New` constructs the `audit.SinkChain` (via `audit.NewSinkChain`) **before** opening the WAL. Chain construction is pure (no IO side effects), so a failure here returns immediately without leaving a WAL file open or a lock file held. This ordering is mandatory: opening the WAL first and then failing chain construction would leak WAL state on the way out. If a future change reorders so the WAL opens first, that branch MUST `Close()` the WAL on chain-init failure before returning the error.

### Wiring into existing composite

`internal/store/composite/composite.go` already has a `New(primary, output, others...)` constructor. The WTP store is added as another `EventStore` in `others`. The Phase 0 refactor adds a `audit.SequenceAllocator` to composite and stamps `ev.Chain` before fanout (separate doc); this client consumes `ev.Chain` directly.

### Test-only seam: `Options.SinkChainOverrideForTests`

The `watchtower` package exposes `SinkChainOverrideForTests` on its `Options` struct so AppendEvent's drop-path tests can substitute a `chain.SinkChainAPI` double that returns `chain.ErrInvalidUTF8` on every Compute. This is a **permanent** test seam, not transient scaffolding: removing it would either eliminate the failing-sink test (a regression in test coverage) or force the test to construct a parallel `*audit.SinkChain` with a hidden hook (more brittle, more code to maintain). The field type is the watchtower-local `chain.SinkChainAPI` interface — production code wires `audit.NewSinkChain(...)` and wraps the result with `chain.NewWatchtowerSink(...)` (the local adapter described below), and tests substitute any value that satisfies the interface.

**Production-validation enforcement.** `Options.validate()` rejects a non-nil `SinkChainOverrideForTests` outside test mode (gated by an `AllowSinkChainOverrideForTests bool` companion flag, mirroring the existing `AllowStubMapper` pattern). A test that wants the override sets both fields; production callers leave both at the zero value. This makes accidental misuse a startup-time error, not a silent behavior change. See Task 22's `validate()` for the exact rejection.

**API stability.** `Options.SinkChainOverrideForTests` (and its `AllowSinkChainOverrideForTests` companion) are explicitly **exempt** from normal API-stability expectations: they are test-only seams that may be renamed, refactored, or replaced without notice. The `validate()` rejection above prevents production callers from depending on them in the first place.

### Watchtower-local adapter: `chain.WatchtowerSink`

The `internal/store/watchtower/chain` package adds a thin adapter, `chain.WatchtowerSink`, that wraps `*audit.SinkChain` and satisfies `chain.SinkChainAPI`. The constructor is `chain.NewWatchtowerSink(inner *audit.SinkChain) *WatchtowerSink`. The adapter delegates `Compute` and `Commit` directly to the inner chain (the audit phase-0 contract is untouched) and adds one new accessor:

- `PeekPrevHash() string` — implemented as `state := inner.State(); return state.PrevHash` over `audit.SinkChainState`. This is a read-only test seam used in `append_test.go` to assert "chain prev_hash did not advance" after a drop. It does **not** belong on `audit.SinkChain` itself: the audit package's `State()` already returns the full `SinkChainState{Generation, PrevHash, Fatal}` triple, which is sufficient for production callers (composite, snapshot/restore). `PeekPrevHash` is a watchtower test-ergonomics convenience — narrowing `State()` down to the single field the drop tests need — implemented in the adapter. **This is the only added surface area** the watchtower introduces over `audit.SinkChain`; the `Compute`/`Commit` methods are pure pass-through.

### Prerequisite plumbing (in-scope for this work)

These three pieces of plumbing don't exist in the codebase today and must land alongside the WTP sink. Each is small but explicit so reviewers know it's not assumed:

1. **Filter generalization.** `internal/store/otel/otel.go` has a private `Filter` type. We move it into a shared package `internal/store/eventfilter/` (or similar; final name in the implementation plan), update OTEL to consume the shared type, and use it from WTP. Backwards-compatible YAML; no behavior change for OTEL.
2. **YAML config schema.** Add `WatchtowerConfig` under `internal/config/config.go` mirroring §6 above. Wire into the existing `AuditConfig` (or its peer) so the daemon constructs a WTP `Store` when `enabled: true`. Add `config_test.go` cases for default expansion (ephemeral overrides, mutual-exclusion validation).
3. **Metrics wiring.** `internal/metrics.Collector` exposes a counter/gauge registry. Add the `wtp_*` series listed under "Metrics" above as fields on a `metrics.Collector` extension or a sibling collector. The host (the daemon `cmd/agentsh`) registers them at startup and passes the collector via `WithMetrics`.

None of these three blocks the WTP package's own unit tests — they only matter at host-wiring time. Each shows up as a discrete milestone in §"Implementation Phases" below.

## Testing Strategy

### Five-layer pyramid

| Layer | What | Tooling | Example |
|---|---|---|---|
| Unit (pure) | `chain/canonical.go`, `chain/context.go`, `compact/encoder.go`, `transport/batcher.go`, `wal/framing.go` CRC paths | Go test + golden files | `TestCanonicalEncoder_Goldens` |
| Unit (I/O) | `wal.WAL` lifecycle on a real FS (tempdir) | Go test + `t.TempDir()` | `TestWAL_RolloverAndReplay` |
| Unit (state machine) | `transport.state` transitions | Mock `Conn` + table tests | `TestState_GoawayTriggersReconnect` |
| Component | Whole `Store` against `testserver` | bufconn | `TestStore_DropsMidBatchTriggersReplay` |
| Integration | Long-running flow: append, kill server, restart, expect ack catch-up | bufconn with restartable scenario | `TestStore_ServerRestart_AcksCatchUp` |

### High-risk integrity tests (first-class, gated before component layer)

These four cases are explicit milestones — they cover the failure modes most likely to corrupt the audit chain or leak metadata, and they must pass before the component-layer tests run.

| Test | Asserts | Where it lives |
|---|---|---|
| `TestStore_WALCleanFailure_NoChainAdvance` | A clean `wal.Append` failure (e.g., overflow detected pre-I/O) returns the error to the caller AND `audit.SinkChain.State().PrevHash` is unchanged. The next successful append uses the same `prev_hash` as before the failure. | `internal/store/watchtower/store_failure_test.go` |
| `TestStore_WALAmbiguousFailure_LatchesFatal` | An ambiguous `wal.Append` failure (injected via a fake file with a flaky `Write`) calls `audit.SinkChain.Fatal`. Subsequent `AppendEvent` calls return `audit.ErrFatalIntegrity` without writing to the WAL. The composite `onAppendError` hook receives a `FatalIntegrityError`. | `internal/store/watchtower/store_failure_test.go` |
| `TestEvent_ChainFieldNotMarshaled` | After composite stamps `ev.Chain`, marshaling `ev` to JSON via the JSONL store, the OTEL converter, and `encoding/json.Marshal` directly, the output contains no `chain`, `Chain`, `_integrity_*`, or `sequence` keys at the top level. Catches accidental tag changes on `pkg/types.Event`. | `pkg/types/events_chain_test.go` (Phase 0) + `internal/store/jsonl/jsonl_chain_test.go` |
| `TestWAL_GenerationBoundaryOrdering` | Appending events `(seq=0..N, gen=7)` then `(seq=0..M, gen=8)` produces exactly two segments: one with header.generation=7 containing only gen-7 records, one with header.generation=8 containing only gen-8 records. The `AppendResult.GenerationRolled` flag is set on the boundary record. | `internal/store/watchtower/wal/wal_generation_test.go` |

These four tests are required before any of the five-layer pyramid component/integration tests are accepted. They directly verify the contract changes from roborev findings #2, #3, and #4.

### `AppendEvent` context semantics

`AppendEvent` does NOT honor `ctx.Done()` for the WAL write step. The audit-durability invariant is that any event the caller passed to `AppendEvent` either lands in the WAL or returns an error — a partially-cancelled write would corrupt this invariant. Specifically:

- `compact.Encode`, `chain.EncodeCanonical`, `audit.SinkChain.Compute`: pure CPU, no ctx check.
- `wal.Append`: ignores ctx cancellation. The WAL write completes (or fails cleanly/ambiguously) before `AppendEvent` returns.
- `transport.Notify()`: non-blocking channel send; no ctx involvement.

The transport goroutine's outbound gRPC sends DO honor ctx cancellation — they're invisible to the `AppendEvent` caller and respect the connection's context for clean shutdown.

This is documented in the package doc-comment on `Store.AppendEvent` so callers don't expect cancellation semantics.

### `QueryEvents`

WTP is a fire-and-forget transport sink. `QueryEvents` returns `(nil, ErrNotSupported)` matching the pattern in `internal/store/otel/otel.go:138` (`"otel store does not support queries"`). The composite store routes queries to its `primary` (SQLite) and never to `others`, so this never fires in practice.

### `testserver` capabilities

```go
ts := testserver.New(t,
    testserver.AckImmediately(),
    testserver.Drop(after: 3, then: testserver.Resume()),
    testserver.Goaway(after: 5*time.Second, code: "DRAINING"),
    testserver.AckDelay(500 * time.Millisecond),
    testserver.StaleWatermark(returnSeq: 100),
)
defer ts.Close()

dialer := ts.NewDialer()
store, _ := watchtower.New(ctx, cfg, watchtower.WithDialer(dialer))

// drive the store
for i := 0; i < 10; i++ { store.AppendEvent(ctx, ev) }

// assertions
ts.WaitForBatch(t, 5 * time.Second)
ts.AssertSequenceRange(t, 1, 10)
ts.AssertReplayObserved(t)
```

The testserver also exposes a `Recorded()` accessor returning all batches it has received in order, so tests can assert against the full conversation, not just final state.

### Golden vectors — published in two locations

1. `internal/store/watchtower/chain/testdata/vectors.json` — IntegrityRecord canonical-encoding vectors (added in Task 7). These will also be published in `docs/spec/wtp/conformance/` for cross-implementation use.
2. `proto/canyonroad/wtp/v1/testdata/*.bin` — wire-format goldens (CompactEvent, EventBatch, SessionInit). Generated by a small `go run ./internal/store/watchtower/cmd/gen-wire-goldens` tool that we ship in-tree but do not run in CI; CI only verifies that the existing goldens parse + round-trip cleanly.

A test failure on a golden is a load-bearing alarm: the canonical encoding has changed and is now incompatible with every other implementation. The golden test message says exactly this.

### Cross-platform considerations (per AGENTS.md)

- Use `filepath.Join` everywhere. No string concatenation of paths.
- WAL `*.INPROGRESS` rename uses `os.Rename`, which on Windows requires the target not to exist (handled by always renaming a new file into a fresh sealed name).
- `fsync(parent)` calls go through the existing `internal/audit/fsync_dir_{unix,windows}.go` helpers (Windows is a no-op there, which the existing audit chain already accepts).
- bufconn-based tests are cross-platform with no extra effort.
- We do *not* exec anything. No /tmp paths anywhere.

## Deferrals and Open Questions

| Item | Status | Where it shows up in the code |
|---|---|---|
| Phase 0: composite shared sequence | Prerequisite | `docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md` is the contract doc; `watchtower.Store.AppendEvent` reads the typed `ev.Chain *types.ChainState` field. |
| Phase 1: OCSF mapper | Prerequisite (hard) | `compact.Mapper` interface; production implementation lives in a different package. The WTP client's `compact/encoder.go` ships a stub `defaultMapper` for unit tests only — production deployment requires `WithMapper(...)` from Phase 1, enforced by `validate()`. |
| Open Q: live key rotation pause/resume | Deferred | Comment in `transport/state.go` at the spot where a `KeyRotation` server message would be handled. The WTP client tolerates session-level `SessionUpdate` (the rotation envelope), so the rotation can be performed by issuing a `SessionUpdate` with a new key fingerprint — the only piece deferred is the *automation* of pausing the chain across the swap. |
| Open Q: OCSF version negotiation | Deferred | Comment in `transport/transport.go` `SessionInit` builder. Today we hard-code `ocsf_version = "1.8.0"` matching the spec. |
| Open Q: sub-second timestamp granularity | Deferred | Comment in `compact/encoder.go` next to the timestamp field. We use uint64 nanoseconds today (already sufficient for nanosecond precision); if the spec lands on a coarser truncation, we'll honour it there. |
| Spec ambiguity #1: loss-only batch sequence range | Flagged for v0.4.10 | Code TODO in `transport/batcher.go` near the `TransportLoss` flush path. We currently emit `from_seq..to_seq` as the missing range and leave the batch's own `sequence_range` covering only the marker record. |
| Spec ambiguity #2: definition of `total_chained` | Flagged for v0.4.10 | Code TODO in `chain/chain.go` next to the SessionInit-building helper. We currently treat it as the count of records the *sink* has chained since installation. |

These deferrals do not block this design. Each is a localized future PR.

## Migration & Rollout

- The sink is **opt-in** via the existing YAML config under `internal/config` (e.g., `audit.watchtower.enabled: true`). It defaults to disabled. The exact YAML schema is added to `internal/config/config.go` as part of this work; see "Prerequisite plumbing" above.
- When disabled, no goroutines start, no disk space is used, and `composite.others` does not include it.
- When enabled but Phase 0 has not landed, `validate()` fails fast with a clear message: `"watchtower sink requires composite shared-sequence support (Phase 0); enable when available"`.
- When enabled but the OCSF mapper is not injected, `validate()` ALSO fails fast: `"watchtower sink requires OCSF mapper (Phase 1); enable when available"`. The stub mapper exists strictly for compile-time and unit-test purposes — production deployment requires Phase 1. (This tightens an earlier inconsistency: the stub is no longer a fallback, it's a test fixture.)

**Mapper nil-handling contract.** `Store.New` must reject both untyped `nil` mappers and typed-nil pointer-to-Mapper implementations. Untyped nil is detected with `m == nil`. For typed-nil, detection is scoped to pointer form via:

```go
rv := reflect.ValueOf(m)
if rv.Kind() == reflect.Ptr && rv.IsNil() {
    return errors.New("mapper is required (typed-nil pointer)")
}
```

Other nilable kinds (`map`, `slice`, `chan`, `func`) implementing `Mapper` are pathological in practice — production mappers are struct pointers (e.g. `*OcsfMapper`) — so the contract intentionally scopes typed-nil rejection to the `*ConcreteMapper` form. If a future implementation deviates from struct-pointer form, the contract should be revisited at that point.

The stub-rejection branch (`compact.IsStubMapper`) runs after the nil branches and matches both value and pointer forms (`StubMapper{}`, `*StubMapper`); the typed-nil `*StubMapper` case is redundantly covered by both branches but the nil branch wins because it produces the more actionable error.

**`compact.Encode` — canonical CompactEvent construction.** All **production sink runtime** construction of `wtpv1.CompactEvent` MUST go through `compact.Encode`. Build-time tooling — golden fixture generators (`internal/store/watchtower/cmd/gen-wire-goldens/fixtures/`), test helpers, intentionally-malformed event generators — MAY construct `CompactEvent` directly when divergence from the canonical encoder is the explicit purpose. The rule exists because the chain step (`chain.Compute`) hashes a fixed canonical projection of the event, so a diverging construction path on the sink runtime path silently breaks integrity verification; tooling that intentionally produces non-canonical messages is exempt.

`Encode` owns these invariants:
- **Mapper must be valid.** `m` must be non-nil and not a typed-nil pointer. Returns `ErrInvalidMapper` otherwise.
- **Chain stamping is mandatory.** `ev.Chain` must be non-nil; the composite store stamps it before fanning out. Returns `ErrMissingChain` otherwise.
- **Timestamp must be valid.** `ev.Timestamp` must be non-zero and ≥ Unix epoch. Pre-epoch instants silently wrap when cast to `uint64`, masking caller bugs. Returns `ErrInvalidTimestamp`.
- **Integrity is left nil.** The chain step populates `Integrity` after computing the entry hash.

`Encode` rejects untyped-nil and typed-nil-pointer mappers via `ErrInvalidMapper`. `Store.New` (Phase 10) performs the same rejection at construction time. This is defense in depth, not redundancy: the runtime nil check is a cheap branch on the hot path, and it makes `Encode` independently safe to call regardless of whether the caller routes through `Store.New`.

Error sentinels are exported so callers can classify with `errors.Is`: `ErrInvalidMapper`, `ErrMissingChain`, `ErrInvalidTimestamp`. Mapper failures are wrapped with `fmt.Errorf("compact mapper: %w", err)` so `errors.Unwrap` returns the underlying mapper error.

Encode failures in the WTP sink's `AppendEvent` path are classified via `errors.Is`. Three classes — `ErrInvalidMapper`, `ErrInvalidTimestamp`, and the default mapper-failure branch — are dropped silently (chain does NOT advance) and counted via per-class counters (`wtp_dropped_invalid_mapper_total`, `wtp_dropped_invalid_timestamp_total`, `wtp_dropped_mapper_failure_total`). The fourth class — `ErrMissingChain` — is NOT dropped: it is propagated to the caller as `fmt.Errorf("watchtower: %w", err)` because a missing chain indicates a composite-store regression that operators must surface loudly. See Task 22a for the metric definitions and Task 23 for the sink-side `errors.Is` wiring.

The three drop classes (`ErrInvalidMapper`, `ErrInvalidTimestamp`, mapper-failure default branch) follow the same boundary contract as the existing per-record drops `wtp_dropped_invalid_utf8_total` (see "per-record encodes only" paragraph above) and `wtp_dropped_sequence_overflow_total` (see sequence-width contract paragraph above):

- **WAL**: drops happen before WAL admission. The WAL is not touched — no segment write, no INPROGRESS lifecycle event, no replay-side accounting.
- **Chain**: `prev_hash` does not advance; the SinkChain is not committed. The chain remains at the same state it occupied before the dropped record.
- **Sequence**: the sequence allocated by the composite store IS consumed (the composite stamps `ev.Chain` before fanning out to each sink). A gap therefore appears in the WTP-observed chain relative to other sinks (JSONL, OTEL) which committed the same allocated sequence. Operators reading WTP output must tolerate gaps; whether to surface those gaps as `TransportLoss` markers (and with what reason code) is deferred to Phase 8 alongside the existing `invalid_utf8` gap-handling decision. The `ErrMissingChain` propagation path does NOT consume a sequence — it returns to the caller before any allocator-coupled state advances — so it cannot create a sequence gap.
- **Log**: structured WARN log emitted with fields `{session_id, sequence, generation, err}`. The `err` value is the wrapped error returned by `Encode`; its message identifies the specific failure (e.g. `compact: invalid mapper`, `compact mapper: <underlying>`).
- **AppendEvent return**: returns `nil` for the three drop classes (sink-internal drop, not propagated to the caller — matches the existing `invalid_utf8` and `sequence_overflow` patterns above). The metric and the structured log are the only signals operators see.

The `default` branch of the `errors.Is` switch — i.e., `Encode` returned an error that is not one of the four sentinels — corresponds to a mapper-side failure wrapped by `Encode` as `compact mapper: %w`. That branch increments `wtp_dropped_mapper_failure_total`. There is no fifth sentinel for this case because the underlying error originates inside the mapper implementation; operators classify it from the wrapped `err` text in the structured log.

The `ErrMissingChain` branch is NOT a drop. `AppendEvent` returns `fmt.Errorf("watchtower: %w", err)` AND emits one ERROR-severity structured log per occurrence with fields `{event_id, session_id, event_type, err}`. None of those fields are peer-supplied — `ev.Chain == nil` is composite-store internal state, all four logged values come from sink-side bookkeeping or fixed sentinel strings, not protocol input — so the log is exempt from the invalid-frame sanitization rule that bans peer-supplied bytes. There is NO per-sink counter for this branch (a missing chain is a developer-visible composite-store regression, not a runtime drop class — operators surface it at the call site rather than in a metric series). The composite store MUST stamp `ev.Chain` before fanout — failing to do so is a programming error, and propagating it lets the caller surface the regression at the call site rather than burying it. There is no rate-limit, sampling, or first-N suppression on this log: every occurrence is a separate composite-store invariant violation worth surfacing. `generation` is intentionally NOT included because composite-store generation is only available via `ev.Chain.Generation`, which is nil on this branch by definition. If operators need to correlate which generation a missing-chain event corresponds to, they should cross-reference `session_id` and `event_id` against the composite-store's session log.

**Caller contract for propagated `compact.ErrMissingChain`.** This error is a developer-facing diagnostic, not an operator-facing throughput failure — composite did not stamp `ev.Chain`, which is a programming/integration bug, not a runtime/transport problem. The watchtower sink and its callers MUST therefore treat the propagated error as follows:

(a) The watchtower sink MUST log the error at ERROR severity once per occurrence (no rate-limit or de-duplication suppression for the first N — every instance is a separate composite-store invariant violation worth surfacing). The log carries fields `{event_id, session_id, event_type, err}` and ONLY those fields, all sourced from `types.Event` itself or a fixed sentinel string — none are peer-supplied:

  - `event_id` is `ev.ID` (logged verbatim, including the empty string when `ev.ID` is empty — do not invent a substitute). The Go-side field on `types.Event` is `ID`; the log key is `event_id` for operator readability.
  - `session_id` is `ev.SessionID` — internal-only, useful for correlating which session's composite failed to stamp.
  - `event_type` is `ev.Type` — internal-only, helps operators see what category of event slipped through without a chain stamp.
  - `err` is `compact.ErrMissingChain.Error()` — the sentinel error string itself, no peer-supplied content; this is a fixed-format internal error.

  `generation` is intentionally NOT included because composite-store generation is only available via `ev.Chain.Generation`, which is nil on this branch by definition. If operators need to correlate which generation a missing-chain event corresponds to, they should cross-reference `session_id` and `event_id` against the composite-store's session log. The log MUST NOT include `payload`, `mapper_err`, the raw event body, or any other peer-derived content. The sanitization rule that bans peer-supplied bytes from invalid-frame logs does not apply here only because every field is internal-only; if `types.Event.ID` or `SessionID` were ever populated by the peer, the field set would have to shrink accordingly.
(b) The sink MUST NOT auto-disable, self-shutdown, or latch fatal on this error. Disabling the sink is an operator decision, not a per-event response. The sink continues to accept subsequent `AppendEvent` calls; if the composite stamps `ev.Chain` correctly on the next event, processing resumes normally.
(c) The sink MAY return the error up the audit pipeline so the composite store has the option to crash-fail in dev/test builds (where invariant violations should be loud) while production builds log and continue. The decision is the composite's, not the WTP sink's.
(d) The error is NOT retryable. Re-encoding the same event with the same `ev.Chain == nil` will produce the same `compact.ErrMissingChain`. Callers MUST NOT loop, back off, or schedule the event for re-delivery — the only remediation is fixing the composite's stamping logic and re-running with a corrected event.

The contrast with the silent-drop classes is intentional: `ErrInvalidMapper`, `ErrInvalidTimestamp`, and the mapper-failure default branch are operator-visible runtime conditions (event source corruption, mapper bugs) where the sink absorbs the failure and counts it; `ErrMissingChain` is a developer-visible integration condition where the sink refuses to absorb the failure because doing so would mask the upstream bug.

**Mapper error sanitization.** Mapper implementations MUST NOT include event payload bytes, raw payload values, or secret material in error strings. The full error string is emitted in structured WARN logs verbatim and (for `ErrMissingChain`) returned through `AppendEvent`'s wrapped error to the caller. Mappers should return descriptive but non-sensitive errors (e.g., `unsupported event type: <type>` rather than `failed to map: <full payload>`). The default `StubMapper` does not return errors. Production mappers must follow this contract; callers cannot sanitize after the fact. Mapper authors should add an explicit code-review checklist item for error-string content.

- Operators can verify the sink end-to-end without a live Watchtower by pointing `Endpoint` at the testserver binary that ships in `cmd/wtp-testserver/` (a thin wrapper around `internal/store/watchtower/testserver`). This is also how we recommend running it in development.

## Implementation Phases

This section enumerates ordered milestones with one-line entry/exit criteria, scaffolding the `writing-plans` follow-up. Each phase is independently reviewable and produces a green CI build.

| # | Phase | Entry | Exit |
|---|---|---|---|
| 1 | **Phase 0 contract land** | Phase 0 contract doc approved. | `audit.SequenceAllocator` and `audit.SinkChain` exist with full unit tests. `audit.IntegrityChain.Wrap` preserved (existing tests green). `pkg/types.Event.Chain *ChainState` added with `json:"-"` tag. `TestEvent_ChainFieldNotMarshaled` passes. |
| 2 | **Composite refactor** | Phase 1 done. | `composite.Store` constructs a `SequenceAllocator`, stamps `ev.Chain` before fanout, exposes `NextGeneration()`. Cross-sink `(seq, gen)` convergence test passes. Single-sink installations behave identically (no observable change). |
| 3 | **Filter + config + metrics plumbing** | Phase 2 done. | `internal/store/eventfilter/` package generalized from OTEL's private filter (OTEL still passes its own tests). `WatchtowerConfig` schema added to `internal/config/config.go` with default-expansion and validation tests. `wtp_*` metrics registered with `internal/metrics.Collector`. |
| 4a-i | **Proto scaffolding** | Phase 3 done. | `proto/canyonroad/wtp/v1/wtp.proto` defined matching spec §7. Generated `wtp.pb.go` and `wtp_grpc.pb.go` committed. Smoke round-trip test passes. |
| 4a-ii | **Schema stability + validators** | Phase 4a-i done. | Schema-stability policy recorded in spec (pre-1.0 unstable). Receiver-side validators in `proto/canyonroad/wtp/v1/validate.go` reject unset `EventBatch.body`, body/compression mismatch, COMPRESSION_UNSPECIFIED, HASH_ALGORITHM_UNSPECIFIED, and over-cap compressed payloads. Negative tests cover every rejection path. |
| 4b | **Wire goldens** | Phase 4a done. | `proto/canyonroad/wtp/v1/testdata/*.bin` goldens generated by in-tree `cmd/gen-wire-goldens` and verified to round-trip in CI (`TestWireGoldens_RoundTrip`). |
| 5 | **Chain helpers** | Phase 4 done. | `internal/store/watchtower/chain/` package: `EncodeCanonical`, `ComputeContextDigest`, `ComputeEventHash`. `chain/testdata/vectors.json` goldens published (cross-implementation conformance suite). All pure unit tests green. |
| 6 | **Compact encoder + mapper interface** | Phase 5 done. | `compact.Mapper` interface defined. Stub mapper for unit tests only. Per-OCSF-class projection helpers tested against `compact/payload/testdata/*.json`. |
| 7 | **WAL package** | Phase 6 done. | `internal/store/watchtower/wal/`: segment header, framing, CRC32C, atomic seal, INPROGRESS lifecycle, meta.json, Reader API. **Required tests**: `TestWAL_RolloverAndReplay`, `TestWAL_GenerationBoundaryOrdering`, `TestWAL_CRCFailureEmitsCoarseLossRange`, `TestWAL_OverflowEmitsLossMarker`. |
| 8 | **Transport state machine** | Phase 7 done. | `internal/store/watchtower/transport/`: Conn interface, Dialer pattern, four-state machine, Batcher with all six invariants, Replayer, Heartbeat. Mock-Conn-driven table tests cover every (state × event) cell. |
| 9 | **In-tree testserver** | Phase 8 done. | `internal/store/watchtower/testserver/`: bufconn server, scenario hooks (Drop, Goaway, AckDelay, StaleWatermark), `WaitForBatch` / `AssertSequenceRange` / `AssertReplayObserved` helpers. Self-tested. |
| 10 | **Store integration + transactional Append** | Phase 9 done. | `internal/store/watchtower/store.go` glues compact + chain + wal + transport. Implements `store.EventStore`. **Required tests**: `TestStore_WALCleanFailure_NoChainAdvance`, `TestStore_WALAmbiguousFailure_LatchesFatal`. |
| 11 | **Component + integration tests** | Phase 10 done. | The five-layer pyramid's component and integration rows pass: `TestStore_DropsMidBatchTriggersReplay`, `TestStore_ServerRestart_AcksCatchUp`, plus the testserver-driven scenario suite. |
| 12 | **Daemon wiring** | Phase 11 done. | `cmd/agentsh` constructs a WTP `Store` when `audit.watchtower.enabled: true`, passes `WithMapper`, `WithMetrics`, `WithLogger`, `WithChainKey`. Manual end-to-end smoke test against `cmd/wtp-testserver` documented. |

Phases 5/6/7/8 can be parallelized across contributors after Phase 4b (the proto definitions are the only shared dependency). Phases 1/2/3 are strict sequential prerequisites.

## Risks

| Risk | Mitigation |
|---|---|
| Canonical encoding drift breaks every other implementation. | Golden vectors are mandatory for every change to `chain/canonical.go`. Vectors are also published as the conformance suite. |
| WAL grows unbounded if server is offline forever. | `max_total_bytes` is hard-capped; oldest unacked drops with `TransportLoss`. Marker is fsynced before the drop is reported as complete. |
| State-machine bugs deadlock the transport goroutine. | All select branches have a `ctx.Done()` arm. Heartbeat miss timer is independent of inbound traffic. State machine has full table-test coverage of every (state × event) cell. |
| Fsync cost on the hot path regresses end-to-end latency (cf. `2026-04-13-deferred-sync`). | Default WAL sync mode is `immediate`, but we expose `deferred` with the same 100ms tick used for the existing JSONL/sidecar path. Operators with the same constraints can opt in. |
| gRPC connection establishment blocks startup. | Dial happens in a background goroutine; `New` returns immediately. The first `AppendEvent` does not wait for connection — the WAL absorbs records until the transport catches up. |
| Cross-platform regressions in WAL atomic-rename or dir-fsync. | The same helpers as the existing JSONL/integrity sidecar; they are already in production on all three OSes. |

## Out-of-Scope (Explicit)

- Server implementation (Watchtower).
- Compressed-batch encoding/decoding. The MVP client always emits `Compression_COMPRESSION_NONE`; the proto enum reserves space for `ZSTD`/`GZIP` and the spec records the size caps, but no compression code path is implemented in this cycle.
- Phase 0 composite refactor (separate doc).
- Phase 1 OCSF mapper (separate work).
- Live key rotation automation.
- mTLS automation, SPIFFE, cert rotation.
- HTTP/2 fallback.
- Multi-tenant routing.
- Querying acked events back from the server (one-way only).
- Backfill from existing JSONL/SQLite stores into WTP.
