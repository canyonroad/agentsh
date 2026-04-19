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
  │ 1. validate: ev.Chain != nil, else ErrMissingChainState
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
                               │ Dial + SessionInit (wal_high_watermark_seq from disk)
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
    FormatVersion  uint32   // = 2 (spec §6.4)
    Sequence       uint64   // shared, from ev.Chain.Sequence
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
// session/segment.
func ComputeContextDigest(ctx SessionContext) string

// ComputeEventHash returns sha256(canonical_compact_event_bytes). Used to
// populate IntegrityRecord.EventHash before passing the canonical-encoded
// IntegrityRecord to audit.SinkChain.Compute.
func ComputeEventHash(canonicalEvent []byte) string
```

The actual chain mutations (Compute/Commit/Fatal/State/Restore) all live on `audit.SinkChain`; we do not re-implement them. The transactional pattern from §"Steady state" calls into `audit.SinkChain` directly.

### Canonical encoding — non-negotiable byte parity

Spec §6.4 mandates a canonical JSON encoding with sorted keys, no insignificant whitespace, ASCII-escaped non-ASCII, and decimal numbers (no scientific notation). `encoding/json` does *not* guarantee any of these invariants across versions, and a single byte difference breaks every other implementation's verification.

We hand-roll the encoder in `chain/canonical.go`:

```go
func EncodeCanonical(rec IntegrityRecord) ([]byte, error)
```

The encoder is exhaustively tested against `chain/testdata/vectors.json`, which is also published as the cross-implementation conformance suite for the spec. Vectors include UTF-8 edge cases (escaped non-ASCII, surrogate pairs), large numbers near uint64 max, and empty strings.

### Context digest (§6.4.6)

```go
func ComputeContextDigest(ctx SessionContext) string
```

Computed once on `SessionInit`, again on `SessionUpdate`, and again on chain rotation. Bound into every event hash in that segment. Implemented as SHA-256 of the canonical encoding of the SessionContext fields the spec lists.

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
  "format_version": 1,
  "ack_high_watermark_seq": 12345,
  "ack_high_watermark_gen": 7,
  "session_id": "01J...ulid",
  "key_fingerprint": "sha256:abcd…"
}
```

Atomically written via `os.WriteFile` on a temp + `os.Rename` + `fsync(parent)` using the existing `internal/audit/fsync_dir_unix.go` and `fsync_dir_windows.go` helpers. The session ID is included so a stale meta.json from a previous installation cannot be silently consumed.

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

Replay batches obey the same invariants as live batches; the only difference is the source of records. The server may legitimately return a stale (lower) ack watermark during gradual rollout or partition recovery; the replayer trusts the lower of `(server_returned_hw, local_ack_hw)` so we re-send unacked records rather than dropping the gap. A higher-than-local server watermark is anomalous and is logged + ignored — we replay from `local_ack_hw + 1`.

### Heartbeat

A `heartbeatTimer` ticks at `heartbeat_interval` (default 30s; 10s in ephemeral mode). On tick: send `Heartbeat`. If two consecutive heartbeats elapse with no inbound message (ack or ServerHeartbeat), set `state = stateConnecting` (reconnect with backoff).

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
- `wtp_session_state` (gauge: 0=connecting, 1=replaying, 2=live, 3=shutdown)
- `wtp_wal_segments` (gauge)
- `wtp_wal_bytes` (gauge)
- `wtp_ack_high_watermark` (gauge)
- `wtp_dropped_missing_chain_total` (counter; increments when `ev.Chain == nil`)
- `wtp_wal_corruption_total` (counter; CRC corruption events during WAL replay)
- `wtp_send_latency_seconds` (histogram, per batch)

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

### Wiring into existing composite

`internal/store/composite/composite.go` already has a `New(primary, output, others...)` constructor. The WTP store is added as another `EventStore` in `others`. The Phase 0 refactor adds a `audit.SequenceAllocator` to composite and stamps `ev.Chain` before fanout (separate doc); this client consumes `ev.Chain` directly.

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

1. `internal/store/watchtower/chain/testdata/vectors.json` — IntegrityRecord canonical-encoding vectors. These are also published in `docs/spec/wtp/conformance/` for cross-implementation use.
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
- Operators can verify the sink end-to-end without a live Watchtower by pointing `Endpoint` at the testserver binary that ships in `cmd/wtp-testserver/` (a thin wrapper around `internal/store/watchtower/testserver`). This is also how we recommend running it in development.

## Implementation Phases

This section enumerates ordered milestones with one-line entry/exit criteria, scaffolding the `writing-plans` follow-up. Each phase is independently reviewable and produces a green CI build.

| # | Phase | Entry | Exit |
|---|---|---|---|
| 1 | **Phase 0 contract land** | Phase 0 contract doc approved. | `audit.SequenceAllocator` and `audit.SinkChain` exist with full unit tests. `audit.IntegrityChain.Wrap` preserved (existing tests green). `pkg/types.Event.Chain *ChainState` added with `json:"-"` tag. `TestEvent_ChainFieldNotMarshaled` passes. |
| 2 | **Composite refactor** | Phase 1 done. | `composite.Store` constructs a `SequenceAllocator`, stamps `ev.Chain` before fanout, exposes `NextGeneration()`. Cross-sink `(seq, gen)` convergence test passes. Single-sink installations behave identically (no observable change). |
| 3 | **Filter + config + metrics plumbing** | Phase 2 done. | `internal/store/eventfilter/` package generalized from OTEL's private filter (OTEL still passes its own tests). `WatchtowerConfig` schema added to `internal/config/config.go` with default-expansion and validation tests. `wtp_*` metrics registered with `internal/metrics.Collector`. |
| 4 | **Proto + wire goldens** | Phase 3 done. | `proto/canyonroad/wtp/v1/wtp.proto` defined matching spec §7. Generated code committed. `proto/canyonroad/wtp/v1/testdata/*.bin` goldens generated by in-tree `cmd/gen-wire-goldens` and verified to round-trip in CI. |
| 5 | **Chain helpers** | Phase 4 done. | `internal/store/watchtower/chain/` package: `EncodeCanonical`, `ComputeContextDigest`, `ComputeEventHash`. `chain/testdata/vectors.json` goldens published (cross-implementation conformance suite). All pure unit tests green. |
| 6 | **Compact encoder + mapper interface** | Phase 5 done. | `compact.Mapper` interface defined. Stub mapper for unit tests only. Per-OCSF-class projection helpers tested against `compact/payload/testdata/*.json`. |
| 7 | **WAL package** | Phase 6 done. | `internal/store/watchtower/wal/`: segment header, framing, CRC32C, atomic seal, INPROGRESS lifecycle, meta.json, Reader API. **Required tests**: `TestWAL_RolloverAndReplay`, `TestWAL_GenerationBoundaryOrdering`, `TestWAL_CRCFailureEmitsCoarseLossRange`, `TestWAL_OverflowEmitsLossMarker`. |
| 8 | **Transport state machine** | Phase 7 done. | `internal/store/watchtower/transport/`: Conn interface, Dialer pattern, four-state machine, Batcher with all six invariants, Replayer, Heartbeat. Mock-Conn-driven table tests cover every (state × event) cell. |
| 9 | **In-tree testserver** | Phase 8 done. | `internal/store/watchtower/testserver/`: bufconn server, scenario hooks (Drop, Goaway, AckDelay, StaleWatermark), `WaitForBatch` / `AssertSequenceRange` / `AssertReplayObserved` helpers. Self-tested. |
| 10 | **Store integration + transactional Append** | Phase 9 done. | `internal/store/watchtower/store.go` glues compact + chain + wal + transport. Implements `store.EventStore`. **Required tests**: `TestStore_WALCleanFailure_NoChainAdvance`, `TestStore_WALAmbiguousFailure_LatchesFatal`. |
| 11 | **Component + integration tests** | Phase 10 done. | The five-layer pyramid's component and integration rows pass: `TestStore_DropsMidBatchTriggersReplay`, `TestStore_ServerRestart_AcksCatchUp`, plus the testserver-driven scenario suite. |
| 12 | **Daemon wiring** | Phase 11 done. | `cmd/agentsh` constructs a WTP `Store` when `audit.watchtower.enabled: true`, passes `WithMapper`, `WithMetrics`, `WithLogger`, `WithChainKey`. Manual end-to-end smoke test against `cmd/wtp-testserver` documented. |

Phases 5/6/7/8 can be parallelized across contributors after Phase 4 (the proto definitions are the only shared dependency). Phases 1/2/3 are strict sequential prerequisites.

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
- Phase 0 composite refactor (separate doc).
- Phase 1 OCSF mapper (separate work).
- Live key rotation automation.
- mTLS automation, SPIFFE, cert rotation.
- HTTP/2 fallback.
- Multi-tenant routing.
- Querying acked events back from the server (one-way only).
- Backfill from existing JSONL/SQLite stores into WTP.
