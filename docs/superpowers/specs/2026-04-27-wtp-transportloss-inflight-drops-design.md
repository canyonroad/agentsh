# WTP TransportLoss for In-Flight Drops + Carrier Wiring

**Date:** 2026-04-27
**Status:** Design — pending implementation
**Scope:** Bundles two pieces that ship together because neither delivers operator value alone:
1. The **TransportLoss carrier**: wire the in-WAL `wal.LossRecord` → on-the-wire `wtpv1.TransportLoss` ClientMessage emission path. Replaces today's `ErrRecordLossEncountered` fail-closed (every overflow/CRC drop currently tears the session down).
2. **In-flight drop reasons**: surface the five existing in-flight drop classes (`mapper_failure`, `invalid_mapper`, `invalid_timestamp`, `invalid_utf8`, `sequence_overflow`) plus `ack_regression_after_gc` as TransportLoss markers, so operators can tell mapper bugs from network loss.

**Related:**
- `docs/superpowers/specs/2026-04-18-wtp-client-design.md` (Phase 8 deferral notes for invalid_utf8 / mapper-drop gap markers)
- `docs/superpowers/specs/2026-04-25-wtp-phase-1-ocsf-mapper-design.md` (§"Out of scope": TransportLoss for mapper-side drops deferred)
- `docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md` (sink chain semantics consumed by AppendEvent)

## Goals

1. Operators can distinguish in-flight client-side drops from network-side loss by querying the receiving Watchtower for `TransportLoss` records by `reason`. Today these manifest as silent counter increments client-side and unexplained sequence gaps server-side.
2. WAL overflow and CRC corruption stop fail-closing the session. They become observable gaps via TransportLoss instead of session restarts.
3. Existing chain integrity guarantees are unchanged: a `TransportLoss` for `(from, to, gen)` permanently removes those sequences from WTP's view; the receiving server treats the gap as authoritative.

## Non-goals

- A v2 WAL frame format with per-record sequence headers for exact CRC-loss ranges. Coarse ranges remain (`docs/superpowers/specs/2026-04-18-wtp-client-design.md:236`).
- Replay or recovery of dropped events from another sink (JSONL, OTEL). Once dropped, a record is permanently absent from WTP's chain.
- Server-side enum support for new reasons. Strict-enum servers will reject unknown values with a Goaway; operators opt in to extended reasons via config (see §"Migration").
- Compression of TransportLoss frames. They are tiny; even a thousand-frame burst is a few KB.
- Coalescing contiguous in-flight drops into a single TransportLoss range. Each drop emits one marker; the server can roll them up.

## Design choices

| Choice | Decision | Reason |
|---|---|---|
| Reason taxonomy | 1:1 with the existing `wtp_dropped_*` counters | Operators can correlate counter labels and TransportLoss reasons without translation. Six new reasons total. |
| Persistence path for in-flight drops | `wal.AppendLoss(LossRecord{FromSeq=ToSeq=ev.Chain.Sequence, ...})` | Uniform with existing overflow/CRC path. Drops survive a crash. The WAL append cost is negligible — drops are by definition rare. |
| Wire ack semantics | TransportLoss is acked symmetrically with EventBatch | Both consume an inflight slot; `BatchAck` advancing past either retires it and unblocks WAL GC. No new ack frame type needed. |
| Encoder signature | `[]*wtpv1.ClientMessage` (was: `*wtpv1.ClientMessage`) | A record list containing `[data, loss, data]` must produce three frames in order. The encoder is the natural splitter; the send loop becomes a `for _, msg := range msgs`. |
| Carrier default | On by default | Today's fail-closed behavior is itself a bug (overflow → session restart instead of graceful gap). No existing operator depends on it. |
| Extended reasons default | Off; gated by `output.wtp.emit_extended_loss_reasons` | New enum values are wire-additive but strict-enum servers reject unknown values per `TRANSPORT_LOSS_REASON_UNSPECIFIED` = "wire-incompatible — receivers MUST reject" convention. Operators flip the flag once their Watchtower supports the new reasons. |

## Wire format changes

`proto/canyonroad/wtp/v1/wtp.proto` — add six values to `TransportLossReason`:

```proto
enum TransportLossReason {
  TRANSPORT_LOSS_REASON_UNSPECIFIED       = 0;
  TRANSPORT_LOSS_REASON_OVERFLOW          = 1;
  TRANSPORT_LOSS_REASON_CRC_CORRUPTION    = 2;

  // NEW (2026-04-27 spec) — in-flight drops + ack regression.
  TRANSPORT_LOSS_REASON_MAPPER_FAILURE          = 3;  // compact.Encode wrapped a mapper-side error
  TRANSPORT_LOSS_REASON_INVALID_MAPPER          = 4;  // defense-in-depth: typed-nil mapper escaped validation
  TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP       = 5;  // ev.Timestamp zero or pre-epoch
  TRANSPORT_LOSS_REASON_INVALID_UTF8            = 6;  // chain.EncodeCanonical reported invalid UTF-8
  TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW       = 7;  // ev.Chain.Sequence > math.MaxInt64
  TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC = 8;  // computeReplayStart synthesized prefix gap
}
```

The existing `UNSPECIFIED = 0` ("wire-incompatible — receivers MUST reject") rule is unchanged. The carrier MUST never emit UNSPECIFIED; an unknown reason string at the carrier maps to `TRANSPORT_LOSS_REASON_UNSPECIFIED` only if a programming error occurred upstream, in which case the carrier logs an ERROR + increments `wtp_loss_unknown_reason_total` and **drops the marker** rather than send a wire-incompatible frame.

No other proto changes. `TransportLoss` already carries `from_sequence`, `to_sequence`, `generation`, and `reason`.

## In-WAL `LossRecord.Reason` strings

A new file `internal/store/watchtower/wal/loss_reasons.go` declares the canonical strings as exported consts:

```go
package wal

const (
    LossReasonOverflow            = "overflow"
    LossReasonCRCCorruption       = "crc_corruption"
    LossReasonAckRegressionAfterGC = "ack_regression_after_gc"

    // In-flight drops (this spec).
    LossReasonMapperFailure     = "mapper_failure"
    LossReasonInvalidMapper     = "invalid_mapper"
    LossReasonInvalidTimestamp  = "invalid_timestamp"
    LossReasonInvalidUTF8       = "invalid_utf8"
    LossReasonSequenceOverflow  = "sequence_overflow"
)
```

Existing producers (`wal.dropOldestLocked`, `wal.reader.go` CRC path, `transport.computeReplayStart`) switch to using these constants. The on-disk encoding is unchanged: `encodeLossPayload` already serializes the reason as raw UTF-8 with the framing layer's record length implicitly bounding it (`internal/store/watchtower/wal/wal.go:1493`).

## Reason → wire enum mapping

A new file `internal/store/watchtower/transport/loss_reason.go`:

```go
package transport

import (
    "github.com/agentsh/agentsh/internal/store/watchtower/wal"
    wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// ToWireReason maps an in-WAL LossRecord.Reason string to its wire enum.
// Returns (UNSPECIFIED, false) for unknown strings — caller MUST treat
// false as a programming error (log ERROR, increment
// wtp_loss_unknown_reason_total, drop the marker).
func ToWireReason(s string) (wtpv1.TransportLossReason, bool) {
    switch s {
    case wal.LossReasonOverflow:
        return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW, true
    case wal.LossReasonCRCCorruption:
        return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_CRC_CORRUPTION, true
    case wal.LossReasonAckRegressionAfterGC:
        return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC, true
    case wal.LossReasonMapperFailure:
        return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE, true
    case wal.LossReasonInvalidMapper:
        return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_MAPPER, true
    case wal.LossReasonInvalidTimestamp:
        return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP, true
    case wal.LossReasonInvalidUTF8:
        return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8, true
    case wal.LossReasonSequenceOverflow:
        return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW, true
    default:
        return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_UNSPECIFIED, false
    }
}
```

Centralizing this map ensures CI catches a missing case via the exhaustiveness test (one entry per `wal.LossReason*` constant; AST walker rejects unmatched constants — pattern matches `internal/ocsf/exhaustiveness_test.go`).

## Drop-site changes (in-flight)

`internal/store/watchtower/append.go` — each `record*` helper appends a single-record loss marker after the counter increment + WARN log. The order matters: counter increment first (cheap, always succeeds), then `wal.AppendLoss` (may fail).

```go
func (s *Store) recordSequenceOverflow(ev types.Event) {
    s.metrics.IncDroppedSequenceOverflow(1)
    s.opts.Logger.LogAttrs(...)
    s.emitInFlightLoss(ev, wal.LossReasonSequenceOverflow)
}

func (s *Store) emitInFlightLoss(ev types.Event, reason string) {
    if !s.opts.EmitExtendedLossReasons {
        return
    }
    loss := wal.LossRecord{
        FromSequence: ev.Chain.Sequence,
        ToSequence:   ev.Chain.Sequence,
        Generation:   ev.Chain.Generation,
        Reason:       reason,
    }
    if err := s.w.AppendLoss(loss); err != nil {
        if wal.IsAmbiguous(err) {
            s.sink.Fatal(err)
            s.latchFatal(err)
            return
        }
        // Clean failure (closed/fatal/etc.): counter-only path.
        s.opts.Logger.LogAttrs(context.Background(), slog.LevelError,
            "wtp: in-flight loss marker not persisted; counter-only",
            slog.String("reason", reason),
            slog.String("err", err.Error()),
            slog.Uint64("event_seq", ev.Chain.Sequence),
            slog.Uint64("event_gen", uint64(ev.Chain.Generation)))
    }
}
```

Behavior matrix:

| Drop site | New behavior |
|---|---|
| `recordSequenceOverflow` | + `emitInFlightLoss(ev, LossReasonSequenceOverflow)` |
| `recordCanonicalFailure` | + `emitInFlightLoss(ev, LossReasonInvalidUTF8)` |
| `recordCompactEncodeFailure` (mapper_failure branch) | + `emitInFlightLoss(ev, LossReasonMapperFailure)` |
| `recordCompactEncodeFailure` (invalid_mapper branch) | + `emitInFlightLoss(ev, LossReasonInvalidMapper)` |
| `recordCompactEncodeFailure` (invalid_timestamp branch) | + `emitInFlightLoss(ev, LossReasonInvalidTimestamp)` |
| `recordCompactEncodeFailure` (default fallthrough) | + `emitInFlightLoss(ev, LossReasonMapperFailure)` (mirrors counter routing) |

The fallthrough preserves the existing classification rule from `append.go:266-281`: any unrecognized error from `compact.Encode` is classified as `mapper_failure`.

## Carrier (encoder + send loop changes)

### Encoder: `state_live.go::encodeBatchMessage`

Old signature:
```go
func encodeBatchMessage(records []wal.Record) (*wtpv1.ClientMessage, error)
```

New signature:
```go
func encodeBatchMessage(records []wal.Record) ([]*wtpv1.ClientMessage, error)
```

Behavior:
1. Walk `records` linearly.
2. Accumulate consecutive `RecordData` into an `EventBatch`.
3. On hitting a `RecordLoss`:
   a. If the data accumulator is non-empty, finalize it into a `ClientMessage{EventBatch}` and append to output.
   b. Map the loss record's Reason via `ToWireReason`. On `ok=false`: log ERROR + `wtp_loss_unknown_reason_total++`, **skip the loss record entirely** (do not emit UNSPECIFIED, which would be wire-incompatible).
   c. Build a `ClientMessage{TransportLoss}` and append to output.
4. On end of input: finalize any pending data accumulator.
5. Return the slice. Empty slice if input was empty or contained only unknown-reason loss records.

Removal: `ErrRecordLossEncountered` sentinel and all its callers in `state_live.go`, `state_replaying.go`. The fail-closed branches that propagated it become unreachable and are deleted.

### Send loop

`runReplaying`, `runLive`, and `runShutdown` (the three states that send batches today) iterate the encoder's slice:

```go
msgs, err := encodeBatchMessageFn(batch.Records)
if err != nil {
    // existing error handling
}
for _, msg := range msgs {
    if err := t.send(msg); err != nil {
        // existing error handling
        return ...
    }
}
```

A single `batch.Records` may produce multiple frames; each consumes its own inflight slot.

### Inflight bookkeeping

`internal/store/watchtower/transport/inflight.go` — extend the inflight tracker so its key is the message's `to_sequence` regardless of frame type. Both `EventBatch{from, to}` and `TransportLoss{from, to}` map to the same key. When a `BatchAck.ack_high_watermark_seq` arrives, all inflight entries with `to_sequence <= ack_high` are retired.

WAL GC bookkeeping (`wal.MarkAcked`) follows the same `to_sequence` convention and is already wired to `BatchAck` — no GC changes required.

The `MaxInflight` cap counts both message types together; a deployment hitting the cap during a loss-marker burst will block the encoder until the server acks. This is acceptable and intentional — it's the same back-pressure as a normal batch burst.

## `ack_regression_after_gc` flow

`transport.computeReplayStart` already constructs a `wal.LossRecord` with `Reason: "ack_regression_after_gc"` and feeds it via `ReplayerOptions.PrefixLoss` (`internal/store/watchtower/transport/transport.go:790-813`). The Replayer surfaces it as the first record of the first NextBatch.

With the carrier wired, the encoder maps that LossRecord to `TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC` and emits it as a TransportLoss ClientMessage. No code changes in `computeReplayStart` — only the constant string switches from a literal to `wal.LossReasonAckRegressionAfterGC`.

## Configuration

`internal/config/config.go` — add to `AuditWatchtowerConfig`:

```go
type AuditWatchtowerConfig struct {
    // ... existing fields ...

    // EmitExtendedLossReasons controls whether the client emits
    // TransportLoss frames with reasons added in 2026-04-27:
    // MAPPER_FAILURE, INVALID_MAPPER, INVALID_TIMESTAMP, INVALID_UTF8,
    // SEQUENCE_OVERFLOW, ACK_REGRESSION_AFTER_GC.
    //
    // Default false. Strict-enum receivers reject unknown values per
    // the TRANSPORT_LOSS_REASON_UNSPECIFIED contract; flip to true once
    // the receiving Watchtower instance has been upgraded to support
    // the new reasons.
    //
    // OVERFLOW and CRC_CORRUPTION are always emitted (carrier-on-by-
    // default) — those values are part of the original wire schema.
    EmitExtendedLossReasons bool `yaml:"emit_extended_loss_reasons"`
}
```

Plumbed through `watchtower.Options.EmitExtendedLossReasons` to the Store. Read at two sites:

- **`emitInFlightLoss` (drop sites in `append.go`)**: when false, skip `wal.AppendLoss` entirely. The drop is counter-only and never enters the WAL — so the encoder can never see an in-flight marker on this path. When true, persist a single-record loss marker.
- **Encoder loss-emit path**: gated by the flag for ACK_REGRESSION_AFTER_GC only. OVERFLOW and CRC_CORRUPTION emit unconditionally — they are part of the original wire schema (not "extended") and any receiver implementing the proto file already accepts them. When flag=false and the encoder encounters an `ack_regression_after_gc` LossRecord (constructed by `computeReplayStart` and fed via `ReplayerOptions.PrefixLoss`), the encoder logs INFO + drops the marker. The session continues — strictly better than the pre-spec session-restart behavior. The gap remains observable in the surrounding sequence numbers; operators see the gap on the wire only after flipping the flag.

The flag gates **wire emission of the six new reason values**, full stop. It does NOT gate the carrier itself — the carrier is unconditionally on. Existing OVERFLOW/CRC are not "extended" and require no flag.

## Failure modes

| Scenario | Behavior |
|---|---|
| In-flight drop, WAL clean error (closed/fatal) | Counter increments, ERROR log, no wire emission. No worse than today. |
| In-flight drop, WAL ambiguous error | Store latches fatal (mirrors regular Append). Drop counter still increments. Subsequent appends bail with `errFatalLatch`. |
| Encoder hits unknown loss-reason string | ERROR log + `wtp_loss_unknown_reason_total++`, marker dropped. Wire integrity preserved (no UNSPECIFIED on wire). |
| Server returns Goaway on unknown enum (extended-reasons flag accidentally on against old server) | Existing Goaway handling: client reconnects with backoff; operator inspects logs and disables flag. |
| Inflight cap hit during loss-marker burst | Encoder back-pressures normally — same as a data burst. |
| TransportLoss is the last frame before reconnect | The new connection's SessionInit carries `wal_high_watermark_seq` past the loss; on reconnect, the server re-acks, the marker is GC'd. No special handling. |

## Metrics

New counter on `internal/metrics`:

```go
// wtp_loss_unknown_reason_total — incremented when the encoder
// encounters a wal.LossRecord.Reason string with no wire enum mapping.
// The marker is dropped (not emitted as UNSPECIFIED) to preserve
// wire-format conformance. Non-zero values indicate a producer added
// a new reason without updating ToWireReason — a programming bug.
wtpLossUnknownReason atomic.Uint64
```

Exposition via `Collector.WriteWTPMetrics` mirrors the existing `wtp_dropped_*` family.

The existing `wtp_dropped_*` counters are unchanged. They count drops at the source, regardless of whether the loss marker reached the wire.

A future addition (out of scope here) is `wtp_loss_emitted_total{reason}` — emit-side observation. Deferred until operators ask for it; today the source-side `wtp_dropped_*` family is sufficient.

## Operator-facing logs

In addition to the existing per-drop WARN, the encoder emits a single INFO per loss marker it dispatches:

```
INFO wtp: emitted TransportLoss frame
  reason=mapper_failure from_seq=1234 to_seq=1234 generation=7
  session_id=... agent_id=...
```

This makes the carrier path observable end-to-end without grepping the wire. Sample rate: every emission. These are rare and informative.

## Tests

### Unit (carrier)

- `TestEncoder_DataLossDataSplitsIntoThreeFrames` — input `[data:N, loss:N+1, data:N+2]` produces `[EventBatch{N}, TransportLoss{N+1, N+1}, EventBatch{N+2}]` in order.
- `TestEncoder_TrailingLossEmitsTrailingFrame` — input `[data:N, loss:N+1]` produces `[EventBatch{N}, TransportLoss{N+1, N+1}]`.
- `TestEncoder_LeadingLossEmitsLeadingFrame` — input `[loss:N, data:N+1]` produces `[TransportLoss{N, N}, EventBatch{N+1}]`.
- `TestEncoder_ConsecutiveLossesAreSeparateFrames` — input `[loss:N, loss:N+1]` produces two TransportLoss frames (no coalescing per design choice).
- `TestEncoder_UnknownReasonDropsMarker` — input contains a LossRecord with Reason="garbage"; encoder logs ERROR, increments `wtp_loss_unknown_reason_total`, omits the loss frame, continues with adjacent data.
- `TestToWireReason_AllConstants` — every `wal.LossReason*` constant has an entry; AST walker (mirrors `internal/ocsf/exhaustiveness_test.go`) catches missing cases at CI time.
- `TestToWireReason_NeverReturnsUnspecified_ForKnownConstants` — all known constants map to a non-UNSPECIFIED enum value.

### Unit (drop sites)

- `TestStore_SequenceOverflow_EmitsLossMarker_WhenFlagOn` — drop site calls AppendLoss with the right reason and (gen, seq).
- `TestStore_SequenceOverflow_NoLossMarker_WhenFlagOff` — flag=false → AppendLoss not called.
- Same matrix for `invalid_utf8`, `mapper_failure`, `invalid_mapper`, `invalid_timestamp`.
- `TestStore_InFlightLoss_WALClean_CounterOnly` — WAL is closed; drop counter still increments, AppendLoss returns clean error, ERROR logged, no fatal latch.
- `TestStore_InFlightLoss_WALAmbiguous_LatchesFatal` — WAL ambiguous failure on AppendLoss path latches store + sink chain fatal.

### Component (carrier wire)

- `TestStore_OverflowEmitsTransportLossOnWire` — exercise WAL overflow, assert testserver receives `ClientMessage{TransportLoss{reason: OVERFLOW}}`.
- `TestStore_CRCCorruptionEmitsTransportLossOnWire` — exercise CRC corruption during replay, assert testserver receives a TransportLoss with reason CRC_CORRUPTION.
- `TestStore_InFlightDropEmitsTransportLossOnWire_WhenFlagOn` — five subtests, one per in-flight reason.
- `TestStore_AckRegressionAfterGC_EmitsTransportLossOnWire_WhenFlagOn` — manufacture an ack_regression_after_gc scenario; assert receiving testserver gets a TransportLoss with that reason.
- `TestStore_TransportLossInflightSlot_RetiredByBatchAck` — server holds back BatchAck; client's inflight tracker shows the slot occupied; server acks; slot retires; WAL GC unblocks.
- `TestStore_TransportLossInflightSlot_CountedTowardMaxInflight` — fill MaxInflight with a mix of EventBatch and TransportLoss; encoder back-pressures correctly.

### Integration (no fail-closed regression)

- `TestStore_OverflowDoesNotRestartSession` — pre-spec, overflow caused session teardown via ErrRecordLossEncountered. Post-spec, the session continues. Strong regression guard.
- `TestStore_CRCCorruptionDoesNotRestartSession` — same regression guard for CRC.

### Wire goldens

- `proto/canyonroad/wtp/v1/testdata/transport_loss_*.bin` — one golden per new reason value (and updated goldens for the existing OVERFLOW/CRC). Round-trip test already exists per spec §"Phase 4b".

## Migration

Migration plays out in three phases:

1. **Client lands this spec, carrier-on-by-default.** Existing OVERFLOW/CRC reasons start emitting on the wire. No server change needed since those enum values already existed.
2. **Watchtower server ships support for new reasons.** Owned by the server team. Client-side flag remains off.
3. **Operators flip `output.wtp.emit_extended_loss_reasons: true` per deployment** once their Watchtower has been upgraded.

Rollback story: each step is independently reversible. If the server-side upgrade misbehaves, operators flip the client flag back to false and the new in-flight reasons return to counter-only. The carrier itself can be reverted by reverting the client-side PR.

Operator doc to update: `docs/superpowers/operator/wtp-monitoring-migration.md` — add a section on the new flag, the wire-incompatibility risk, and the recommended rollout order. Mirrors the LogGoawayMessage entry from Task 27b.

## Open questions

None. All design questions resolved during the brainstorm:

- Bundle scope: yes (carrier + reasons together).
- Reason taxonomy: 1:1 with counters.
- Persistence path: WAL via AppendLoss.
- Ack semantics: symmetrical with EventBatch.
- Carrier default: on.
- Extended-reasons default: off (gated by flag).
- Encoder signature: returns slice.
- Coalescing: no; one marker per drop.

## Acceptance criteria

1. `proto/canyonroad/wtp/v1/wtp.proto` carries the six new enum values; generated `.pb.go` regenerated and committed.
2. `wal/loss_reasons.go` declares all reason strings as exported consts; existing producers reference them.
3. `transport/loss_reason.go` declares `ToWireReason`; an exhaustiveness CI test enforces 1:1 coverage.
4. `state_live.go::encodeBatchMessage` returns `[]*wtpv1.ClientMessage`; `ErrRecordLossEncountered` and its callers are removed.
5. The send loops in `runLive`, `runReplaying`, `runShutdown` iterate the slice and back-pressure on inflight cap.
6. `inflight.go` retires both EventBatch and TransportLoss slots via `BatchAck` against `to_sequence`.
7. The five `record*` drop sites in `append.go` route through a shared `emitInFlightLoss` helper that respects the flag and handles WAL ambiguous → fatal latch.
8. `EmitExtendedLossReasons` is wired through config → Options → Store; default false.
9. All unit, component, integration, and golden tests above pass on linux + macos + windows.
10. `TestStore_OverflowDoesNotRestartSession` and `TestStore_CRCCorruptionDoesNotRestartSession` pass — the legacy fail-closed behavior is gone.
11. `docs/superpowers/operator/wtp-monitoring-migration.md` documents the new flag.
12. No regression in existing `wtp_dropped_*` counter behavior — they continue to increment at the source.

## Out of scope (explicitly deferred)

- Coalescing contiguous in-flight drops into a single TransportLoss range. Each drop emits its own marker.
- `wtp_loss_emitted_total{reason}` emit-side counter. Source-side counters are sufficient until operators ask.
- v2 WAL frame format with per-record sequence headers (separate spec).
- Server-side support for the six new reason enum values. Owned by the Watchtower server team; this spec only declares the client-side wire contract.
- Backfilling drops that happened before this spec lands. Once it ships, only forward drops emit markers.
