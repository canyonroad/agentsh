# WTP Drop-Class Counters — Design

**Date:** 2026-04-25
**Status:** Approved (brainstorming complete; ready for implementation plan)
**Scope:** Wire the five existing `wtp_dropped_invalid_*_total` counters at the existing reject sites in `internal/store/watchtower/AppendEvent`, plus structured WARN logs.

## Background

Task 22a registered five drop-class counters on `metrics.WTPMetrics`:

| Counter | Trip condition |
|---|---|
| `wtp_dropped_invalid_utf8_total` | `chain.EncodeCanonical` returns `chain.ErrInvalidUTF8` |
| `wtp_dropped_sequence_overflow_total` | `ev.Chain.Sequence > math.MaxInt64` |
| `wtp_dropped_invalid_mapper_total` | `compact.Encode` returns `compact.ErrInvalidMapper` |
| `wtp_dropped_invalid_timestamp_total` | `compact.Encode` returns `compact.ErrInvalidTimestamp` |
| `wtp_dropped_mapper_failure_total` | `compact.Encode` returns a mapper-wrapped error (catch-all) |

`internal/metrics/wtp.go` lines 463-467 explicitly mark these as **NOT YET WIRED — emits zero**. The `AppendEvent` docstring at `internal/store/watchtower/append.go:67-75` documents the gap as Task 23 follow-up:

> SCOPE NOTE: this is Task 23's core transactional path. The full spec additionally routes compact.ErrInvalidMapper / ErrInvalidTimestamp / mapper-wrapped / sequence-overflow / chain.ErrInvalidUTF8 through per-class drop counters (wtp_dropped_invalid_*_total) with structured WARN logs. That counter-wiring layer is follow-up work alongside the Task 22a sink-failure counter surface; today those errors propagate to the caller as wrapped errors.

This design closes that gap.

## Architecture

Three private methods on `*Store`, each owning the classify-and-emit logic for one reject class:

```
AppendEvent reject sites (in source order):
  ├─ ev.Chain.Sequence > math.MaxInt64   ─→ s.recordSequenceOverflow(ev)
  ├─ compact.Encode(...) error            ─→ s.recordCompactEncodeFailure(err, ev)
  └─ chain.EncodeCanonical(...) error     ─→ s.recordCanonicalFailure(err, ev)
```

Each helper:
1. Increments the appropriate `WTPMetrics.IncDroppedX(1)` counter (nil-safe via `*WTPMetrics` receiver).
2. Emits one structured WARN via `s.opts.Logger`.
3. Returns `void` — the caller still does its existing `return fmt.Errorf("…: %w", err)`, so error-return semantics are preserved exactly.

`recordCompactEncodeFailure` does the multi-way classification:

| `errors.Is(err, …)` | Counter | Reason label |
|---|---|---|
| `compact.ErrInvalidMapper` | `IncDroppedInvalidMapper(1)` | `invalid_mapper` |
| `compact.ErrInvalidTimestamp` | `IncDroppedInvalidTimestamp(1)` | `invalid_timestamp` |
| (catch-all) | `IncDroppedMapperFailure(1)` | `mapper_failure` |

The catch-all branch fires for the mapper-wrapped error returned by `compact/encoder.go:71` (`fmt.Errorf("compact mapper: %w", err)`), since that path does not preserve a typed sentinel by design.

Note: `compact.ErrMissingChain` is unreachable from `AppendEvent` because line 100 (`if ev.Chain == nil { return … }`) bails before `compact.Encode` runs. No counter is added for that path; if a future code change makes it reachable it falls into the `mapper_failure` catch-all and surfaces in logs.

## WARN log shape

Mirrors the existing `recv_multiplexer.go` pattern:

```go
s.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
    "wtp: dropping event before WAL append",
    slog.String("reason", "<class>"),
    slog.String("err", err.Error()),         // omitted for sequence_overflow (no underlying err)
    slog.Uint64("event_seq", ev.Chain.Sequence),
    slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
    slog.String("session_id", s.opts.SessionID),
    slog.String("agent_id", s.opts.AgentID))
```

The `reason` label values (`invalid_mapper`, `invalid_timestamp`, `mapper_failure`, `sequence_overflow`, `invalid_utf8`) match the metric suffix exactly so log readers can grep by reason and find the matching counter without translation.

`event_seq` / `event_gen` give triage context (what record was rejected); `session_id` / `agent_id` cross-correlate with WAL identity warnings already in `store.go`.

## Error-return semantics

Existing returns are preserved verbatim:

| Site | Existing return |
|---|---|
| Sequence overflow | `fmt.Errorf("watchtower: ev.Chain.Sequence %d overflows int64", ev.Chain.Sequence)` |
| compact.Encode failure | `fmt.Errorf("compact.Encode: %w", err)` |
| chain.EncodeCanonical failure | `fmt.Errorf("chain.EncodeCanonical: %w", err)` |

The existing `compact.Encode` and `chain.EncodeCanonical` returns already use `%w` to preserve the underlying sentinel for `errors.Is` callers. This design adds the counter+WARN side effect; it does not introduce a new sentinel for sequence overflow (the existing error is a one-off `fmt.Errorf` that callers do not match against today, and there is no demonstrated need to add one).

## Out of scope

- WAL `Append` and `Commit` errors. These are transactional infrastructure failures (clean / ambiguous classification, fatal-latch territory) — not "drop class." They have their own paths in `append.go` and stay as-is.
- The `ev.Chain == nil` early bail at line 100. It returns a one-off error and is not a peer-derived drop class; no counter is added.
- New metric counters. The five counters in scope are already registered on `WTPMetrics`; this work only wires producers.

## Testing

Two test files. The split exists because `Options.validate` rejects nil and typed-nil `Mapper` at construction (`internal/store/watchtower/options.go:181-185`), so `compact.ErrInvalidMapper` is unreachable from `AppendEvent` through a real `watchtower.New` flow. The wiring is still defense-in-depth — operators want the counter to fire if the validation surface ever changes — but the test for that branch must call the helper directly.

### `internal/store/watchtower/append_drop_test.go` (external `watchtower_test` package)

Real `watchtower.New` + `AppendEvent` integration tests, one per reachable drop class plus happy path:

| Test | Trigger | Counter asserted | Reason label asserted |
|---|---|---|---|
| `TestAppendEvent_DropsOnInvalidTimestamp` | `ev.Timestamp = time.Time{}` | `DroppedInvalidTimestamp() == 1` | `invalid_timestamp` |
| `TestAppendEvent_DropsOnMapperFailure` | Test-fixture mapper whose `MapEvent` returns an error | `DroppedMapperFailure() == 1` | `mapper_failure` |
| `TestAppendEvent_DropsOnSequenceOverflow` | `ev.Chain.Sequence = math.MaxInt64 + 1` | `DroppedSequenceOverflow() == 1` | `sequence_overflow` |
| `TestAppendEvent_DropsOnInvalidUTF8` | `Options.KeyFingerprint` containing a non-UTF-8 byte (flows into `IntegrityRecord.KeyFingerprint` → `chain.EncodeCanonical` → `chain.ErrInvalidUTF8`) | `DroppedInvalidUTF8() == 1` | `invalid_utf8` |
| `TestAppendEvent_HappyPath_NoDrops` | Valid mapper, timestamp, sequence, key fingerprint | ALL five counters stay at 0; no WARN | — |

### `internal/store/watchtower/append_drop_internal_test.go` (internal `watchtower` package)

| Test | Approach | Counter asserted | Reason label asserted |
|---|---|---|---|
| `TestRecordCompactEncodeFailure_ClassifiesInvalidMapper` | Construct a Store, call `s.recordCompactEncodeFailure(compact.ErrInvalidMapper, ev)` directly | `DroppedInvalidMapper() == 1` | `invalid_mapper` |

Each failing-path test (both files) also asserts:
- `errors.Is(err, <expected sentinel>)` on the returned error where applicable (preserves existing semantics; sequence overflow has no sentinel and asserts on the message instead).
- The captured WARN log carries the triage attrs (`event_seq`, `event_gen`, `session_id`, `agent_id`).

The happy-path test catches a regression where every successful append accidentally bumps a drop counter.

## Files touched

| File | Change |
|---|---|
| `internal/store/watchtower/append.go` | Add 3 private helpers; insert 3 helper calls at the existing reject sites; remove the SCOPE NOTE referencing this work as future. |
| `internal/store/watchtower/append_drop_test.go` | NEW: 5 tests via real `AppendEvent` (4 reachable drop classes + 1 happy path). |
| `internal/store/watchtower/append_drop_internal_test.go` | NEW: 1 test calling `recordCompactEncodeFailure` directly to cover the defense-in-depth `ErrInvalidMapper` branch (unreachable through Options validation). |
| `internal/metrics/wtp.go` | Update the "NOT YET WIRED — emits zero" comments at lines 463-467 to point at `AppendEvent` as the live producer. |

## Acceptance

- `go test ./...` passes (existing tests stay green; 6 new tests added — 5 external + 1 internal).
- `GOOS=windows go build ./...` passes.
- All 5 counters increment exactly once per trip, with no double-counting under the happy path.
- `roborev review` clean (no findings above Low).
