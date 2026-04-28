# WTP Deferred Failure-Metric Wiring — Design

**Date:** 2026-04-28
**Status:** Draft, awaiting user review
**Related:** WTP client design (`docs/superpowers/specs/2026-04-18-wtp-client-design.md`),
TransportLoss in-flight drops (PR #255), batch compression (PR #256).

## Summary

Wire two metric families that have been name-reserved with always-emit
zero contracts since Phase 4 but never actually incremented:

- `wtp_session_init_failures_total{reason}` — the agent's outbound
  handshake failure paths in `state_connecting.go`. Expand the reason
  enum from 2 to 6 values; emit at the 5 distinct failure sites.
- `wtp_dropped_invalid_frame_total{reason}` — the agent's inbound
  `ServerMessage` validation path. Add 5 new `Validate*` functions to
  the proto package; 2 new `ValidationReason` constants; route inbound
  frame failures through the existing `ClassifyAndIncInvalidFrame`
  helper in `recv_multiplexer.go`.

`wtp_session_rotation_failures_total{reason}` is **explicitly
out-of-scope** — it depends on inbound `SessionUpdate` rotation
handling, which is Phase 5+ work tracked as a separate "Project C"
spec.

## Motivation

Both metric families exist in the agent's metric surface today, emit
zero on every scrape, and have honest doc text saying "name-reserved
for receiver use" / "wired by Phase 8" — the current state is
acceptable but unfortunate: an operator looking at the agent's
dashboards cannot distinguish "no handshake failures" from "we never
implemented the counter."

Both families have clear emit sites in current code. The cost of
wiring is small (single PR per family); the value is that operators
get real failure signal from the next agent release.

The third family (`wtp_session_rotation_failures_total`) requires
implementing the *feature* (inbound SessionUpdate rotation) before the
metric can be wired. That is a much bigger project and is deferred.

## Non-Goals

- Implementing inbound `SessionUpdate` rotation (Project C).
- Wiring `wtp_session_rotation_failures_total` (depends on Project C).
- Adding *application-layer* invariant checks to validators
  (`applyServerAckTuple` continues to handle ack-vs-local-state
  invariants through `wtp_anomalous_ack_total{reason}`).
- New validators for `ClientMessage` variants the testserver already
  validates — no changes to testserver-side validation; the existing
  `ValidateEventBatch` / `ValidateSessionInit` calls in `testserver/server.go`
  stay as-is.
- Changing the existing `wtp_reconnects_total{reason}` semantics.

## Background — Current State

### `wtp_session_init_failures_total{reason}`

- Defined in `internal/metrics/wtp.go` with reason enum
  `{invalid_utf8, unknown}` and always-emit zero contract.
- The `IncSessionInitFailures` facade method exists but **has no
  caller** in production code.
- The agent's outbound handshake failure paths in
  `internal/store/watchtower/transport/state_connecting.go` (lines
  ~23, ~42, ~48, ~56, ~62) handle 5 distinct failure modes — each
  returns a state transition (StateConnecting / StateShutdown) and a
  wrapped error, but emits no metric.
- `wtp_reconnects_total{reason}` IS incremented for the connection-
  level event by the run loop's reconnect path, but cannot
  distinguish "send failed during handshake" from "send failed after
  Live state was reached."

### `wtp_dropped_invalid_frame_total{reason}`

- Defined in `internal/metrics/wtp.go` with reasons:
  `event_batch_body_unset`, `event_batch_compression_unspecified`,
  `event_batch_compression_mismatch`,
  `session_init_algorithm_unspecified`, `payload_too_large`,
  `decompress_error`, `classifier_bypass`, `unknown`.
- `transport.ClassifyAndIncInvalidFrame` is the canonical wrapper for
  validator failures; it routes typed `*ValidationError` through the
  proto-side reason and falls back to `classifier_bypass` for
  non-typed errors.
- **Wired today only in the testserver** (`testserver/server.go:363,
  415`) for `EventBatch` and `SessionInit` reception. The
  testserver acts as the receiver for client→server frames.
- The agent itself receives `ServerMessage` variants in
  `recv_multiplexer.go` (`SessionAck`, `BatchAck`, `ServerHeartbeat`,
  `Goaway`, `ServerUpdate`) and applies them, but **does not validate
  them** because the proto package has no `Validate*` functions for
  these variants.

### `wtp_session_rotation_failures_total{reason}`

- Defined with reasons `{invalid_utf8, unknown}` and always-emit zero.
- No handler for inbound `SessionUpdate` exists in the agent.
  `recv_multiplexer.go` fail-closes on `*ServerMessage_ServerUpdate`
  with the structured WARN
  `"server_update_unsupported_in_phase_4"` and the recv error
  `"recv: control frame session_update not yet handled"`.
- Wiring this metric requires the rotation feature to land first.
  Deferred to Project C.

## Design

### Project A — `wtp_session_init_failures_total{reason}` wiring

**Reason enum expansion** (`internal/metrics/wtp.go`):

The `WTPSessionFailureReason` enum is shared between
`wtp_session_init_failures_total` (this project) and
`wtp_session_rotation_failures_total` (Project C). Some reasons fire
only on one of the two call sites; that's intentional — the enum is
the union of both producers' failure modes.

| Reason | Existing? | Fires when (in the SessionInit producer scope of THIS project) |
|---|---|---|
| `invalid_utf8` | yes | RESERVED for chain-rotation failures (Project C). `ValidateSessionInit` does not currently surface invalid-UTF-8 errors, so this reason is always-zero on the SessionInit producer until Project C lands. |
| `send_failed` | new | `conn.Send(SessionInit)` returns error |
| `recv_failed` | new | `conn.Recv()` returns error before SessionAck arrives |
| `unexpected_message` | new | recv'd a non-SessionAck `ServerMessage` variant |
| `rejected` | new | server returned `SessionAck.accepted=false` |
| `unknown` | yes | `ValidateSessionInit` returned any error (today: `ReasonSessionInitAlgorithmUnspecified`); also the catch-all for any future failure path the enum does not name explicitly |

The `invalid_utf8` reason stays in the enum so the schema is stable
across this project and Project C — operator dashboards that filter
on `reason="invalid_utf8"` keep working when Project C lands and
starts producing non-zero values for the rotation path.

The 4 new reasons are added to:
- `WTPSessionFailureReason` constant block.
- `wtpSessionFailureReasonsValid` map.
- `wtpSessionFailureReasonsEmitOrder` slice (alphabetical).

Existing parity tests (`TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons`,
`TestWTPMetrics_SessionFailureReasonValidationAndEscape`) update to
expect the 6-reason set.

**`state_connecting.go` emit sites:**

| Path | Existing return | Add metric increment |
|---|---|---|
| line ~23 (`ValidateSessionInit` fails) | `StateShutdown` + wrapped error | `t.metrics.IncSessionInitFailures(unknown)` (the validator only returns `ReasonSessionInitAlgorithmUnspecified` today; a future validator surface gain — e.g. the chain-rotation invalid-UTF-8 case — would add an `errors.Is(err, chain.ErrInvalidUTF8)` discrimination here that emits `invalid_utf8`) |
| line ~42 (`conn.Send` fails) | `StateConnecting` + wrapped error | `t.metrics.IncSessionInitFailures(send_failed)` |
| line ~48 (`conn.Recv` fails) | `StateConnecting` + wrapped error | `t.metrics.IncSessionInitFailures(recv_failed)` |
| line ~56 (wrong message type) | `StateConnecting` + error | `t.metrics.IncSessionInitFailures(unexpected_message)` |
| line ~62 (`accepted == false`) | `StateShutdown` + reject_reason | `t.metrics.IncSessionInitFailures(rejected)` |

The validator-failure path emits `unknown` rather than mapping
`ReasonSessionInitAlgorithmUnspecified` to a dedicated reason because
the operator response is identical to "any other validator failure":
the agent's outbound SessionInit construction is misconfigured
(usually `Algorithm` left zero in `Options`). A `*ValidationError`
returned by the validator is logged via the existing wrapped-error
pattern; the structured ERR carries the field-level cause for triage.
If the validator surface gains additional sentinel error kinds
(e.g. invalid-UTF-8 from chain-rotation in Project C), they're added
as `errors.Is` branches at this site without a schema migration —
the `invalid_utf8` reason already exists in the enum reserved for
exactly that case.

The server's `RejectReason` text on `accepted=false` is **not**
included as a label value — that text is unbounded/free-form and
would explode label cardinality. The structured WARN already emitted
on rejection logs the full text; metrics carry only the count under
`rejected`.

### Project B — Inbound frame validators + `wtp_dropped_invalid_frame_total{reason}`

**New `ValidationReason` constants** (`proto/canyonroad/wtp/v1/validate.go`):

| Constant | String value | Fires when |
|---|---|---|
| `ReasonGoawayCodeUnspecified` | `goaway_code_unspecified` | `Goaway.code == GOAWAY_CODE_UNSPECIFIED` (wire-incompatible per the proto's UNSPECIFIED contract) |
| `ReasonSessionUpdateGenerationInvalid` | `session_update_generation_invalid` | inbound `SessionUpdate.generation == 0` (rotation MUST monotonically advance to a positive generation) |

Both follow the existing naming pattern
`<message>_<field>_<failure>`. They join the proto's
`AllValidationReasons()` slice; the cross-package parity test
(`internal/metrics/wtp_parity_test.go`) auto-fails until matching
`WTPInvalidFrameReason` constants land.

**New `Validate*` functions** (`proto/canyonroad/wtp/v1/validate.go`):

```go
// ValidateSessionAck rejects a SessionAck whose body is structurally
// inconsistent. Stateless: state-dependent invariants (e.g. ack must
// not exceed local seq) are enforced at the transport's apply layer
// (applyServerAckTuple). Returns ReasonUnknown for any structural
// failure the validator can detect (nil message, accepted=false with
// empty reject_reason).
func ValidateSessionAck(ack *SessionAck) error

// ValidateBatchAck rejects a nil BatchAck. Returns ReasonUnknown.
// State-dependent invariants are not the validator's concern.
func ValidateBatchAck(ack *BatchAck) error

// ValidateServerHeartbeat rejects a nil ServerHeartbeat. Returns
// ReasonUnknown.
func ValidateServerHeartbeat(hb *ServerHeartbeat) error

// ValidateGoaway returns ReasonGoawayCodeUnspecified when
// Goaway.code == GOAWAY_CODE_UNSPECIFIED — that value is wire-
// incompatible per the proto's UNSPECIFIED contract. Returns
// ReasonUnknown for any other structural failure (nil message).
func ValidateGoaway(g *Goaway) error

// ValidateSessionUpdate returns ReasonSessionUpdateGenerationInvalid
// when SessionUpdate.generation == 0. Returns ReasonUnknown for any
// other structural failure (nil message).
func ValidateSessionUpdate(u *SessionUpdate) error
```

All five functions return `*ValidationError` (the existing typed-
error pattern that `ClassifyAndIncInvalidFrame` already routes
correctly).

**Recv-multiplexer wiring**
(`internal/store/watchtower/transport/recv_multiplexer.go`):

The existing dispatch switch on `m := msg.Msg.(type)` adds a
validation step at the top of each variant arm:

```go
case *wtpv1.ServerMessage_SessionAck:
    if err := wtpv1.ValidateSessionAck(m.SessionAck); err != nil {
        ClassifyAndIncInvalidFrame(t.opts.Logger, t.metrics, err)
        select {
        case rs.errCh <- fmt.Errorf("recv: invalid SessionAck: %w", err):
        default:
        }
        return
    }
    // ... existing handler ...
```

Same shape applied to the `BatchAck`, `ServerHeartbeat`, `Goaway`,
and `ServerUpdate` (carrying `SessionUpdate`) arms.

The `ServerUpdate` arm continues to fail-closed regardless of the
validation outcome — Project C territory — but a malformed
ServerUpdate now correctly increments
`wtp_dropped_invalid_frame_total{reason=session_update_generation_invalid}`
*before* fail-closing, rather than silently triggering only the
existing `server_update_unsupported` reconnect.

The `default:` arm (unknown frame type) keeps its existing
`wtp_reconnects_total{reason=recv_unknown_frame}` behavior — that's
a different metric for a different concern (peer-side schema drift
of a whole oneof variant, not within-variant validator failure).

### Wire-shape and failure semantics

Validation runs *before* the existing handler in each dispatch arm,
so a malformed frame never reaches the apply layer. On validation
failure:

1. `ClassifyAndIncInvalidFrame` increments
   `wtp_dropped_invalid_frame_total{reason=...}`. The reason comes
   from the `*ValidationError`'s `Reason` field (one of the named
   reasons or `unknown`).
2. The helper emits a rate-limited structured WARN with `reason`,
   `err_type`, and the offending frame's variant name (existing
   helper behavior).
3. The recv goroutine sends a recv error onto `errCh` and returns.
   The main state-machine loop reads the error and transitions to
   `StateConnecting` with
   `wtp_reconnects_total{reason=recv_unknown_frame}` (existing
   behavior — the malformed-frame reconnect path is already wired to
   this reason).

A single malformed frame ticks **two** counters:
- `wtp_dropped_invalid_frame_total{reason=...}` — frame-level
  diagnostic ("why was the frame rejected").
- `wtp_reconnects_total{reason=recv_unknown_frame}` — connection-
  level event ("why did we reconnect").

That double-count is intentional, mirroring the SessionInit case
(see Project A): the two metrics answer different questions. A
single failure event legitimately fires both.

Application-level invariants (e.g. ack high-watermark exceeds local
seq, generation regression) stay where they are today —
`applyServerAckTuple` continues to handle them via
`wtp_anomalous_ack_total{reason}`. Validators only fence
structural / wire-contract failures.

### Failure modes reference

| Failure | Counter incremented | Reconnect? | Operator response |
|---|---|---|---|
| Outbound SessionInit validator failure (today: `ReasonSessionInitAlgorithmUnspecified`) | `wtp_session_init_failures_total{unknown}` | no (StateShutdown) | Investigate Options misconfiguration (typically `Algorithm` left zero) — structured ERR log carries the field-level cause |
| `conn.Send(SessionInit)` fails | `wtp_session_init_failures_total{send_failed}` | yes | Check network egress / server reachability |
| `conn.Recv()` fails before SessionAck | `wtp_session_init_failures_total{recv_failed}` | yes | Check server liveness / network return path |
| Recv'd non-SessionAck variant | `wtp_session_init_failures_total{unexpected_message}` | yes | Server protocol bug / version mismatch |
| Server returned `accepted=false` | `wtp_session_init_failures_total{rejected}` | no (StateShutdown) | Server-side auth / agent identity mismatch |
| Inbound `Goaway.code == UNSPECIFIED` | `wtp_dropped_invalid_frame_total{goaway_code_unspecified}` + `wtp_reconnects_total{recv_unknown_frame}` | yes | Server protocol-version mismatch |
| Inbound `SessionUpdate.generation == 0` | `wtp_dropped_invalid_frame_total{session_update_generation_invalid}` + `wtp_reconnects_total{recv_unknown_frame}` | yes | Server bug |
| Inbound SessionAck/BatchAck/ServerHeartbeat structural failure | `wtp_dropped_invalid_frame_total{unknown}` + `wtp_reconnects_total{recv_unknown_frame}` | yes | Server bug; check structured WARN for field-level cause |

## Test Strategy

Unit:

- `proto/canyonroad/wtp/v1/validate_test.go` — for each new
  `Validate*` function:
  - happy path (well-formed → nil)
  - named-reason failure mode (e.g. `Goaway.code == UNSPECIFIED`
    → `ReasonGoawayCodeUnspecified`)
  - unknown-reason structural failure (e.g. nil → `ReasonUnknown`)
  - errors are typed `*ValidationError` (so `errors.As` works)
- `proto/canyonroad/wtp/v1/validate_reason_test.go` — extend the
  reason-completeness test to include the 2 new reason constants.
- `internal/metrics/wtp_parity_test.go` — auto-extends; the cross-
  package parity test fails until matching `WTPInvalidFrameReason`
  constants land in the metrics package.
- `internal/metrics/wtp_test.go` — extend
  `TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons` to
  expect the 2 new reasons at zero on first scrape.
- `internal/metrics/wtp_test.go` — extend
  `TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons` to
  expect the 4 new reason labels at zero. Add a new
  `TestWTPMetrics_SessionInitFailures_PerReasonInc` that increments
  each of the 6 reasons and asserts the resulting Prom output.

Component (using the existing testserver harness):

- `internal/store/watchtower/component_session_init_failure_test.go`
  — drive the agent through each of the 5 SessionInit failure
  paths and assert the counter ticked with the expected reason. The
  testserver already supports the configurations needed:
  - `RejectSessionInit: true` for `rejected`
  - close-conn-during-recv for `recv_failed`
  - inject a wrong-message-type response for `unexpected_message`
  - induce a send error via the existing dialer-failure hook for
    `send_failed`
  - construct an Options that fails `ValidateSessionInit`
    (e.g., `Algorithm: HASH_ALGORITHM_UNSPECIFIED`) for the validator-failure path
    — emits reason `unknown` per the producer table
- `internal/store/watchtower/component_invalid_frame_test.go` — drive
  the testserver to inject:
  - a `Goaway` with `code: UNSPECIFIED` → assert
    `wtp_dropped_invalid_frame_total{reason=goaway_code_unspecified}` ticked
  - a `SessionUpdate` with `generation: 0` → assert
    `wtp_dropped_invalid_frame_total{reason=session_update_generation_invalid}` ticked
  - a structurally-malformed `BatchAck`/`SessionAck`/`ServerHeartbeat`
    → assert `wtp_dropped_invalid_frame_total{reason=unknown}` ticked
  - in all cases assert the agent reconnected (StateConnecting
    transition observable via the session-state gauge or
    `wtp_reconnects_total{reason=recv_unknown_frame}` increment)

The component tests follow the established `AssertReplayObserved` +
60s deadline pattern from `compress_integration_test.go` to avoid
joining the Windows flake-class observed in
`TestStore_OverflowEmitsTransportLossOnWire`.

Cross-compile: `GOOS=windows go build ./...` clean.

## Operator Documentation

Append to `docs/superpowers/operator/wtp-monitoring-migration.md`:

- A section documenting the expanded `wtp_session_init_failures_total`
  reason set: 6 values, when each fires, recommended alert thresholds
  (e.g., notify-only on any non-zero rate; page on sustained
  `rejected` rate which indicates an auth/identity problem).
- A section documenting the 2 new
  `wtp_dropped_invalid_frame_total` reason values (`goaway_code_unspecified`,
  `session_update_generation_invalid`) and what they signal — both
  point to server protocol-version mismatch.
- Both new families include the standard "Reload model" /
  "Verification after a flip" sections matching the existing
  knob-documentation style.

## Failure Modes (cross-cutting)

| Failure mode | Sender behavior | Wire effect | Operator signal |
|---|---|---|---|
| Validator surface gains a new sentinel error not yet handled in `state_connecting.go` | `IncSessionInitFailures(unknown)` | unchanged | always-emit `unknown` reason guarantees the metric still increments correctly; structured ERR log carries the err_type for triage |
| Inbound frame fails validation, errCh buffer is full | `ClassifyAndIncInvalidFrame` increments the counter; the `select` default arm drops the recv-error send (existing behavior) | recv goroutine returns; main loop will re-detect the conn problem on next iteration | `wtp_dropped_invalid_frame_total` increments correctly even when errCh buffer is full |
| Inbound frame is valid but the apply layer rejects it (e.g. ack regression) | unchanged — application-level invariants route through `wtp_anomalous_ack_total` | unchanged | unchanged |

## Out of Scope (Project C territory)

- Inbound `SessionUpdate` actually being applied (rotation feature):
  WAL generation roll, integrity-chain rekey, transport flush+roll
  coordination. The full design exists in
  `2026-04-18-wtp-client-design.md` but the implementation is
  multi-week, multi-PR work that deserves its own brainstorm cycle.
- `wtp_session_rotation_failures_total{reason}` wiring — depends on
  Project C.
- Live-rotation-aware reconnect handling.

## Open Questions

None — design is converged. Awaiting user spec review before plan
authoring.
