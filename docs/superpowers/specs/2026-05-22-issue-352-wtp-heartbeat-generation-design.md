# Issue #352 — `ServerHeartbeat.generation` design

**Status:** approved, ready for implementation plan
**Date:** 2026-05-22
**Issue:** [#352](https://github.com/canyonroad/agentsh/issues/352) — WTP v0.5: ServerHeartbeat.generation — carry full watermark tuple
**Label:** `wtp-v0.5`

## Problem

`ServerHeartbeat` (`proto/canyonroad/wtp/v1/wtp.proto:184-186`) carries only
`ack_high_watermark_seq`. The recv multiplexer pushes heartbeat events onto
`eventCh` with `gen = 0`, and the main goroutine substitutes
`t.persistedAck.Generation` at apply time
(`state_live.go:259`, `state_replaying.go:81`). This substitution is safe only
under a strict FIFO-order invariant on `eventCh` (any earlier `BatchAck` has
been applied before the heartbeat is dispatched), documented load-bearing at
`recv_multiplexer.go:24-31` and `44-50`.

The substitution is a workaround for a missing wire field. It couples client
correctness to an event-ordering rule that is otherwise an implementation
detail of the dispatcher. Adding `generation` to `ServerHeartbeat` makes the
watermark tuple `(gen, seq)` explicit on every server frame — matching
`SessionAck` and `BatchAck` — and removes the workaround.

## Decision: hard cutover (v0.5)

- v0.5 wire only. The validator rejects `generation == 0`.
- The substitution code and its FIFO-substitution comments are deleted.
- No fallback path for v0.4.x servers. Safe because no production server
  currently emits `ServerHeartbeat` — only `recv_multiplexer_integration_test.go`
  constructs synthetic frames.
- Scope is proto + client + validator + tests. No server emitter wiring
  (testserver or production) lands in this change.

## Files touched

| File | Change |
|---|---|
| `proto/canyonroad/wtp/v1/wtp.proto:184-186` | Add `uint32 generation = 2;` to `ServerHeartbeat` |
| `proto/canyonroad/wtp/v1/wtp.pb.go` | Regenerated via `make proto` |
| `proto/canyonroad/wtp/v1/validate.go:368-374` | Reject `generation == 0` (in addition to existing nil check) |
| `proto/canyonroad/wtp/v1/validate_test.go:222-235` | Add zero-gen rejection case; update happy path to set `Generation` |
| `internal/store/watchtower/transport/recv_multiplexer.go:24-31, 44-50, 286-291` | Populate `ev.gen` from wire; delete heartbeat-substitution rationale |
| `internal/store/watchtower/transport/state_live.go:247-261` | Pass `ev.gen` to `applyAckFromRecv` and `inflight.Release` instead of `t.persistedAck.Generation` |
| `internal/store/watchtower/transport/state_replaying.go:77-81` | Same: `ev.gen` instead of `t.persistedAck.Generation` |
| `internal/store/watchtower/transport/recv_multiplexer_integration_test.go:103-114` | `recvHeartbeat(seq)` → `recvHeartbeat(gen, seq)`; update call sites |
| Other transport tests calling `recvHeartbeat` | Pass explicit gen at every call site |

The FIFO-order invariant on `eventCh` itself stays as a runtime guarantee.
Only the *heartbeat-substitution rationale* is removed from the comments.
Implementation step: grep `recv_multiplexer.go`, `state_live.go`,
`state_replaying.go` for other documented reasons FIFO order is load-bearing
(e.g., ordered processing of intermixed `BatchAck` + `PolicyPush`). If any
remain, leave a trimmed comment naming them; if none, delete the comments
cleanly.

## Data flow

**Before:**
server → `ServerHeartbeat{seq}` → recv goroutine emits
`recvAckEvent{kind: Heartbeat, gen: 0, seq}` → main goroutine substitutes
`t.persistedAck.Generation` → `applyAckFromRecv(persisted.gen, seq)`.

**After:**
server → `ServerHeartbeat{gen, seq}` → recv goroutine emits
`recvAckEvent{kind: Heartbeat, gen: wire, seq}` → main goroutine passes
`ev.gen` directly → `applyAckFromRecv(ev.gen, ev.seq)`.

The `recvAckEventHeartbeat` kind discriminator is retained — it still selects
different behavior from `recvAckEventBatchAck` (heartbeat doesn't drive
`inflight.Release` in `state_replaying`; in `state_live` it now releases with
the wire gen).

## Error handling

### Stateless validation

`ValidateServerHeartbeat` adds a zero-gen check returning:

```go
&ValidationError{
    Reason: ReasonUnknown,
    Inner:  fmt.Errorf("%w: server_heartbeat.generation must be > 0", ErrInvalidFrame),
}
```

Same error shape as the existing nil check. Routes through
`ClassifyAndIncInvalidFrame` at `recv_multiplexer.go:279` exactly like every
other invalid-frame failure.

### Stateful handling

No new logic. The heartbeat now feeds `applyAckFromRecv` with the same
`(gen, seq)` shape as `BatchAck`. Existing cross-generation handling
(regression detection, future-gen, replay-cursor anomaly) applies uniformly
to both event kinds.

### Inflight release semantic flip (highest-risk line)

`state_live.go:261` changes from
`inflight.Release(t.persistedAck.Generation, ev.seq)` to
`inflight.Release(ev.gen, ev.seq)`. This is a real semantic change:

- **Before:** a heartbeat could only release inflight at the persisted gen
  (because the wire carried no gen).
- **After:** a heartbeat carrying a higher gen drives the cross-gen release
  path.

This is the intended tightening — it was only impossible to express on the
wire before — but the implementation plan must include an explicit positive
test exercising this new code path.

## Testing

1. **`proto/canyonroad/wtp/v1/validate_test.go`**
   - `TestValidateServerHeartbeat_ZeroGeneration`: gen=0 returns
     `ErrInvalidFrame`-wrapped error.
   - Update `TestValidateServerHeartbeat_HappyPath` to include `Generation: 1`.

2. **`internal/store/watchtower/transport/recv_multiplexer_integration_test.go`**
   - Heartbeat with explicit wire gen propagates to dispatch: assert
     `ev.gen` equals the wire value (not zero, not persisted).

3. **New positive test in `state_live` or recv-mux integration**
   - Heartbeat with `gen > persistedAck.Generation` drives
     `applyAckFromRecv`'s cross-gen path and `inflight.Release(ev.gen, …)`.
     Confirms the old substitution wasn't masking a behavior we now want
     exposed.

4. **`internal/store/watchtower/transport/recv_multiplexer_failclosed_test.go`**
   - Extend with gen==0 case: heartbeat with zero gen triggers
     `ClassifyAndIncInvalidFrame` and fail-closed teardown.

5. **Existing tests using `recvHeartbeat(seq)`**
   - Each call site updates to pass the gen the surrounding assertion
     implicitly expected (usually the test's persisted gen). Mechanical.

## Migration

- v0.5 wire only. No staged rollout, no compat shim, no fallback.
- After merge, any `ServerHeartbeat` with `generation == 0` is rejected as an
  invalid frame.
- Safe because no production server emits `ServerHeartbeat` today — only
  test scaffolding does.
- `make proto` regenerates `wtp.pb.go` (uses `protoc` per `Makefile:32-45`).

## Non-goals

- Wiring `cmd/wtp-testserver` to emit heartbeats. (Belongs with whatever
  feature first needs heartbeats on the wire.)
- Production server-side emitter. (Same — out of scope until needed.)
- Any change to `BatchAck`, `SessionAck`, or other ack frames. They already
  carry generation.

## Out-of-band confirmations needed during implementation

- Confirm whether deleting the FIFO-substitution comment leaves any
  remaining behavior that depends on FIFO order for reasons unrelated to
  heartbeat gen. If yes, keep a trimmed-down comment explaining the
  remaining reason. If no, delete cleanly.
- Audit any test that observed `gen == 0` on a dispatched heartbeat event —
  those assertions invert under this change.
