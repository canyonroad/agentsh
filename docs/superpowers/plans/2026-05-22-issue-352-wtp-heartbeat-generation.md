# Issue #352 — `ServerHeartbeat.generation` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `generation` to the `ServerHeartbeat` wire frame; hard-cutover the client to use the wire value; delete the FIFO-order substitution workaround.

**Architecture:** Single-PR surgical change in 8 tasks. Proto field add → validator tightening (reject `gen == 0`) → recv-multiplexer passthrough → state handlers stop substituting → comment cleanup → cross-compile + full test. Each task is TDD where it changes behavior, mechanical where it changes wiring.

**Tech Stack:** Go 1.21+, protoc-gen-go, standard `go test`. Spec: `docs/superpowers/specs/2026-05-22-issue-352-wtp-heartbeat-generation-design.md`.

---

## Pre-flight context (read once before starting)

The substitution being removed lives in three places. Recv-multiplexer pushes events with `gen=0` for heartbeats; both state handlers substitute `t.persistedAck.Generation` at apply time. The substitution is "safe only because FIFO order on `eventCh` guarantees any earlier `BatchAck` has already advanced `persistedAck.Generation`" (load-bearing comment at `recv_multiplexer.go:24-31`).

After this plan: the wire carries `(gen, seq)`, the client trusts the wire value, and the substitution code + its rationale comments are deleted. Validator rejects `generation == 0` outright — no v0.4.x compat fallback. Safe because no production server emits `ServerHeartbeat` today (only `recv_multiplexer_integration_test.go` constructs synthetic frames).

`Makefile:32-45` regenerates proto via `protoc`. Build/test commands per `CLAUDE.md`: `go build ./...`, `go test ./...`, `GOOS=windows go build ./...`.

---

## Task 1: Add `generation` field to `ServerHeartbeat` proto

**Files:**
- Modify: `proto/canyonroad/wtp/v1/wtp.proto:184-186`
- Regen: `proto/canyonroad/wtp/v1/wtp.pb.go`

- [ ] **Step 1: Edit the proto**

Change `proto/canyonroad/wtp/v1/wtp.proto:184-186` from:

```protobuf
message ServerHeartbeat {
  uint64 ack_high_watermark_seq = 1;
}
```

to:

```protobuf
message ServerHeartbeat {
  uint64 ack_high_watermark_seq = 1;
  uint32 generation             = 2;
}
```

- [ ] **Step 2: Regenerate the Go bindings**

Run: `make proto`
Expected: `wtp.pb.go` is regenerated, no errors. Diff shows a new `Generation uint32` field and `GetGeneration()` accessor on `*ServerHeartbeat`.

If `make proto` is unavailable in the environment, run the protoc invocation from `Makefile:32-45` directly.

- [ ] **Step 3: Verify the build still compiles**

Run: `go build ./...`
Expected: PASS. No callers reference the new field yet, so no test fails.

- [ ] **Step 4: Commit**

```bash
git add proto/canyonroad/wtp/v1/wtp.proto proto/canyonroad/wtp/v1/wtp.pb.go
git commit -m "wtp: add ServerHeartbeat.generation field (#352)"
```

---

## Task 2: Tighten `ValidateServerHeartbeat` to reject `generation == 0` (TDD)

**Files:**
- Test: `proto/canyonroad/wtp/v1/validate_test.go:222-237`
- Modify: `proto/canyonroad/wtp/v1/validate.go:366-376`

- [ ] **Step 1: Write the failing test for zero-gen rejection**

Append to `proto/canyonroad/wtp/v1/validate_test.go` (after the existing `TestValidateServerHeartbeat_HappyPath`):

```go
func TestValidateServerHeartbeat_ZeroGeneration(t *testing.T) {
	err := ValidateServerHeartbeat(&ServerHeartbeat{
		AckHighWatermarkSeq: 42,
		Generation:          0,
	})
	if err == nil {
		t.Fatal("ValidateServerHeartbeat(gen=0): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Reason != ReasonHeartbeatGenerationInvalid {
		t.Fatalf("err = %v; want *ValidationError with Reason=%q", err, ReasonHeartbeatGenerationInvalid)
	}
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("err = %v; want errors.Is(ErrInvalidFrame) true", err)
	}
}
```

- [ ] **Step 2: Update the happy-path test to set `Generation`**

Change `proto/canyonroad/wtp/v1/validate_test.go:233-237` from:

```go
func TestValidateServerHeartbeat_HappyPath(t *testing.T) {
	if err := ValidateServerHeartbeat(&ServerHeartbeat{AckHighWatermarkSeq: 42}); err != nil {
		t.Errorf("ValidateServerHeartbeat: %v", err)
	}
}
```

to:

```go
func TestValidateServerHeartbeat_HappyPath(t *testing.T) {
	if err := ValidateServerHeartbeat(&ServerHeartbeat{
		AckHighWatermarkSeq: 42,
		Generation:          1,
	}); err != nil {
		t.Errorf("ValidateServerHeartbeat: %v", err)
	}
}
```

- [ ] **Step 3: Run tests — expect zero-gen test to FAIL**

Run: `go test ./proto/canyonroad/wtp/v1/ -run TestValidateServerHeartbeat -v`
Expected: `TestValidateServerHeartbeat_ZeroGeneration` FAILS with "want error, got nil"; the other two heartbeat tests PASS.

- [ ] **Step 4: Implement the validator change**

Change `proto/canyonroad/wtp/v1/validate.go:366-376` from:

```go
// ValidateServerHeartbeat rejects a nil ServerHeartbeat. No other
// stateless invariants apply.
func ValidateServerHeartbeat(hb *ServerHeartbeat) error {
	if hb == nil {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: server_heartbeat is nil", ErrInvalidFrame),
		}
	}
	return nil
}
```

to:

```go
// ValidateServerHeartbeat returns ReasonHeartbeatGenerationInvalid
// when the inbound ServerHeartbeat has generation == 0 (issue #352:
// generation is REQUIRED in WTP v0.5; no prior server version emitted
// ServerHeartbeat, so there is no compat path for unset generation).
// Returns ReasonUnknown for nil.
func ValidateServerHeartbeat(hb *ServerHeartbeat) error {
	if hb == nil {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: server_heartbeat is nil", ErrInvalidFrame),
		}
	}
	if hb.Generation == 0 {
		return &ValidationError{
			Reason: ReasonHeartbeatGenerationInvalid,
			Inner:  fmt.Errorf("%w: server_heartbeat.generation must be > 0", ErrInvalidFrame),
		}
	}
	return nil
}
```

- [ ] **Step 5: Run tests — expect all heartbeat tests to PASS**

Run: `go test ./proto/canyonroad/wtp/v1/ -run TestValidateServerHeartbeat -v`
Expected: all three tests PASS.

- [ ] **Step 6: Run the full validator test suite to catch regressions**

Run: `go test ./proto/canyonroad/wtp/v1/...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add proto/canyonroad/wtp/v1/validate.go proto/canyonroad/wtp/v1/validate_test.go
git commit -m "wtp: validator rejects ServerHeartbeat with generation=0 (#352)"
```

---

## Task 3: Wire heartbeat `gen` through recv-multiplexer (TDD via integration test)

**Files:**
- Modify: `internal/store/watchtower/transport/recv_multiplexer_integration_test.go:103-114, 173-186`
- Modify: `internal/store/watchtower/transport/recv_multiplexer.go:24-31, 286-291`

This task atomically updates the integration test expectation (heartbeat events now carry the wire gen, not zero) and the recv-mux code that produces them.

- [ ] **Step 1: Update the `recvHeartbeat` helper signature**

Change `internal/store/watchtower/transport/recv_multiplexer_integration_test.go:103-114` from:

```go
// recvHeartbeat is a one-line constructor for a ServerHeartbeat server
// message. The proto carries no generation field; the recv multiplexer
// substitutes t.persistedAck.Generation at apply time.
func recvHeartbeat(seq uint64) *wtpv1.ServerMessage {
	return &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_ServerHeartbeat{
			ServerHeartbeat: &wtpv1.ServerHeartbeat{
				AckHighWatermarkSeq: seq,
			},
		},
	}
}
```

to:

```go
// recvHeartbeat is a one-line constructor for a ServerHeartbeat server
// message. Generation is REQUIRED on the wire in WTP v0.5 (issue #352);
// the recv multiplexer surfaces it directly without substitution.
func recvHeartbeat(gen uint32, seq uint64) *wtpv1.ServerMessage {
	return &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_ServerHeartbeat{
			ServerHeartbeat: &wtpv1.ServerHeartbeat{
				AckHighWatermarkSeq: seq,
				Generation:          gen,
			},
		},
	}
}
```

- [ ] **Step 2: Update integration-test push table to expect wire gen**

Change `internal/store/watchtower/transport/recv_multiplexer_integration_test.go:173-186` from:

```go
	// Wire-order push: BatchAck(1, 100), HB(99), BatchAck(1, 200), HB(150).
	// Heartbeats keep gen=0 on the wire (the multiplexer leaves it zero
	// and substitutes at apply time on the main goroutine).
	pushSeq := []struct {
		frame string
		gen   uint32
		seq   uint64
		msg   *wtpv1.ServerMessage
	}{
		{"batch_ack", 1, 100, recvBatchAck(1, 100)},
		{"server_heartbeat", 0, 99, recvHeartbeat(99)},
		{"batch_ack", 1, 200, recvBatchAck(1, 200)},
		{"server_heartbeat", 0, 150, recvHeartbeat(150)},
	}
```

to:

```go
	// Wire-order push: BatchAck(1, 100), HB(1, 99), BatchAck(1, 200), HB(1, 150).
	// Per issue #352, ServerHeartbeat now carries generation on the wire;
	// the multiplexer surfaces it directly without substitution.
	pushSeq := []struct {
		frame string
		gen   uint32
		seq   uint64
		msg   *wtpv1.ServerMessage
	}{
		{"batch_ack", 1, 100, recvBatchAck(1, 100)},
		{"server_heartbeat", 1, 99, recvHeartbeat(1, 99)},
		{"batch_ack", 1, 200, recvBatchAck(1, 200)},
		{"server_heartbeat", 1, 150, recvHeartbeat(1, 150)},
	}
```

- [ ] **Step 3: Run the integration test — expect FAIL**

Run: `go test ./internal/store/watchtower/transport/ -run TestRecvMultiplexer.*Integration -v`
Expected: FAILS on the heartbeat gen assertion (`event[1] gen: got 0, want 1`) because the multiplexer is still emitting `ev.gen = 0`.

- [ ] **Step 4: Update the recv-multiplexer dispatch**

Change `internal/store/watchtower/transport/recv_multiplexer.go:286-291` from:

```go
			h := m.ServerHeartbeat
			ev := recvAckEvent{
				kind: recvAckEventHeartbeat,
				// gen left zero; main substitutes t.persistedAck.Generation
				// at apply time per the FIFO-order invariant.
				seq: h.GetAckHighWatermarkSeq(),
			}
```

to:

```go
			h := m.ServerHeartbeat
			ev := recvAckEvent{
				kind: recvAckEventHeartbeat,
				gen:  h.GetGeneration(),
				seq:  h.GetAckHighWatermarkSeq(),
			}
```

- [ ] **Step 5: Update the `recvAckEventHeartbeat` doc comment**

Change `internal/store/watchtower/transport/recv_multiplexer.go:24-31` from:

```go
	// recvAckEventHeartbeat wraps a *wtpv1.ServerMessage_ServerHeartbeat
	// demux. Only seq is populated from the wire frame; gen is zero
	// because the proto carries no generation field. The main goroutine
	// substitutes t.persistedAck.Generation at apply time — safe ONLY
	// because strict FIFO order on eventCh guarantees any earlier
	// BatchAck has already been processed (and may have advanced
	// t.persistedAck.Generation) before this heartbeat reaches the
	// dispatch site. See round-22 Finding 1.
	recvAckEventHeartbeat
```

to:

```go
	// recvAckEventHeartbeat wraps a *wtpv1.ServerMessage_ServerHeartbeat
	// demux. gen + seq are populated from the wire frame (issue #352);
	// the discriminator distinguishes heartbeats from BatchAcks because
	// state handlers apply different inflight/release semantics.
	recvAckEventHeartbeat
```

- [ ] **Step 6: Run the integration test — expect PASS**

Run: `go test ./internal/store/watchtower/transport/ -run TestRecvMultiplexer.*Integration -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/transport/recv_multiplexer.go internal/store/watchtower/transport/recv_multiplexer_integration_test.go
git commit -m "wtp: recv multiplexer carries ServerHeartbeat.generation from wire (#352)"
```

---

## Task 4: Drop substitution in `state_live`; add cross-gen heartbeat test (TDD)

**Files:**
- Test: `internal/store/watchtower/transport/recv_multiplexer_test.go` (new test added to the existing `Heartbeat_advancing_returns_Adopted` neighborhood around line 704)
- Modify: `internal/store/watchtower/transport/state_live.go:247-266`

- [ ] **Step 1: Write the failing cross-gen heartbeat test**

Find the existing `t.Run("Heartbeat_advancing_returns_Adopted", ...` block at `internal/store/watchtower/transport/recv_multiplexer_test.go:704`. Add a sibling subtest immediately after the closing brace of that `t.Run`:

```go
	t.Run("Heartbeat_with_higher_gen_applies_wire_gen", func(t *testing.T) {
		// Issue #352: ServerHeartbeat now carries generation on the
		// wire. applyAckFromRecv MUST be driven with the wire gen, not
		// the persisted gen — otherwise a heartbeat that follows a
		// roll-up to gen+1 (where the BatchAck that advanced the
		// generation was dropped) would be silently mis-applied at the
		// old generation.
		env := newClampTestEnv(t, Options{
			InitialAckTuple: &AckTuple{Sequence: 50, Generation: 1, Present: true},
		})
		SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
		appendDataInGen(t, env.w, 1, 2, 100)

		got := env.tr.applyAckFromRecv("server_heartbeat", 2, 80)
		if got != AckOutcomeAdopted {
			t.Fatalf("applyAckFromRecv outcome: got %v, want AckOutcomeAdopted", got)
		}
		if persisted := PersistedAckForTest(env.tr); persisted.Generation != 2 {
			t.Fatalf("persistedAck.Generation: got %d, want 2 (cross-gen adopt)", persisted.Generation)
		}
	})
```

- [ ] **Step 2: Run the new test — expect PASS (sanity check, since the test calls `applyAckFromRecv` directly with wire gen)**

Run: `go test ./internal/store/watchtower/transport/ -run Heartbeat_with_higher_gen -v`
Expected: PASS. This test pins the unit-level contract that `applyAckFromRecv` already handles cross-gen acks correctly — it documents the *behavior* the state-handler change below will start exercising in production.

(If the test FAILS, stop: the `applyAckFromRecv` cross-gen path itself is broken and the design assumption — "no new stateful logic" — is wrong. Surface this finding before continuing.)

- [ ] **Step 3: Update `state_live.go` to pass `ev.gen` through**

Change `internal/store/watchtower/transport/state_live.go:247-266` from:

```go
			case recvAckEventHeartbeat:
				// Heartbeat carries no gen on the wire; FIFO order on
				// eventCh guarantees any earlier BatchAck has already
				// advanced t.persistedAck.Generation, so substituting
				// here is safe (round-22 Finding 1 invariant).
				//
				// Heartbeats use the SAME ack clamp as BatchAck and
				// may carry an ack advance when a BatchAck was
				// missed (per spec). Release every covered batch on
				// an Adopted heartbeat — otherwise the sender would
				// wedge at MaxInflight until reconnect (roborev
				// Medium round-4).
				outcome := t.applyAckFromRecv("server_heartbeat", t.persistedAck.Generation, ev.seq)
				if outcome == AckOutcomeAdopted {
					inflight.Release(t.persistedAck.Generation, ev.seq)
					if err := drainAvailable(); err != nil {
						teardownForReconnect()
						return StateConnecting, err
					}
				}
```

to:

```go
			case recvAckEventHeartbeat:
				// Heartbeats use the SAME ack clamp as BatchAck and
				// may carry an ack advance when a BatchAck was
				// missed (per spec). Release every covered batch on
				// an Adopted heartbeat — otherwise the sender would
				// wedge at MaxInflight until reconnect (roborev
				// Medium round-4).
				outcome := t.applyAckFromRecv("server_heartbeat", ev.gen, ev.seq)
				if outcome == AckOutcomeAdopted {
					inflight.Release(ev.gen, ev.seq)
					if err := drainAvailable(); err != nil {
						teardownForReconnect()
						return StateConnecting, err
					}
				}
```

- [ ] **Step 4: Run state_live and recv-mux tests**

Run: `go test ./internal/store/watchtower/transport/ -run "TestRecvMultiplexer|TestRunLive|TestState_?[Ll]ive" -v`
Expected: PASS. Verified via pre-flight grep: no test other than the integration test (already updated in Task 3) constructs a `ServerHeartbeat` frame and feeds it through the recv goroutine; the direct `applyAckFromRecv("server_heartbeat", ...)` test sites (`recv_multiplexer_test.go:388, 428, 714`) all pass an explicit gen and are unaffected by this change.

- [ ] **Step 5: Run the full transport test suite**

Run: `go test ./internal/store/watchtower/transport/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/transport/state_live.go internal/store/watchtower/transport/recv_multiplexer_test.go
git commit -m "wtp: state_live uses ev.gen for heartbeat ack/release (#352)"
```

---

## Task 5: Drop substitution in `state_replaying`

**Files:**
- Modify: `internal/store/watchtower/transport/state_replaying.go:77-82`

- [ ] **Step 1: Update `state_replaying.go`**

Change `internal/store/watchtower/transport/state_replaying.go:77-82` from:

```go
			case recvAckEventHeartbeat:
				// Heartbeat carries no gen on the wire; FIFO order
				// guarantees any earlier BatchAck has already
				// advanced t.persistedAck.Generation.
				t.applyAckFromRecv("server_heartbeat", t.persistedAck.Generation, ev.seq)
			}
```

to:

```go
			case recvAckEventHeartbeat:
				// Heartbeat carries gen on the wire (issue #352);
				// pass it through directly. Unlike state_live, no
				// inflight.Release here — runReplaying is draining,
				// not sending.
				t.applyAckFromRecv("server_heartbeat", ev.gen, ev.seq)
			}
```

- [ ] **Step 2: Run state_replaying tests**

Run: `go test ./internal/store/watchtower/transport/ -run "TestState_?[Rr]eplaying|TestRunReplaying" -v`
Expected: PASS. Same reasoning as Task 4 Step 4: no test outside the integration test constructs a heartbeat frame and feeds it through the recv goroutine in replaying state.

- [ ] **Step 3: Run the full transport test suite**

Run: `go test ./internal/store/watchtower/transport/...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/store/watchtower/transport/state_replaying.go
git commit -m "wtp: state_replaying uses ev.gen for heartbeat ack (#352)"
```

---

## Task 6: Add fail-closed test for `generation == 0` heartbeat

**Files:**
- Test: `internal/store/watchtower/transport/recv_multiplexer_failclosed_test.go` (append after the last existing test)

- [ ] **Step 1: Write the fail-closed test**

Append to `internal/store/watchtower/transport/recv_multiplexer_failclosed_test.go`:

```go
// TestRecvMultiplexer_FailClosedHeartbeatZeroGeneration verifies that a
// ServerHeartbeat with generation=0 (an invalid v0.5 frame per issue
// #352) is rejected by ValidateServerHeartbeat, drives the errCh
// sentinel, and tears down the recv session. The frame is
// schema-valid (the wire decoded cleanly) but semantically invalid —
// classified as ReasonHeartbeatGenerationInvalid / ErrInvalidFrame.
func TestRecvMultiplexer_FailClosedHeartbeatZeroGeneration(t *testing.T) {
	fc := newRecvFakeConn()
	tr, _ := newFailClosedTransport(t, fc, false)

	msg := &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_ServerHeartbeat{
			ServerHeartbeat: &wtpv1.ServerHeartbeat{
				AckHighWatermarkSeq: 42,
				// Generation deliberately omitted (zero value).
			},
		},
	}
	if err := driveFailClosed(t, tr, fc, msg); err == nil {
		t.Fatal("expected errCh sentinel after fail-closed zero-gen heartbeat")
	}
}
```

- [ ] **Step 2: Run the test — expect PASS (validator already enforces this from Task 2)**

Run: `go test ./internal/store/watchtower/transport/ -run TestRecvMultiplexer_FailClosedHeartbeatZeroGeneration -v`
Expected: PASS. This test is regression-protection for the wire/validator integration.

- [ ] **Step 3: Commit**

```bash
git add internal/store/watchtower/transport/recv_multiplexer_failclosed_test.go
git commit -m "wtp: fail-closed test for zero-generation ServerHeartbeat (#352)"
```

---

## Task 7: FIFO-rationale comment audit + cleanup

**Files:**
- Audit and possibly modify: `internal/store/watchtower/transport/recv_multiplexer.go:44-50, 77`

The eventCh FIFO comment block at `recv_multiplexer.go:44-50` reads:

```go
// Wire-ordering invariant (round-22 Finding 1, load-bearing): events on
// eventCh are processed in strict FIFO order on the main goroutine. The
// recv goroutine pushes them in receive order; the main goroutine
// selects one at a time and runs applyAckFromRecv to completion before
// pulling the next. The heartbeat-generation substitution rule (see
// recvAckEventHeartbeat) depends on this invariant — any change to the
// recv-event ordering MUST be reviewed against the substitution rule.
```

The heartbeat-substitution rule is gone. Audit whether anything else in the transport depends on strict FIFO order on `eventCh`.

- [ ] **Step 1: Audit FIFO dependents**

Run: `grep -rn "FIFO\|recvAckEvent\|eventCh" internal/store/watchtower/transport/ | grep -v _test.go`

Read every match. Look for code that depends on strict ordering between `BatchAck`, `Heartbeat`, and `PolicyPush` events on `eventCh`. Examples of what would still be load-bearing: any apply-time logic that requires the *last* BatchAck of a gen to land before a subsequent event; any clamp logic that walks generations forward and would mis-clamp under reordering.

- [ ] **Step 2A (if no remaining dependent): delete the FIFO comment**

If the audit finds no remaining FIFO dependent, replace `recv_multiplexer.go:44-50`:

```go
// Wire-ordering invariant (round-22 Finding 1, load-bearing): events on
// eventCh are processed in strict FIFO order on the main goroutine. The
// recv goroutine pushes them in receive order; the main goroutine
// selects one at a time and runs applyAckFromRecv to completion before
// pulling the next. The heartbeat-generation substitution rule (see
// recvAckEventHeartbeat) depends on this invariant — any change to the
// recv-event ordering MUST be reviewed against the substitution rule.
```

with:

```go
// Events on eventCh are processed in receive order on the main
// goroutine: the recv goroutine pushes in receive order; the main
// goroutine selects one at a time and runs applyAckFromRecv to
// completion before pulling the next.
```

- [ ] **Step 2B (if dependents remain): trim the comment to name them**

If the audit finds remaining dependents, replace the comment with a version that names the specific reasons FIFO is still load-bearing and removes the heartbeat-substitution sentence. Example shape:

```go
// Wire-ordering invariant: events on eventCh are processed in strict
// FIFO order on the main goroutine. The recv goroutine pushes them in
// receive order; the main goroutine selects one at a time and runs
// applyAckFromRecv to completion before pulling the next. Load-bearing
// for: <list the specific reasons found in the audit>.
```

- [ ] **Step 3: Verify the comment at line 77 still reads sensibly**

Check `recv_multiplexer.go:77`:

```go
// eventCh carries demuxed BatchAck and ServerHeartbeat events in
```

…and read the surrounding paragraph. If it references the substitution rationale, trim it; if it only describes the channel mechanics, leave it.

- [ ] **Step 4: Run the full transport test suite**

Run: `go test ./internal/store/watchtower/transport/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/transport/recv_multiplexer.go
git commit -m "wtp: drop heartbeat-substitution rationale from FIFO comments (#352)"
```

---

## Task 8: Cross-compile + full test suite verification

**Files:** none modified.

- [ ] **Step 1: Linux build**

Run: `go build ./...`
Expected: PASS.

- [ ] **Step 2: Windows cross-compile (per CLAUDE.md)**

Run: `GOOS=windows go build ./...`
Expected: PASS.

- [ ] **Step 3: Full test suite**

Run: `go test ./...`
Expected: PASS.

If `TestFlushLoop_PeriodicSync` (internal/store) or `TestStore_*EmitsTransportLossOnWire` family flakes on Linux/Windows CI, that is pre-existing and unrelated to this change (per memory `project_flushloop_windows_flake.md` and `project_wtp_transportloss_flakes.md`). Re-run once; if still flaky, note in the PR description and proceed — do NOT chase those flakes here.

- [ ] **Step 4: Manual diff sanity check**

Run: `git log --oneline main..HEAD` and review each commit.
Expected: 7 focused commits (Tasks 1, 2, 3, 4, 5, 6, 7 each produced one — Task 8 has no commit).

- [ ] **Step 5: Run roborev between tasks per project preference**

(See memory `feedback_roborev_between_tasks.md`.) The plan is complete; the user typically runs roborev at this point. No commit from this step.

---

## Done criteria

- `ServerHeartbeat.generation` exists on the wire (Task 1).
- Validator rejects `generation == 0` with `ErrInvalidFrame` (Task 2).
- Recv multiplexer surfaces wire gen on `recvAckEvent` (Task 3).
- `state_live` and `state_replaying` no longer reference `t.persistedAck.Generation` on the heartbeat path (Tasks 4, 5).
- A fail-closed test pins the zero-gen rejection at the wire boundary (Task 6).
- The FIFO-substitution rationale comments are gone or trimmed (Task 7).
- `go build ./...`, `GOOS=windows go build ./...`, and `go test ./...` all pass (Task 8).
