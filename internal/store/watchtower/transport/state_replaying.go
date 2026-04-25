package transport

import (
	"context"
	"fmt"
)

// runReplaying drains the WAL via the supplied Replayer and ships records
// in EventBatch messages over the conn that the Connecting state opened.
// On success it returns StateLive (and t.conn is RETAINED — the Live state
// handler picks up the same conn for ongoing batch sends). On any error
// path (Replayer error, build error, send error, ctx cancellation) it
// closes t.conn and clears it before returning StateConnecting so the
// run loop reconnects on the next iteration with a fresh dial.
//
// Lifecycle invariant matches runConnecting (state_connecting.go): every
// error path on a held Conn calls Close() exactly once (the full-teardown
// primitive — never CloseSend(), which is the half-close that would leave
// the underlying stream open and leak resources during reconnect backoff).
//
// ctx cancellation is surfaced as the wrapped Replayer error and treated
// the same as any other replay failure: conn is torn down, state regresses
// to Connecting, and the run loop owns whether to retry or shut down.
//
// PRODUCTION-BLOCKED — recv multiplexer not yet wired. The spec at
// docs/superpowers/specs/2026-04-18-wtp-client-design.md:565 requires
// stateReplaying to process inbound BatchAck, ServerHeartbeat,
// SessionUpdate, and Goaway concurrently with replay completion. This
// implementation only loops over NextBatch and Send — it has NO recv
// branch, so any inbound control frame that arrives during a long replay
// would be dropped (or, depending on the gRPC stream's buffer, would
// stall the receive side). Task 17 (Live state Batcher) and Task 18
// (heartbeat) introduce the shared recv goroutine + multiplexer that
// runReplaying will plug into. Until then, runReplaying MUST NOT be
// wired into the production run loop.
//
// The unexport of runReplaying is an EXTERNAL-CALL-SITE GUARD, not a
// compile-time guarantee:
//   - Callers OUTSIDE the internal/store/watchtower/transport package
//     CANNOT reach runReplaying without going through a future RunOnce
//     dispatch table that Task 22 will add (and which will gate
//     Replaying behind the recv loop landing in Task 17/18).
//   - Callers INSIDE the transport package CAN still call runReplaying
//     directly — Go's package-level visibility does not prevent this.
//     Production wiring inside the transport package (Task 22's Run
//     loop) MUST gate the call behind the recv-multiplexer plumbing
//     that Tasks 17/18 introduce. See the updated Task 22 Run-loop
//     snippet in docs/superpowers/plans/2026-04-18-wtp-client.md
//     "Task 16 — Deferred to Task 17/18", which makes that dependency
//     structural (the snippet visibly cannot work without Task 17/18
//     landing first).
//
// The exported test seam RunReplayingForTest lives in
// state_replaying_internal_test.go (compiled out of the production
// binary) so external transport_test callers can still drive the
// per-state handler in isolation.
func (t *Transport) runReplaying(ctx context.Context, r *Replayer) (State, error) {
	// Per-connection recv channel handles, captured once per loop entry.
	// Nil-channel semantics make the drain arms dormant when t.recv is
	// not set (tests that exercise runReplaying without a dial).
	var (
		recvEventCh <-chan recvAckEvent
		recvErrCh   <-chan error
	)
	if t.recv != nil {
		recvEventCh = t.recv.eventCh
		recvErrCh = t.recv.errCh
	}
	for {
		// Drain any pending recv-multiplexer events before issuing the
		// next NextBatch. Per sub-step 17.X (plan §"Single FIFO ack-
		// event channel"; round-22 Finding 1) the recv goroutine
		// pushes typed events onto recv.eventCh in strict wire order;
		// the apply happens on the main state-machine goroutine to
		// preserve the single-owner invariant for the cursor fields.
		// Non-blocking drain so the replay loop never stalls waiting
		// on the recv side; recvEventCh is nil when t.recv is unset,
		// in which case Go's nil-channel semantics keep the drain
		// arms inert and the default arm fires immediately. Recv-
		// error handling: if the recv goroutine surfaced a fatal
		// stream error OR a fail-closed unhandled control frame
		// (round-22 Finding 4), tear down the recvSession + conn and
		// regress to Connecting on the same iteration.
		select {
		case ev := <-recvEventCh:
			switch ev.kind {
			case recvAckEventBatchAck:
				t.applyAckFromRecv("batch_ack", ev.gen, ev.seq)
			case recvAckEventHeartbeat:
				// Heartbeat carries no gen on the wire; FIFO order
				// guarantees any earlier BatchAck has already
				// advanced t.persistedAck.Generation.
				t.applyAckFromRecv("server_heartbeat", t.persistedAck.Generation, ev.seq)
			}
		case err := <-recvErrCh:
			_ = t.conn.Close()
			t.teardownRecv()
			t.conn = nil
			return StateConnecting, fmt.Errorf("recv: %w", err)
		case sr := <-t.stopCh:
			// Task 19: Stop during replay aborts in-flight replay
			// immediately (no drain — we have no batcher to flush).
			// CloseSend signals the server; Close + teardown matches
			// the recv-error path's full-teardown semantics so the
			// run loop's StateShutdown case returns nil with no
			// leaked conn/recv state.
			_ = t.conn.CloseSend()
			_ = t.conn.Close()
			t.teardownRecv()
			t.conn = nil
			close(sr.done)
			return StateShutdown, nil
		default:
			// No recv events pending; fall through to the next
			// NextBatch iteration.
		}
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			_ = t.conn.Close()
			t.teardownRecv()
			t.conn = nil
			return StateConnecting, fmt.Errorf("replay batch: %w", err)
		}
		if len(batch.Records) > 0 {
			msg, err := buildEventBatchFn(batch.Records)
			if err != nil {
				_ = t.conn.Close()
				t.teardownRecv()
				t.conn = nil
				return StateConnecting, fmt.Errorf("build EventBatch: %w", err)
			}
			if err := t.conn.Send(msg); err != nil {
				_ = t.conn.Close()
				t.teardownRecv()
				t.conn = nil
				return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
			}
		}
		if done {
			return StateLive, nil
		}
	}
}

// buildEventBatchFn is the function variable runReplaying calls to wrap
// WAL records into a wtpv1.EventBatch envelope. Defaults to the empty-
// message stub so the Replaying state machine can be exercised in tests.
// Task 17 (Live-state Batcher) and Task 22 (Store integration) replace
// this with the real builder before runReplaying is wired into the
// production run loop. Until then, in addition to the stub-builder
// hazard, runReplaying is missing the recv multiplexer required by the
// spec (see runReplaying header) — both gaps are addressed by Task
// 17/18, and runReplaying remains unexported so production callers
// outside the transport package cannot reach it.
//
// Tests that need to assert against a non-empty wire format can override
// via setBuildEventBatchFnForTest (see state_replaying_internal_test.go);
// production code MUST NOT mutate this variable outside of the
// initialization performed by Task 22.
// buildEventBatchFn is the function variable runReplaying calls to wrap
// WAL records into a wtpv1.EventBatch envelope. Defaults to
// encodeBatchMessage so the Live and Replaying states share one
// implementation — both flows wrap already-marshaled CompactEvents
// into an UncompressedEvents body with matching (from_sequence,
// to_sequence, generation) metadata.
//
// Tests that need to assert against a custom wire shape can override
// via setBuildEventBatchFnForTest (see state_replaying_internal_test.go).
// Production code MUST NOT mutate this variable.
var buildEventBatchFn = encodeBatchMessage
