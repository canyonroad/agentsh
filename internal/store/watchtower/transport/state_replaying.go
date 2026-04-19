package transport

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
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
func (t *Transport) runReplaying(ctx context.Context, r *Replayer) (State, error) {
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			_ = t.conn.Close()
			t.conn = nil
			return StateConnecting, fmt.Errorf("replay batch: %w", err)
		}
		if len(batch.Records) > 0 {
			msg, err := buildEventBatchFn(batch.Records)
			if err != nil {
				_ = t.conn.Close()
				t.conn = nil
				return StateConnecting, fmt.Errorf("build EventBatch: %w", err)
			}
			if err := t.conn.Send(msg); err != nil {
				_ = t.conn.Close()
				t.conn = nil
				return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
			}
		}
		if done {
			return StateLive, nil
		}
	}
}

// RunReplaying is the public test seam for runReplaying. The full state-
// machine dispatch (calling runReplaying from RunOnce/Run alongside
// Connecting and Live handlers) is wired by Task 22 (Store integration);
// Task 16's scope is the per-state handler + Replayer mechanics, so this
// method exists to let transport tests drive runReplaying directly without
// running the full RunOnce dispatch table.
//
// IMPORTANT: production callers MUST replace buildEventBatchFn with a
// real builder before invoking RunReplaying — the default stub
// (buildEventBatchStub) returns an empty ClientMessage that would put
// invalid frames on the wire. Task 17 fills in the real wire format and
// Task 22 wires it up; until then, only tests should call RunReplaying
// directly, and they should either tolerate the stub's empty message or
// override buildEventBatchFn via setBuildEventBatchFnForTest.
func (t *Transport) RunReplaying(ctx context.Context, r *Replayer) (State, error) {
	return t.runReplaying(ctx, r)
}

// buildEventBatchFn is the function variable runReplaying calls to wrap
// WAL records into a wtpv1.EventBatch envelope. Defaults to the empty-
// message stub so the Replaying state machine can be exercised in tests.
// Task 17 (Live-state Batcher) and Task 22 (Store integration) replace
// this with the real builder before runReplaying is wired into the
// production run loop.
//
// Tests that need to assert against a non-empty wire format can override
// via setBuildEventBatchFnForTest (see state_replaying_internal_test.go);
// production code MUST NOT mutate this variable outside of the
// initialization performed by Task 22.
var buildEventBatchFn = buildEventBatchStub

// buildEventBatchStub is a no-op wire-format placeholder. Returns an empty
// ClientMessage so the Replaying state machine can be exercised in tests
// without depending on the unpublished EventBatch wire schema.
//
// TODO(Task 17): replace with the real builder that wraps records'
// payloads (already-serialized CompactEvent bytes) plus their (sequence,
// generation) and integrity records into a wtpv1.EventBatch envelope.
// Task 22 (Store integration) is responsible for the wiring that points
// buildEventBatchFn at the real implementation before the run loop ever
// reaches runReplaying in production.
func buildEventBatchStub(_ []wal.Record) (*wtpv1.ClientMessage, error) {
	return &wtpv1.ClientMessage{}, nil
}
