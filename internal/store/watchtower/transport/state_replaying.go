package transport

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// runReplaying drains the WAL via the supplied Replayer and ships records
// in EventBatch messages over the conn that the Connecting state opened.
// On success it returns StateLive. On a Send/Replayer error it returns
// StateConnecting so the caller's run loop reconnects (the run loop owns
// backoff and conn teardown — runReplaying does NOT close t.conn here, the
// Connecting handler will overwrite it on the next attempt).
//
// ctx cancellation propagates through the Replayer; if NextBatch returns a
// ctx error we surface it so the run loop can decide whether to shut down
// or retry.
func (t *Transport) runReplaying(ctx context.Context, r *Replayer) (State, error) {
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			return StateConnecting, fmt.Errorf("replay batch: %w", err)
		}
		if len(batch.Records) > 0 {
			msg, err := buildEventBatch(batch.Records)
			if err != nil {
				return StateConnecting, fmt.Errorf("build EventBatch: %w", err)
			}
			if err := t.conn.Send(msg); err != nil {
				return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
			}
		}
		if done {
			return StateLive, nil
		}
	}
}

// buildEventBatch wraps WAL records into a wtpv1.EventBatch envelope. The
// records' payloads are the already-serialized CompactEvent bytes; we just
// re-pack them with their (sequence, generation) and integrity records.
//
// Stub: Task 17 fills in the real wire format. Today this returns an empty
// ClientMessage so the Replaying state machine can be exercised in tests
// without depending on the unpublished batch wire schema.
func buildEventBatch(_ []wal.Record) (*wtpv1.ClientMessage, error) {
	return &wtpv1.ClientMessage{}, nil
}
