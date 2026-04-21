package transport

import (
	"context"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// LiveOptions configures the Live state's batcher and inflight window.
type LiveOptions struct {
	Batcher        BatcherOptions
	MaxInflight    int
	HeartbeatEvery time.Duration
}

// runLive consumes Reader notifications, batches records, and sends
// EventBatch messages while honoring the inflight window. Returns
// StateConnecting on stream error, StateShutdown on ctx cancellation.
//
// Reader lifecycle: like the StateReplaying case, the Live case OWNS its
// Reader. `defer rdr.Close()` ensures the Reader is unregistered from the
// WAL on EVERY exit path (stream error → StateConnecting, ctx cancellation
// → StateShutdown). Per `wal/reader.go` Reader.Close (near line 446),
// Close is what removes the Reader from `WAL.readers` so notifyReaders
// stops waking it; without it, every reconnect cycle would leak a
// registered Reader. The StateLive case in the Run loop creates a fresh
// Reader on each entry — readers are NOT reused across reconnect cycles.
//
// Conn lifecycle: matches runReplaying's invariant. Every exit path on
// a held Conn calls t.conn.Close() exactly once and clears
// t.conn = nil before returning, so the Run loop's next StateConnecting
// iteration starts with a fresh dial. ctx cancellation also closes +
// clears (StateShutdown still tears down the conn — the caller does
// not need to know whether runLive returned by error or by shutdown to
// know it owns no conn now). Round-6: prior to this fix the error
// returns left t.conn dangling, and the Run loop would then dial on
// top of a still-held conn reference on the next StateConnecting
// iteration.
func (t *Transport) runLive(ctx context.Context, rdr *wal.Reader, opts LiveOptions) (State, error) {
	defer rdr.Close()
	b := NewBatcher(opts.Batcher)
	tick := time.NewTicker(opts.Batcher.MaxAge / 2)
	defer tick.Stop()

	inflight := 0

	flush := func() error {
		batch := b.Drain()
		if batch == nil {
			return nil
		}
		msg, err := encodeBatchMessage(batch.Records)
		if err != nil {
			return err
		}
		if err := t.conn.Send(msg); err != nil {
			return fmt.Errorf("send EventBatch: %w", err)
		}
		inflight++
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			// ctx cancellation: caller (Run loop) decides whether to
			// shut down or reconnect. Close the conn so the next
			// StateConnecting iteration starts clean.
			_ = t.conn.Close()
			t.conn = nil
			return StateShutdown, ctx.Err()
		case ack := <-t.recvBatchAckCh:
			// Recv-multiplexer arm per sub-step 17.X (plan
			// §"Two-cursor ack clamp in BatchAck/ServerHeartbeat
			// handlers"). The recv goroutine pushes typed events
			// onto the channel; the apply happens here on the
			// main state-machine goroutine to preserve the
			// single-owner invariant for the cursor fields. Nil
			// channel until initRecvChannels has run — Go's nil-
			// channel semantics make this select arm dormant in
			// that case (blocks forever, never selected), which
			// is the desired behavior when no recv goroutine is
			// running.
			t.applyAckFromRecv("batch_ack", ack.gen, ack.seq)
		case <-t.heartbeatSignalCh:
			// Coalesced heartbeat signal: load the latest snapshot
			// from the atomic pointer (the recv goroutine
			// overwrites the pointer on every heartbeat, so older
			// pending events may have been silently dropped per
			// the round-6 typed-event backpressure policy table).
			// The recv goroutine emits gen=0 because
			// wtpv1.ServerHeartbeat carries no generation field on
			// the wire; substitute t.persistedAck.Generation here
			// so applyAckFromRecv classifies within the active
			// generation per spec §"Effective-ack tuple and clamp"
			// (heartbeat is treated as a watermark snapshot within
			// the active generation).
			if hb := t.latestHeartbeat.Load(); hb != nil {
				t.applyAckFromRecv("server_heartbeat", t.persistedAck.Generation, hb.seq)
			}
		case err := <-t.recvErrCh:
			// Recv goroutine surfaced a fatal stream error; tear
			// down the conn and regress to Connecting so the run
			// loop dials a fresh stream on the next iteration.
			_ = t.conn.Close()
			t.conn = nil
			return StateConnecting, fmt.Errorf("recv: %w", err)
		case <-rdr.Notify():
			// Pull as many records as the window and batcher allow.
			for inflight < opts.MaxInflight {
				rec, ok, err := rdr.TryNext()
				if err != nil {
					_ = t.conn.Close()
					t.conn = nil
					return StateConnecting, fmt.Errorf("reader: %w", err)
				}
				if !ok {
					break
				}
				if outBatch := b.Add(rec); outBatch != nil {
					msg, err := encodeBatchMessage(outBatch.Records)
					if err != nil {
						_ = t.conn.Close()
						t.conn = nil
						return StateConnecting, err
					}
					if err := t.conn.Send(msg); err != nil {
						_ = t.conn.Close()
						t.conn = nil
						return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
					}
					inflight++
				}
			}
		case now := <-tick.C:
			if outBatch := b.Tick(now); outBatch != nil {
				msg, err := encodeBatchMessage(outBatch.Records)
				if err != nil {
					_ = t.conn.Close()
					t.conn = nil
					return StateConnecting, err
				}
				if err := t.conn.Send(msg); err != nil {
					_ = t.conn.Close()
					t.conn = nil
					return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
				}
				inflight++
			}
		}
		_ = flush // explicit lint reference; called from Drain path
	}
}

// encodeBatchMessage packs WAL records into a wtpv1.EventBatch envelope.
func encodeBatchMessage(_ []wal.Record) (*wtpv1.ClientMessage, error) {
	// Stub — full encoding is integrated with chain/compact in Task 22.
	return &wtpv1.ClientMessage{}, nil
}
