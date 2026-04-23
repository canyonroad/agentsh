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

	// Per-connection recv channel handles. Captured into locals once at
	// the top of the loop so the select arms are dormant when the
	// recvSession has not been initialised (e.g. tests that drive
	// runLive with no dial). Go's nil-channel semantics make the
	// select arms block forever on a nil channel — exactly what we
	// want when no recv goroutine is running.
	var (
		recvEventCh <-chan recvAckEvent
		recvErrCh   <-chan error
	)
	if t.recv != nil {
		recvEventCh = t.recv.eventCh
		recvErrCh = t.recv.errCh
	}

	for {
		select {
		case <-ctx.Done():
			// ctx cancellation: caller (Run loop) decides whether to
			// shut down or reconnect. Tear down the recvSession (round-22
			// Finding 2) and the conn so the next StateConnecting
			// iteration starts clean.
			_ = t.conn.Close()
			t.teardownRecv()
			t.conn = nil
			return StateShutdown, ctx.Err()
		case sr := <-t.stopCh:
			// Task 19: orderly shutdown. runShutdown drains the
			// reader (best-effort, bounded by sr.drainDeadline),
			// flushes the batcher, and CloseSend's the conn.
			// Then full-tear down the conn + recvSession the same
			// way ctx-cancellation does so the run loop's
			// StateShutdown case returns nil with no leaked state.
			t.runShutdown(ctx, b, rdr, sr.drainDeadline)
			_ = t.conn.Close()
			t.teardownRecv()
			t.conn = nil
			close(sr.done)
			return StateShutdown, nil
		case ev := <-recvEventCh:
			// Recv-multiplexer arm per sub-step 17.X (plan §"Single
			// FIFO ack-event channel"; round-22 Finding 1). The recv
			// goroutine pushes typed events onto recv.eventCh in
			// strict wire order; the apply happens here on the main
			// state-machine goroutine to preserve the single-owner
			// invariant for the cursor fields. recvEventCh is nil
			// until t.recv is set — Go's nil-channel semantics make
			// this select arm dormant in that case.
			switch ev.kind {
			case recvAckEventBatchAck:
				t.applyAckFromRecv("batch_ack", ev.gen, ev.seq)
			case recvAckEventHeartbeat:
				// Heartbeat carries no gen on the wire; FIFO order on
				// eventCh guarantees any earlier BatchAck has already
				// advanced t.persistedAck.Generation, so substituting
				// here is safe (round-22 Finding 1 invariant).
				t.applyAckFromRecv("server_heartbeat", t.persistedAck.Generation, ev.seq)
			}
		case err := <-recvErrCh:
			// Recv goroutine surfaced a fatal stream error OR a fail-
			// closed unhandled control frame (round-22 Finding 4); tear
			// down the recvSession + conn and regress to Connecting so
			// the run loop dials a fresh stream on the next iteration.
			_ = t.conn.Close()
			t.teardownRecv()
			t.conn = nil
			return StateConnecting, fmt.Errorf("recv: %w", err)
		case <-rdr.Notify():
			// Pull as many records as the window and batcher allow.
			for inflight < opts.MaxInflight {
				rec, ok, err := rdr.TryNext()
				if err != nil {
					_ = t.conn.Close()
					t.teardownRecv()
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
						t.teardownRecv()
						t.conn = nil
						return StateConnecting, err
					}
					if err := t.conn.Send(msg); err != nil {
						_ = t.conn.Close()
						t.teardownRecv()
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
					t.teardownRecv()
					t.conn = nil
					return StateConnecting, err
				}
				if err := t.conn.Send(msg); err != nil {
					_ = t.conn.Close()
					t.teardownRecv()
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
