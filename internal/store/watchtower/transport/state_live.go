package transport

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
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
		msg, err := encodeBatchMessageFn(batch.Records)
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
				if rec.Kind == wal.RecordLoss {
					// Pre-Task-13 temporary path: log + drop. See
					// filterDataRecords (state_replaying.go) for the full
					// rationale; the encoder fail-loud contract requires
					// callers to keep loss markers out of EventBatch.
					t.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
						"wtp: dropping wal.RecordLoss marker pending TransportLoss (Task 13) carrier",
						slog.String("caller_state", "live"),
						slog.Uint64("loss_generation", uint64(rec.Generation)),
						slog.Uint64("loss_from_seq", rec.Loss.FromSequence),
						slog.Uint64("loss_to_seq", rec.Loss.ToSequence),
						slog.String("loss_reason", rec.Loss.Reason),
						slog.String("session_id", t.opts.SessionID))
					continue
				}
				if outBatch := b.Add(rec); outBatch != nil {
					msg, err := encodeBatchMessageFn(outBatch.Records)
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
				msg, err := encodeBatchMessageFn(outBatch.Records)
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

// encodeBatchMessageFn packs WAL records into a wtpv1.EventBatch envelope.
// Declared as a package-level variable (not a plain function) so tests
// that drive the Live state with raw non-CompactEvent payloads can
// swap in a stub via SetEncodeBatchMessageFnForTest without needing to
// produce real marshaled CompactEvent bytes.
var encodeBatchMessageFn = encodeBatchMessage

// encodeBatchMessage is the production EventBatch encoder. It unmarshals
// each data record's wal.Record.Payload (already the marshaled
// CompactEvent bytes the Store produced) into a *wtpv1.CompactEvent and
// wraps the slice in an UncompressedEvents body.
//
// Loss markers (wal.RecordLoss) MUST NOT be smuggled inside an
// UncompressedEvents batch — the dedicated TransportLoss message flow
// (Task 13) is the only safe carrier. Until that path lands, this
// encoder fails LOUD on RecordLoss rather than silently stripping the
// marker and emitting a partial batch: a silent strip is an integrity
// gap (Replayer.NextBatch is documented to surface every loss marker
// verbatim — see replayer.go), so dropping one would mask WAL overflow
// / CRC-corruption notices the server relies on. Callers in Live,
// Replaying, and Shutdown already treat an encoder error as a fatal-
// for-this-stream condition and regress to Connecting; that loud
// failure is the right posture until Task 13 wires TransportLoss.
//
// from_sequence / to_sequence / generation reflect the first and last
// data record. Compression is COMPRESSION_NONE because we send raw
// CompactEvents; zstd/gzip is a post-MVP enhancement.
func encodeBatchMessage(records []wal.Record) (*wtpv1.ClientMessage, error) {
	events := make([]*wtpv1.CompactEvent, 0, len(records))
	var (
		fromSeq uint64
		toSeq   uint64
		gen     uint32
		seenOne bool
	)
	for _, rec := range records {
		if rec.Kind == wal.RecordLoss {
			return nil, fmt.Errorf("encodeBatchMessage: RecordLoss marker (gen=%d) cannot be encoded into an UncompressedEvents batch; TransportLoss carrier (Task 13) is required", rec.Generation)
		}
		if rec.Kind != wal.RecordData {
			continue
		}
		ce := &wtpv1.CompactEvent{}
		if err := proto.Unmarshal(rec.Payload, ce); err != nil {
			return nil, fmt.Errorf("encodeBatchMessage: unmarshal record seq=%d: %w", rec.Sequence, err)
		}
		events = append(events, ce)
		if !seenOne {
			fromSeq = rec.Sequence
			gen = rec.Generation
			seenOne = true
		}
		toSeq = rec.Sequence
	}
	batch := &wtpv1.EventBatch{
		FromSequence: fromSeq,
		ToSequence:   toSeq,
		Generation:   gen,
		Compression:  wtpv1.Compression_COMPRESSION_NONE,
		Body: &wtpv1.EventBatch_Uncompressed{
			Uncompressed: &wtpv1.UncompressedEvents{Events: events},
		},
	}
	return &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{EventBatch: batch},
	}, nil
}
