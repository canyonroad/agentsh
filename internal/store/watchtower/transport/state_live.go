package transport

import (
	"context"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

// encoderMetrics is the metrics collector the encoder uses to record
// loss-marker bookkeeping (currently: wtp_loss_unknown_reason_total).
// Test seam — production wiring sets this from transport.New.
var encoderMetrics *metrics.WTPMetrics

// SetEncoderEmitExtendedReasons is a retained no-op kept for binary
// compatibility with test code that was written against the old
// package-level flag. The encoder now reads EmitExtendedLossReasons from
// transport.Options (per-Transport) so the package-level bool is no
// longer consulted. Callers that previously relied on this setter to
// control encoder behavior must set transport.Options.EmitExtendedLossReasons
// instead (threaded via watchtower.Options.EmitExtendedLossReasons).
//
// Deprecated: use transport.Options.EmitExtendedLossReasons.
func SetEncoderEmitExtendedReasons(_ bool) {}

// isExtendedReason reports whether the wire enum is one of the six
// reasons added in the 2026-04-27 spec. OVERFLOW and CRC_CORRUPTION
// return false — they're always emitted regardless of the flag.
func isExtendedReason(r wtpv1.TransportLossReason) bool {
	switch r {
	case wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE,
		wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_MAPPER,
		wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP,
		wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8,
		wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW,
		wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC:
		return true
	default:
		return false
	}
}

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

	// Track outstanding batch boundaries by (gen, seq) so a single
	// coalesced BatchAck releases every covered batch — a counter
	// that decrements by one per ack would stall the send path
	// against any conforming server that batches acknowledgements
	// (roborev Medium round-3).
	var inflight inflightTracker

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
			drainErr := t.runShutdown(ctx, b, rdr, sr.drainDeadline)
			_ = t.conn.Close()
			t.teardownRecv()
			t.conn = nil
			close(sr.done)
			if drainErr != nil {
				return StateShutdown, drainErr
			}
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
				outcome := t.applyAckFromRecv("batch_ack", ev.gen, ev.seq)
				// Release every pending batch whose high-watermark is
				// at or below the adopted ack — a coalesced BatchAck
				// can cover several Sends, and decrementing by one
				// would stall the send path. Anomaly / ResendNeeded /
				// NoOp acks are NOT a release event (cursor did not
				// advance); the rolled-back-Adopted path also returns
				// NoOp from applyAckFromRecv so it is correctly
				// excluded here.
				if outcome == AckOutcomeAdopted {
					inflight.Release(ev.gen, ev.seq)
				}
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
				}
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
			for inflight.Len() < opts.MaxInflight {
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
					msgs, err := encodeBatchMessageFn(outBatch.Records, t.emitExtendedLossReasons)
					if err != nil {
						_ = t.conn.Close()
						t.teardownRecv()
						t.conn = nil
						return StateConnecting, err
					}
					for _, msg := range msgs {
						if err := t.conn.Send(msg); err != nil {
							_ = t.conn.Close()
							t.teardownRecv()
							t.conn = nil
							return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
						}
						t.logEmittedLossIfApplicable(ctx, msg)
						gen, seq := extractWireHighWatermark(msg)
						inflight.Push(gen, seq)
					}
				}
			}
		case now := <-tick.C:
			// Gate the tick-driven flush on available inflight
			// capacity. Without this gate the tick path would send
			// an aged batch even when inflight.Len() ==
			// opts.MaxInflight, allowing one extra unacked batch
			// onto the wire. The Notify path's overshoot scenario:
			// b.Add(rec) flushes a full batch (inflight.Push), but
			// the same Add buffers `rec` as the start of a new
			// batch in b.pending; if the window now equals
			// MaxInflight, the next tick.C arm would still flush
			// that fresh batch (roborev Medium round-6).
			//
			// Records stay in b.pending across ticks until the
			// window opens (a BatchAck releases capacity); the
			// next tick after release flushes them. b.Tick is
			// idempotent on full pending — calling it later with
			// the same MaxAge boundary already crossed still
			// returns the buffered batch.
			if inflight.Len() < opts.MaxInflight {
				if outBatch := b.Tick(now); outBatch != nil {
					msgs, err := encodeBatchMessageFn(outBatch.Records, t.emitExtendedLossReasons)
					if err != nil {
						_ = t.conn.Close()
						t.teardownRecv()
						t.conn = nil
						return StateConnecting, err
					}
					for _, msg := range msgs {
						if err := t.conn.Send(msg); err != nil {
							_ = t.conn.Close()
							t.teardownRecv()
							t.conn = nil
							return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
						}
						t.logEmittedLossIfApplicable(ctx, msg)
						gen, seq := extractWireHighWatermark(msg)
						inflight.Push(gen, seq)
					}
				}
			}
		}
	}
}

// encodeBatchMessageFn packs WAL records into wtpv1.ClientMessage slices.
// Declared as a package-level variable (not a plain function) so tests
// that drive the Live state with raw non-CompactEvent payloads can
// swap in a stub via SetEncodeBatchMessageFnForTest without needing to
// produce real marshaled CompactEvent bytes.
//
// The second parameter emitExtended controls whether extended-reason
// TransportLoss frames are emitted or silently dropped; callers pass
// their per-Transport flag captured at run-state entry so a global flag
// mutation in another test goroutine cannot affect an in-progress encode.
var encodeBatchMessageFn = func(records []wal.Record, emitExtended bool) ([]*wtpv1.ClientMessage, error) {
	return encodeBatchMessage(records, emitExtended)
}

// extractWireHighWatermark returns the (generation, to_sequence) of a
// ClientMessage carrying either an EventBatch or a TransportLoss. The
// inflight tracker keys both frame types by this tuple — a BatchAck
// retiring entries up to (gen, ack_high) covers both kinds uniformly.
func extractWireHighWatermark(msg *wtpv1.ClientMessage) (uint32, uint64) {
	switch m := msg.Msg.(type) {
	case *wtpv1.ClientMessage_EventBatch:
		return m.EventBatch.Generation, m.EventBatch.ToSequence
	case *wtpv1.ClientMessage_TransportLoss:
		return m.TransportLoss.Generation, m.TransportLoss.ToSequence
	default:
		return 0, 0
	}
}

// encodeBatchMessage walks `records` linearly, packing consecutive
// RecordData into EventBatch ClientMessages and emitting one
// TransportLoss ClientMessage per RecordLoss. Total wire order is
// preserved: a records list of [data, data, loss, data] produces three
// frames in order: EventBatch, TransportLoss, EventBatch.
//
// emitExtended controls whether extended TransportLoss reasons are
// emitted or silently dropped. Callers capture this value from the
// per-Transport EmitExtendedLossReasons field at the start of each run
// state so a concurrent test mutation of a package-level flag cannot
// affect an in-progress encode.
//
// On encountering a RecordLoss whose Reason has no wire enum mapping
// (ToWireReason returns ok=false): the marker is DROPPED, an ERROR is
// logged, and wtp_loss_unknown_reason_total is incremented.
// UNSPECIFIED is never emitted on the wire (it is wire-incompatible per
// the proto's TRANSPORT_LOSS_REASON_UNSPECIFIED contract). The
// exhaustiveness CI test (loss_reason_exhaustiveness_test.go) prevents
// this from happening for known wal.LossReason* constants; this branch
// exists for defense in depth.
//
// Compression is COMPRESSION_NONE on every EventBatch (zstd/gzip is
// post-MVP). TransportLoss has no body; just (from, to, gen, reason).
func encodeBatchMessage(records []wal.Record, emitExtended bool) ([]*wtpv1.ClientMessage, error) {
	var msgs []*wtpv1.ClientMessage

	var (
		curEvents  []*wtpv1.CompactEvent
		curFromSeq uint64
		curToSeq   uint64
		curGen     uint32
		curSeen    bool
	)

	flushData := func() {
		if !curSeen {
			return
		}
		batch := &wtpv1.EventBatch{
			FromSequence: curFromSeq,
			ToSequence:   curToSeq,
			Generation:   curGen,
			Compression:  wtpv1.Compression_COMPRESSION_NONE,
			Body: &wtpv1.EventBatch_Uncompressed{
				Uncompressed: &wtpv1.UncompressedEvents{Events: curEvents},
			},
		}
		msgs = append(msgs, &wtpv1.ClientMessage{
			Msg: &wtpv1.ClientMessage_EventBatch{EventBatch: batch},
		})
		curEvents = nil
		curSeen = false
	}

	for _, rec := range records {
		switch rec.Kind {
		case wal.RecordLoss:
			flushData()
			wireReason, ok := ToWireReason(rec.Loss.Reason)
			if !ok {
				if encoderMetrics != nil {
					encoderMetrics.IncWTPLossUnknownReason(1)
				}
				continue
			}
			if !emitExtended && isExtendedReason(wireReason) {
				// Spec §"Configuration": extended reasons are gated. Drop the
				// marker; OVERFLOW/CRC_CORRUPTION fall through this branch
				// because isExtendedReason returns false for them.
				continue
			}
			tl := &wtpv1.TransportLoss{
				FromSequence: rec.Loss.FromSequence,
				ToSequence:   rec.Loss.ToSequence,
				Generation:   rec.Loss.Generation,
				Reason:       wireReason,
			}
			msgs = append(msgs, &wtpv1.ClientMessage{
				Msg: &wtpv1.ClientMessage_TransportLoss{TransportLoss: tl},
			})
		case wal.RecordData:
			ce := &wtpv1.CompactEvent{}
			if err := proto.Unmarshal(rec.Payload, ce); err != nil {
				return nil, fmt.Errorf("encodeBatchMessage: unmarshal record seq=%d: %w", rec.Sequence, err)
			}
			curEvents = append(curEvents, ce)
			if !curSeen {
				curFromSeq = rec.Sequence
				curGen = rec.Generation
				curSeen = true
			}
			curToSeq = rec.Sequence
		default:
			// Skip unknown record kinds (forward compat).
		}
	}
	flushData()
	return msgs, nil
}
