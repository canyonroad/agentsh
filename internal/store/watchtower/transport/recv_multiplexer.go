package transport

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// recvBatchAck is the typed event the recv goroutine emits onto
// t.recvBatchAckCh when it demuxes a *wtpv1.ServerMessage_BatchAck frame.
// Carries the (gen, seq) tuple the main state-machine goroutine feeds into
// applyAckFromRecv.
type recvBatchAck struct {
	gen uint32
	seq uint64
}

// recvServerHeartbeat is the typed event the recv goroutine emits via the
// coalescing latestHeartbeat atomic.Pointer. The wire-format
// *wtpv1.ServerHeartbeat carries only ack_high_watermark_seq, so the
// goroutine emits gen=0 here; the main goroutine substitutes
// t.persistedAck.Generation at apply-time per the spec §"Effective-ack
// tuple and clamp" (heartbeat is treated as a watermark snapshot within
// the active generation).
type recvServerHeartbeat struct {
	gen uint32
	seq uint64
	at  time.Time
}

// runRecv is the recv-goroutine loop. It calls t.conn.Recv() repeatedly,
// demuxes the inbound *wtpv1.ServerMessage frame into typed events, and
// pushes each event onto the appropriate channel per the round-6 typed-event
// backpressure policy table:
//
//   - recvBatchAck → blocking send on t.recvBatchAckCh (depth 1). A BatchAck
//     carries durability-advancing data; dropping one would silently regress
//     the local ack watermark. If the main goroutine is wedged longer than
//     the heartbeat-deadline window the protocol is already broken, and the
//     blocking send is the correct backpressure signal.
//   - recvServerHeartbeat → coalescing via t.latestHeartbeat (atomic
//     pointer overwrite) plus a non-blocking trySend on t.heartbeatSignalCh
//     (depth 1). Heartbeats are idempotent over the watermark snapshot, so
//     older pending heartbeats may be silently overwritten by newer ones.
//
// The recv goroutine MUST NOT touch t.persistedAck / t.remoteReplayCursor
// / t.persistedAckPresent directly (single-owner invariant per
// transport.go:76-77 and plan §"Concurrency boundary for ack-cursor
// updates"). All cursor mutations happen on the main goroutine via
// applyAckFromRecv.
//
// runRecv exits on:
//   - ctx cancellation (via the inner Recv blocking on the conn's stream
//     ctx, which is cancelled by Run when transitioning out of Live)
//   - any non-nil error from t.conn.Recv() (stream closed by the peer or
//     by Close); the main goroutine notices via the recvErrCh signal
func (t *Transport) runRecv(ctx context.Context) {
	for {
		// Bail if the parent context has been cancelled. The conn.Recv()
		// call below will also unblock once Close() is called on the conn,
		// but checking ctx first avoids one extra Recv attempt on shutdown.
		select {
		case <-ctx.Done():
			return
		default:
		}
		msg, err := t.conn.Recv()
		if err != nil {
			// Surface the error through the dedicated channel so the main
			// goroutine can transition to Connecting on the next select
			// iteration. The channel has depth 1 + non-blocking trySend
			// because only the FIRST recv error matters for transition
			// purposes — subsequent errors during the wind-down are
			// redundant.
			select {
			case t.recvErrCh <- err:
			default:
			}
			return
		}
		switch m := msg.GetMsg().(type) {
		case *wtpv1.ServerMessage_BatchAck:
			a := m.BatchAck
			ev := recvBatchAck{gen: a.GetGeneration(), seq: a.GetAckHighWatermarkSeq()}
			// Blocking send per the round-6 typed-event backpressure table.
			select {
			case t.recvBatchAckCh <- ev:
			case <-ctx.Done():
				return
			}
		case *wtpv1.ServerMessage_ServerHeartbeat:
			h := m.ServerHeartbeat
			// ServerHeartbeat carries no generation field on the wire;
			// the main goroutine substitutes t.persistedAck.Generation at
			// apply-time. We still pass the seq through this typed event
			// so the coalescing semantics stay consistent.
			t.latestHeartbeat.Store(&recvServerHeartbeat{
				gen: 0,
				seq: h.GetAckHighWatermarkSeq(),
				at:  time.Now(),
			})
			select {
			case t.heartbeatSignalCh <- struct{}{}:
			default:
				// Main goroutine has not drained the previous signal yet;
				// the latestHeartbeat pointer already reflects the new
				// snapshot. No-op per the coalescing policy.
			}
		default:
			// Frame types other than BatchAck/ServerHeartbeat are not
			// handled by this multiplexer (Goaway/SessionUpdate land in
			// later tasks). Drop them silently for now — they are not
			// ack-bearing and do not regress any cursor.
		}
	}
}

// applyAckFromRecv is the recv-side wrapper around applyServerAckTuple.
// It is invoked from the main state-machine goroutine when a typed
// recvBatchAck or recvServerHeartbeat event surfaces on the recv channel;
// the recv goroutine NEVER touches t.persistedAck / t.remoteReplayCursor
// / t.persistedAckPresent directly (single-owner invariant per plan §
// "Concurrency boundary for ack-cursor updates").
//
// `frame` is the proto frame name ("batch_ack" / "server_heartbeat") used
// in the anomaly WARN's structured log so operators can tell which frame
// type drove the anomaly. SessionAck logs through the ackSessionAck site
// directly (with frame="session_ack") — same side-effect contract,
// inlined there for the anomaly-WARN/rejectReason interleave.
//
// Round-8 — the four-branch dispatch matches Task 15.1 Step 1b. The
// Adopted branch is the ONLY one that calls walMarkAckedFn + emits
// the gauge; ResendNeeded logs INFO and regresses remoteReplayCursor
// only; Anomaly logs WARN and leaves both cursors unchanged; NoOp
// is silent.
func (t *Transport) applyAckFromRecv(frame string, serverGen uint32, serverSeq uint64) {
	// Snapshot BOTH cursors before the helper mutates — required for
	// rollback on Adopted-then-MarkAcked-failure per Task 15.1 Step 1b.5.
	priorPersisted := t.persistedAck
	priorReplay := t.remoteReplayCursor
	priorPresent := t.persistedAckPresent

	outcome := t.applyServerAckTuple(serverGen, serverSeq)
	switch outcome.Kind {
	case AckOutcomeAnomaly:
		if t.ackAnomalyLimiter.Allow() {
			// Per spec §"Acknowledgement model": True anomaly. FIVE
			// disjoint sub-cases discriminated by outcome.AnomalyReason
			// (round-12 expansion of round-11's four-case taxonomy).
			// Log the FULL cursor context so operators can diagnose
			// without log correlation. Round-12: emit the per-generation
			// data-bearing high-water (`wal_written_data_high_seq`)
			// instead of the global `HighWaterSequence()` because the
			// unified predicate compares against
			// `WrittenDataHighWater(serverGen)`.
			var (
				wtdHighSeq uint64
				wtdHighOK  bool
				wtdHighErr error
			)
			wtdHighSeq, wtdHighOK, wtdHighErr = t.walWrittenDataHighWaterFn(serverGen)
			attrs := []slog.Attr{
				slog.String("frame", frame),
				slog.String("reason", outcome.AnomalyReason),
				slog.Uint64("server_seq", serverSeq),
				slog.Uint64("server_gen", uint64(serverGen)),
				slog.Uint64("local_persisted_seq", t.persistedAck.Sequence),
				slog.Uint64("local_persisted_gen", uint64(t.persistedAck.Generation)),
				slog.Uint64("wal_written_data_high_seq", wtdHighSeq),
				slog.Bool("wal_written_data_high_ok", wtdHighOK),
				slog.String("session_id", t.opts.SessionID),
			}
			if wtdHighErr != nil {
				attrs = append(attrs, slog.String("wal_written_data_high_err", wtdHighErr.Error()))
			}
			t.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
				"ack: anomalous server ack tuple", attrs...)
		}
		t.metrics.IncAnomalousAck(outcome.AnomalyReason)
		// Cursors unchanged; nothing more to do.
	case AckOutcomeAdopted:
		// persistedAck advanced; persist to WAL and emit metric.
		if err := t.walMarkAckedFn(t.persistedAck.Generation, t.persistedAck.Sequence); err != nil {
			// Persistence failed: roll back BOTH cursors so the in-memory
			// mirrors stay in lock-step with the on-disk meta.json.
			t.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
				"ack: wal.MarkAcked failed; rolling back ack cursors",
				slog.String("frame", frame),
				slog.Uint64("attempted_seq", t.persistedAck.Sequence),
				slog.Uint64("attempted_gen", uint64(t.persistedAck.Generation)),
				slog.String("err", err.Error()),
				slog.String("session_id", t.opts.SessionID))
			t.persistedAck = priorPersisted
			t.remoteReplayCursor = priorReplay
			t.persistedAckPresent = priorPresent
			// Server will re-deliver this watermark on the next BatchAck
			// or ServerHeartbeat. No metric emission on the failure path.
			return
		}
		t.metrics.SetAckHighWatermark(int64(t.persistedAck.Sequence))
	case AckOutcomeResendNeeded:
		// remoteReplayCursor moved within the SAME generation;
		// persistedAck unchanged; do NOT call walMarkAckedFn. Log INFO
		// so operators can see the server is stale relative to local
		// persistence (gradual rollout / partition recovery within a
		// generation — normal, not anomalous). Cross-generation
		// ResendNeeded is impossible under the same-gen scope (Task
		// 15.1 / Finding 1 narrowing): cross-gen tuples take the
		// Anomaly branch above. Bump the wtp_resend_needed_total
		// counter so an unusual rate of legitimate same-gen
		// regressions is visible to operators.
		t.metrics.IncResendNeeded()
		t.opts.Logger.LogAttrs(context.Background(), slog.LevelInfo,
			"ack: server ack tuple lower than persistedAck within same generation; remote replay cursor regressed",
			slog.String("frame", frame),
			slog.Uint64("server_seq", serverSeq),
			slog.Uint64("server_gen", uint64(serverGen)),
			slog.Uint64("local_persisted_seq", t.persistedAck.Sequence),
			slog.Uint64("local_persisted_gen", uint64(t.persistedAck.Generation)),
			slog.String("session_id", t.opts.SessionID))
	case AckOutcomeNoOp:
		// No cursor moved; nothing to do.
	}
}

// initRecvChannels lazily allocates the recv-multiplexer channels and the
// coalescing latestHeartbeat pointer. Called by runConnecting on the first
// successful dial so the channels are ready before runReplaying / runLive
// start their main-goroutine selects.
//
// The channels are owned by the main goroutine; the recv goroutine only
// sends. Channel depths are per the round-6 typed-event backpressure table:
// recvBatchAckCh is depth 1 with blocking send (BatchAck carries durability
// data); heartbeatSignalCh is depth 1 with non-blocking trySend (heartbeats
// are idempotent and coalesced via the atomic pointer); recvErrCh is depth
// 1 with non-blocking trySend (only the first recv error matters).
func (t *Transport) initRecvChannels() {
	if t.recvBatchAckCh == nil {
		t.recvBatchAckCh = make(chan recvBatchAck, 1)
	}
	if t.heartbeatSignalCh == nil {
		t.heartbeatSignalCh = make(chan struct{}, 1)
	}
	if t.recvErrCh == nil {
		t.recvErrCh = make(chan error, 1)
	}
	if t.latestHeartbeat == nil {
		t.latestHeartbeat = &atomic.Pointer[recvServerHeartbeat]{}
	}
}
