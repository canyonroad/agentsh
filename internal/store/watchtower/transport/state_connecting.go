package transport

import (
	"context"
	"fmt"
	"log/slog"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// runConnecting establishes a stream and exchanges SessionInit/SessionAck.
// On success it returns StateReplaying. On dial failure or stream error it
// returns StateConnecting (the caller's run loop is responsible for backoff).
// On a server SessionAck rejection (accepted=false) or a programming error
// (e.g. SessionInit fails local validation) it returns StateShutdown — the
// session cannot recover from these via reconnect.
//
// Every error path calls conn.Close() (full teardown) rather than
// CloseSend() (half-close) so the underlying stream is fully released and
// no goroutines/sockets leak while the run loop backs off and retries.
func (t *Transport) runConnecting(ctx context.Context) (State, error) {
	init := t.sessionInit()
	if err := wtpv1.ValidateSessionInit(init.GetSessionInit()); err != nil {
		// Outbound self-check: this is a local construction bug
		// (Options misconfig, bookkeeping drift) — NOT a dropped
		// peer frame, so it does NOT increment
		// wtp_dropped_invalid_frame_total. That metric is scoped
		// to inbound peer traffic per its help text; mixing local
		// bugs into the same series would confuse alerting and
		// triage. The error is surfaced via the returned state
		// transition (StateShutdown); Transport.Err() carries the
		// wrapped detail for the caller's diagnostic log.
		return StateShutdown, fmt.Errorf("invalid SessionInit: %w", err)
	}

	conn, err := t.opts.Dialer.Dial(ctx)
	if err != nil {
		return StateConnecting, fmt.Errorf("dial: %w", err)
	}
	t.conn = conn

	if err := conn.Send(init); err != nil {
		_ = conn.Close()
		t.conn = nil
		return StateConnecting, fmt.Errorf("send SessionInit: %w", err)
	}

	msg, err := conn.Recv()
	if err != nil {
		_ = conn.Close()
		t.conn = nil
		return StateConnecting, fmt.Errorf("recv SessionAck: %w", err)
	}

	ack := msg.GetSessionAck()
	if ack == nil {
		_ = conn.Close()
		t.conn = nil
		return StateConnecting, fmt.Errorf("expected SessionAck, got %T", msg.Msg)
	}

	if !ack.GetAccepted() {
		t.rejectReason = ack.GetRejectReason()
		_ = conn.Close()
		t.conn = nil
		return StateShutdown, fmt.Errorf("session rejected: %s", ack.GetRejectReason())
	}

	t.ackSessionAck(ack)
	// NOTE: starting the recv goroutine has been moved to the Run
	// loop so RunOnce(StateConnecting) — used by transport-level
	// tests that drive a single state transition — does NOT leave a
	// live recvSession with no owner to call teardownRecv. Run owns
	// the lifecycle: it calls startRecv after runConnecting returns
	// successfully, and runReplaying / runLive own the matching
	// teardown. Per roborev Medium round-3.
	return StateReplaying, nil
}

// ackSessionAck dispatches a SessionAck's (generation, ack_high_watermark_seq)
// tuple through applyServerAckTuple and applies the side effects of the
// classified outcome per Task 15.1 Step 1b:
//
//   - AckOutcomeAnomaly: rate-limited WARN + IncAnomalousAck(reason); cursors
//     unchanged.
//   - AckOutcomeAdopted: persist via walMarkAckedFn; on failure roll BOTH
//     cursors back to their prior snapshot (lock-step with on-disk meta.json)
//     and log a WARN; on success emit SetAckHighWatermark.
//   - AckOutcomeResendNeeded: INFO + IncResendNeeded; persistedAck unchanged.
//   - AckOutcomeNoOp: silent.
func (t *Transport) ackSessionAck(ack *wtpv1.SessionAck) {
	serverGen := ack.GetGeneration()
	serverSeq := ack.GetAckHighWatermarkSeq()

	priorPersisted := t.persistedAck
	priorReplay := t.remoteReplayCursor
	priorPresent := t.persistedAckPresent

	outcome := t.applyServerAckTuple(serverGen, serverSeq)
	switch outcome.Kind {
	case AckOutcomeAnomaly:
		if t.ackAnomalyLimiter.Allow() {
			var (
				wtdHighSeq uint64
				wtdHighOK  bool
				wtdHighErr error
			)
			wtdHighSeq, wtdHighOK, wtdHighErr = t.walWrittenDataHighWaterFn(serverGen)
			attrs := []slog.Attr{
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
				"session_ack: anomalous server ack tuple", attrs...)
		}
		t.metrics.IncAnomalousAck(outcome.AnomalyReason)
	case AckOutcomeAdopted:
		if err := t.walMarkAckedFn(t.persistedAck.Generation, t.persistedAck.Sequence); err != nil {
			t.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
				"session_ack: wal.MarkAcked failed; rolling back ack cursors",
				slog.Uint64("attempted_seq", t.persistedAck.Sequence),
				slog.Uint64("attempted_gen", uint64(t.persistedAck.Generation)),
				slog.String("err", err.Error()),
				slog.String("session_id", t.opts.SessionID))
			t.persistedAck = priorPersisted
			t.remoteReplayCursor = priorReplay
			t.persistedAckPresent = priorPresent
			return
		}
		t.metrics.SetAckHighWatermark(int64(t.persistedAck.Sequence))
	case AckOutcomeResendNeeded:
		t.opts.Logger.LogAttrs(context.Background(), slog.LevelInfo,
			"session_ack: server ack tuple lower than persistedAck; remote replay cursor regressed",
			slog.Uint64("server_seq", serverSeq),
			slog.Uint64("server_gen", uint64(serverGen)),
			slog.Uint64("local_persisted_seq", t.persistedAck.Sequence),
			slog.Uint64("local_persisted_gen", uint64(t.persistedAck.Generation)),
			slog.String("session_id", t.opts.SessionID))
		t.metrics.IncResendNeeded()
	case AckOutcomeNoOp:
		// No cursor moved; nothing to do.
	}
}

// RunOnce runs a single state transition for testing. Production code
// should use Run, which loops until Shutdown. The error mirrors whatever
// the per-state handler surfaced so tests can assert on failure modes.
//
// Self-contained teardown: a successful runConnecting transition leaves
// t.conn set for the next state handler to consume; the production Run
// loop hands off ownership to runReplaying / runLive which own
// teardown. As a single-transition seam, RunOnce closes the conn (and
// tears down any in-flight recv session, though startRecv now runs in
// Run, not in runConnecting) before returning so callers do not
// inherit live resources with no owner. Per roborev Medium round-5.
func (t *Transport) RunOnce(ctx context.Context, st State) (State, error) {
	switch st {
	case StateConnecting:
		next, err := t.runConnecting(ctx)
		if next == StateReplaying {
			t.regressToConnecting()
		}
		return next, err
	default:
		return StateShutdown, nil
	}
}
