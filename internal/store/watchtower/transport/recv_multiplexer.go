package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode"
	"unicode/utf8"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// recvAckEventKind discriminates between the two ack-bearing wire frames
// the recv goroutine demuxes onto recvSession.eventCh per the round-22
// single-FIFO design (plan §"Single FIFO ack-event channel").
type recvAckEventKind int

const (
	// recvAckEventBatchAck wraps a *wtpv1.ServerMessage_BatchAck demux.
	// gen + seq are populated from the wire frame.
	recvAckEventBatchAck recvAckEventKind = iota + 1
	// recvAckEventHeartbeat wraps a *wtpv1.ServerMessage_ServerHeartbeat
	// demux. Only seq is populated from the wire frame; gen is zero
	// because the proto carries no generation field. The main goroutine
	// substitutes t.persistedAck.Generation at apply time — safe ONLY
	// because strict FIFO order on eventCh guarantees any earlier
	// BatchAck has already been processed (and may have advanced
	// t.persistedAck.Generation) before this heartbeat reaches the
	// dispatch site. See round-22 Finding 1.
	recvAckEventHeartbeat
)

// recvAckEvent is the single tagged-union event type the recv goroutine
// pushes onto recvSession.eventCh. The kind discriminator selects the
// dispatch on the main goroutine; gen/seq carry the ack tuple.
//
// Wire-ordering invariant (round-22 Finding 1, load-bearing): events on
// eventCh are processed in strict FIFO order on the main goroutine. The
// recv goroutine pushes them in receive order; the main goroutine
// selects one at a time and runs applyAckFromRecv to completion before
// pulling the next. The heartbeat-generation substitution rule (see
// recvAckEventHeartbeat) depends on this invariant — any change to the
// recv-event ordering MUST be reviewed against the substitution rule.
type recvAckEvent struct {
	kind recvAckEventKind
	gen  uint32
	seq  uint64
}

// recvSession bundles all per-connection recv-multiplexer state per
// the round-22 plan §"Per-connection recv state". A new instance is
// created on each successful dial and discarded when the conn tears
// down. The fields are non-nil for the lifetime of the connection;
// Transport.recv points at the live session OR is nil (when no recv
// goroutine is running, e.g. between connections or in tests that
// drive applyAckFromRecv directly without a dial).
//
// Per-connection ctx + cancelFn is the load-bearing piece for round-22
// Finding 2: cancelling this ctx unblocks the recv goroutine's
// blocking send on eventCh even when the transport-wide ctx is still
// alive (e.g. StateLive→StateConnecting transition after a stream
// error — only this connection is dead, not the transport).
type recvSession struct {
	ctx      context.Context
	cancelFn context.CancelFunc
	// eventCh carries demuxed BatchAck and ServerHeartbeat events in
	// strict wire order. Depth 4 absorbs steady-state burstiness; the
	// recv goroutine blocks on send when the channel is full and
	// unblocks via ctx cancellation. Single-channel-FIFO design per
	// round-22 Finding 1.
	eventCh chan recvAckEvent
	// errCh surfaces fatal recv errors (stream closed by peer, OR
	// fail-closed for unhandled control frames per round-22 Finding 4).
	// Depth 1 with non-blocking trySend because only the FIRST recv
	// error matters for the state-machine transition; subsequent
	// errors during the wind-down are redundant.
	errCh chan error
	// done is closed by runRecv right before it returns. teardownRecv
	// waits on it so callers can rely on the recv goroutine being fully
	// stopped (and no longer reading t.conn) once teardownRecv returns.
	// This is the synchronisation primitive that prevents data races on
	// t.conn between the recv goroutine and the main state-machine
	// goroutine when it dials a fresh conn after teardown (round-22
	// Finding 2 — the per-connection ctx cancel + done close together
	// give a fully synchronous teardown).
	done chan struct{}
}

// newRecvSession constructs a recvSession bound to the given parent ctx.
// The session's ctx is a child of parent — cancelling either cancels
// both, so a transport-wide shutdown propagates AND a per-connection
// teardown can unblock the recv goroutine without touching the parent.
func newRecvSession(parent context.Context) *recvSession {
	ctx, cancelFn := context.WithCancel(parent)
	return &recvSession{
		ctx:      ctx,
		cancelFn: cancelFn,
		eventCh:  make(chan recvAckEvent, 4),
		errCh:    make(chan error, 1),
		done:     make(chan struct{}),
	}
}

// teardownRecv cancels the per-connection recv ctx, waits for the recv
// goroutine to fully exit (closing rs.done), and clears the live session
// reference. Idempotent — safe to call from every state-exit path; a
// nil t.recv is a no-op so the helper can run even when no recv
// goroutine is active.
//
// The wait on rs.done is load-bearing for round-22 Finding 2: callers
// (state_live, state_replaying, integration tests) reassign t.conn
// after teardown returns, and the recv goroutine reads t.conn via
// t.conn.Recv(). Without the wait, the goroutine could still be in
// flight inside Recv() when the next dial overwrites t.conn — a data
// race the race detector catches.
//
// Caller-ordering contract (load-bearing): ctx cancellation alone does
// NOT unblock t.conn.Recv() — the conn's underlying transport (gRPC
// stream, fake test conn, etc.) only returns from Recv when (a) a frame
// arrives, (b) Recv hits a stream error, or (c) the conn is Closed.
// Therefore callers MUST close t.conn BEFORE calling teardownRecv (so
// the in-flight Recv unblocks and the goroutine signals done). Closing
// the conn AFTER teardownRecv would deadlock — the wait would never
// return because Recv stays blocked. State-handler exit paths follow
// this order: t.conn.Close() first, then teardownRecv(), then
// t.conn = nil.
func (t *Transport) teardownRecv() {
	if t.recv == nil {
		return
	}
	rs := t.recv
	t.recv = nil
	rs.cancelFn()
	<-rs.done
}

// startRecv constructs a recvSession bound to the given parent context
// and starts the runRecv goroutine. Called by runConnecting on a
// successful (accepted) SessionAck so that runReplaying / runLive can
// consume BatchAck, ServerHeartbeat, Goaway, and stream-error events
// via the recvSession channels. Paired one-to-one with teardownRecv on
// every conn-close exit path.
//
// Preconditions: t.conn is set; t.recv is nil. The latter is enforced
// by the run-loop lifecycle — every state-handler exit path that
// closes the conn calls teardownRecv (which sets t.recv = nil) before
// the loop re-enters runConnecting, so a clean entry to runConnecting
// always sees t.recv == nil.
func (t *Transport) startRecv(parent context.Context) {
	rs := newRecvSession(parent)
	t.recv = rs
	go t.runRecv(rs)
}

// runRecv is the recv-goroutine loop. It calls t.conn.Recv() repeatedly,
// demuxes the inbound *wtpv1.ServerMessage frame into a tagged-union
// recvAckEvent, and pushes the event onto rs.eventCh in strict wire
// order. Heartbeats are NOT coalesced — they share the channel with
// BatchAck events to preserve the ordering invariant (plan §"Single
// FIFO ack-event channel"; round-22 Finding 1).
//
// The recv goroutine MUST NOT touch t.persistedAck / t.remoteReplayCursor
// / t.persistedAckPresent directly (single-owner invariant per plan
// §"Concurrency boundary for ack-cursor updates"). All cursor mutations
// happen on the main goroutine via applyAckFromRecv.
//
// Fail-closed for unhandled control frames (round-22 Finding 4): a
// *wtpv1.ServerMessage_Goaway or *wtpv1.ServerMessage_ServerUpdate
// pushes a fatal error onto rs.errCh and returns. Tasks 18/19/20 will
// replace these with real handlers; until then the staging path
// surfaces them so the main goroutine drops back to Connecting
// instead of silently dropping a session-critical control frame.
//
// Unknown frame types (anything not in the switch) take a separate
// fail-closed branch — the proto-evolution defence: a future server
// may add control frames the client predates, and silently dropping
// them risks correctness.
//
// runRecv exits on:
//   - rs.ctx cancellation (per-connection cancel; round-22 Finding 2)
//   - any non-nil error from t.conn.Recv() (stream closed by peer)
//   - any unhandled control frame or unknown frame type (fail-closed)
//
// WARN-VOLUME POLICY (Task 22d): the three fail-closed branches each
// emit ONE WARN per occurrence — no rate-limiting, no dedup. This is
// intentional. Each fail-closed return tears the connection down and
// drops the run loop back to Connecting, which exponentially backs
// off (200ms → 30s) before the next dial. The reconnect backoff IS
// the rate limiter for upstream WARN volume: a server stuck in a
// Goaway/ServerUpdate/unknown-frame loop produces at most one WARN
// per backoff interval (~one per 30s in steady state once the
// backoff cap kicks in). Adding an in-process rate limiter on top
// would mask repeated occurrences and prevent operators from seeing
// the bug pattern. If a future server-side bug ever generates WARN
// volume above what reconnect backoff bounds, the right fix is at
// the server (or at a future SLI threshold on
// wtp_reconnects_total{reason=~"server_update_unsupported|recv_unknown_frame|server_goaway"}),
// not in-process suppression here.
func (t *Transport) runRecv(rs *recvSession) {
	// Closing rs.done is what unblocks teardownRecv's wait. defer at the
	// top guarantees every exit path (ctx cancel, Recv error, fail-closed
	// control frame, unknown frame) signals exit — round-22 Finding 2's
	// load-bearing synchronisation primitive.
	defer close(rs.done)
	for {
		// Bail if the per-connection ctx has been cancelled. The
		// conn.Recv() call below will also unblock once Close() is
		// called on the conn, but checking ctx first avoids one extra
		// Recv attempt on shutdown.
		select {
		case <-rs.ctx.Done():
			return
		default:
		}
		msg, err := t.conn.Recv()
		if err != nil {
			// Surface the error through rs.errCh so the main goroutine
			// can transition to Connecting on the next select iteration.
			// Non-blocking send because only the FIRST recv error
			// matters; subsequent errors during wind-down are redundant.
			select {
			case rs.errCh <- err:
			default:
			}
			return
		}
		switch m := msg.GetMsg().(type) {
		case *wtpv1.ServerMessage_BatchAck:
			a := m.BatchAck
			ev := recvAckEvent{
				kind: recvAckEventBatchAck,
				gen:  a.GetGeneration(),
				seq:  a.GetAckHighWatermarkSeq(),
			}
			// Blocking send; per-connection ctx unblocks if main is
			// wedged (round-22 Finding 2). The heartbeat-deadline
			// timer (Task 18) is the wedge-defence at the protocol
			// layer.
			select {
			case rs.eventCh <- ev:
			case <-rs.ctx.Done():
				return
			}
		case *wtpv1.ServerMessage_ServerHeartbeat:
			h := m.ServerHeartbeat
			ev := recvAckEvent{
				kind: recvAckEventHeartbeat,
				// gen left zero; main substitutes t.persistedAck.Generation
				// at apply time per the FIFO-order invariant.
				seq: h.GetAckHighWatermarkSeq(),
			}
			select {
			case rs.eventCh <- ev:
			case <-rs.ctx.Done():
				return
			}
		case *wtpv1.ServerMessage_Goaway:
			// Task 22d: structured WARN before the errCh sentinel
			// so operators see the branch without grepping the
			// errCh substring. Standard fields plus the stable
			// payload subset (code, retry, message-present marker).
			// Message text is OMITTED by default (conservative
			// posture) and only included verbatim when
			// LogGoawayMessage is true — see transport.Options
			// docstring for the rationale + server-contract gate.
			g := m.Goaway
			msgPresent := g.GetMessage() != ""
			attrs := []slog.Attr{
				slog.String("frame", "recv_control"),
				slog.String("reason", "goaway_received"),
				slog.String("goaway_code", g.GetCode().String()),
				slog.Bool("goaway_retry_immediately", g.GetRetryImmediately()),
				slog.Bool("goaway_message_present", msgPresent),
			}
			if t.opts.LogGoawayMessage {
				attrs = append(attrs, slog.String("goaway_message", sanitizeForLog(g.GetMessage())))
			}
			attrs = append(attrs, slog.String("session_id", t.opts.SessionID))
			t.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
				"wtp: recv fail-closed control frame", attrs...)
			// Tasks 18/19/20 will replace these with real handlers.
			// Fail closed so the main goroutine drops to Connecting
			// instead of silently dropping a session-critical frame
			// (round-22 Finding 4).
			select {
			case rs.errCh <- errors.New("recv: control frame goaway not yet handled"):
			default:
			}
			return
		case *wtpv1.ServerMessage_ServerUpdate:
			// Task 22d: structured WARN. Standard fields only —
			// Phase 4 has no SessionUpdate handler, so dragging
			// payload fields into the WARN now would be churn (the
			// WARN site goes away when Phase 5+ adds support).
			t.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
				"wtp: recv fail-closed control frame",
				slog.String("frame", "recv_control"),
				slog.String("reason", "server_update_unsupported_in_phase_4"),
				slog.String("session_id", t.opts.SessionID))
			// Tasks 18/19/20 will replace these with real handlers.
			// Fail closed; see Goaway branch above.
			select {
			case rs.errCh <- errors.New("recv: control frame session_update not yet handled"):
			default:
			}
			return
		default:
			// Task 22d: structured WARN. Standard fields plus
			// frame_type carrying the proto Go type for triage —
			// the unknown-frame branch is the only one where the
			// proto type is not statically known.
			t.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
				"wtp: recv fail-closed control frame",
				slog.String("frame", "recv_control"),
				slog.String("reason", "recv_unknown_frame_type"),
				slog.String("frame_type", fmt.Sprintf("%T", m)),
				slog.String("session_id", t.opts.SessionID))
			// Unknown frame type — proto-evolution defence: the
			// server may add new control frames the client predates.
			// Surface as a recv error so the main goroutine drops to
			// Connecting rather than silently dropping the frame.
			select {
			case rs.errCh <- fmt.Errorf("recv: unknown control frame %T, returning to Connecting", m):
			default:
			}
			return
		}
	}
}

// applyAckFromRecv is the recv-side wrapper around applyServerAckTuple.
// It is invoked from the main state-machine goroutine when a
// recvAckEvent surfaces on rs.eventCh; the recv goroutine NEVER
// touches t.persistedAck / t.remoteReplayCursor / t.persistedAckPresent
// directly (single-owner invariant per plan §"Concurrency boundary
// for ack-cursor updates").
//
// `frame` is the proto frame name ("batch_ack" / "server_heartbeat")
// used in the anomaly WARN's structured log so operators can tell which
// frame type drove the anomaly. SessionAck logs through the ackSessionAck
// site directly (with frame="session_ack") — same side-effect contract,
// inlined there for the anomaly-WARN/rejectReason interleave.
//
// Round-8 — the four-branch dispatch matches Task 15.1 Step 1b. The
// Adopted branch is the ONLY one that calls walMarkAckedFn + emits
// the gauge; ResendNeeded logs INFO and regresses remoteReplayCursor
// only; Anomaly logs WARN and leaves both cursors unchanged; NoOp
// is silent.
//
// Returns the AckOutcomeKind so callers (runLive) can release a slot
// in the inflight window only when the ack actually advanced the
// acknowledged watermark (AckOutcomeAdopted). Decrementing on
// Anomaly / ResendNeeded / NoOp would let duplicate or stale acks
// reopen send capacity without a newly acknowledged batch and so
// allow the client to exceed MaxInflight (roborev Medium).
func (t *Transport) applyAckFromRecv(frame string, serverGen uint32, serverSeq uint64) AckOutcomeKind {
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
			//
			// Return NoOp (NOT outcome.Kind == Adopted) so runLive does
			// NOT decrement inflight on the rolled-back attempt — a
			// later successful re-delivery of the same watermark would
			// otherwise decrement again, allowing the client to exceed
			// MaxInflight (roborev Medium follow-up).
			return AckOutcomeNoOp
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
	return outcome.Kind
}

const (
	// goawayMessageMaxBytes caps the sanitized + truncated
	// goaway_message log field at 512 bytes total INCLUDING the
	// trailing truncation marker. Operators see "...[truncated]"
	// at the end whenever the budget kicks in instead of a
	// silently chopped string.
	goawayMessageMaxBytes  = 512
	goawayTruncationMarker = "...[truncated]"
)

// sanitizeForLog returns s safe for emission as a slog string field.
// It enforces three guarantees, IN THIS ORDER:
//
//  1. Replace any invalid UTF-8 sequence with U+FFFD
//     (strings.ToValidUTF8 — handles multi-byte invalid sequences
//     correctly, where per-byte ASCII filtering would pass corrupted
//     multi-byte runs through).
//  2. Replace any control / non-printable rune with U+FFFD. ALL C0
//     controls (U+0000..U+001F) including '\t' and '\n' are
//     replaced — only the literal space character ' ' (U+0020) and
//     printable Unicode pass through. This handler-agnostic policy
//     eliminates log-injection risk regardless of which slog handler
//     the operator's transport eventually uses (stdlib JSON, stdlib
//     Text, or any custom handler).
//  3. Truncate the SANITIZED OUTPUT to at most goawayMessageMaxBytes
//     bytes WITH goawayTruncationMarker appended INSIDE that budget,
//     ending at a UTF-8 rune boundary so the output is always valid
//     UTF-8.
//
// Order matters. Sanitization can grow the string (a single invalid
// byte expands to a 3-byte U+FFFD); truncating raw input could split
// a valid multi-byte sequence at a non-rune boundary.
//
// Empty input passes through unchanged.
//
// Currently used only by the Goaway WARN site under the
// LogGoawayMessage opt-in. If a second caller emerges, lift to
// internal/log/sanitize.go and replace the local function with a
// shared call WITHOUT changing the contract — the test sub-cases in
// recv_multiplexer_failclosed_test.go are the regression for the
// invariants above.
func sanitizeForLog(s string) string {
	if s == "" {
		return ""
	}
	valid := strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(len(valid))
	for _, r := range valid {
		switch r {
		case ' ':
			// Only the literal space character passes through; '\t'
			// and '\n' are C0 controls and fall into the default
			// branch (handler-agnostic policy — see top-of-func
			// docstring).
			b.WriteRune(r)
		default:
			if unicode.IsPrint(r) {
				b.WriteRune(r)
			} else {
				b.WriteRune('�')
			}
		}
	}
	out := b.String()
	if len(out) <= goawayMessageMaxBytes {
		return out
	}
	budget := goawayMessageMaxBytes - len(goawayTruncationMarker)
	// Walk back to a rune boundary so we never chop mid-rune.
	for budget > 0 && !utf8.RuneStart(out[budget]) {
		budget--
	}
	return out[:budget] + goawayTruncationMarker
}
