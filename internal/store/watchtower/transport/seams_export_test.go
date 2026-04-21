package transport

import (
	"context"
	"log/slog"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"golang.org/x/time/rate"
)

// Test-only export seams for the Task 15.1 two-cursor ack clamp work.
// These helpers live in a _test.go file so they are compiled out of the
// production binary; the unexported fields on Transport remain unreachable
// from outside the package except via these seams.

// SetWALMarkAckedFnForTest swaps the test seam that applyServerAckTuple's
// caller uses to drive wal.MarkAcked. Production callers MUST NOT touch
// this — the only legitimate use is _test.go-only error injection.
func SetWALMarkAckedFnForTest(t *Transport, fn func(gen uint32, seq uint64) error) {
	t.walMarkAckedFn = fn
}

// SetWALWrittenDataHighWaterFnForTest swaps the test seam used inside
// applyServerAckTuple AND by the WARN-context emitter in the SessionAck
// handler. Override to inject errors from wal.WrittenDataHighWater.
func SetWALWrittenDataHighWaterFnForTest(t *Transport, fn func(gen uint32) (uint64, bool, error)) {
	t.walWrittenDataHighWaterFn = fn
}

// SetWALEarliestDataSequenceFnForTest swaps the test seam used inside
// computeReplayStart to drive wal.EarliestDataSequence.
func SetWALEarliestDataSequenceFnForTest(t *Transport, fn func(gen uint32) (uint64, bool, error)) {
	t.walEarliestDataSequenceFn = fn
}

// SetWALHighGenerationFnForTest swaps the test seam used inside
// computeReplayPlan to drive wal.HighGeneration. Override to inject a
// specific upper bound on the multi-stage iteration without having to
// append records into a real WAL.
func SetWALHighGenerationFnForTest(t *Transport, fn func() uint32) {
	t.walHighGenerationFn = fn
}

// SetWALHasDataBelowGenerationFnForTest swaps the test seam used inside
// applyServerAckTuple's first-apply (gen, seq=0) gate. Override to inject
// the lower-generation-data flag without having to populate a real WAL
// across multiple generations.
func SetWALHasDataBelowGenerationFnForTest(t *Transport, fn func(threshold uint32) (bool, error)) {
	t.walHasDataBelowGenerationFn = fn
}

// SetWALHasReplayableRecordsFnForTest swaps the test seam used inside
// computeReplayPlan's intermediate-generation loop (round-16 Finding 2)
// to drive wal.HasReplayableRecords. Override to inject the
// any-payload-present flag for a generation without having to write
// records (data or loss) into a real WAL.
func SetWALHasReplayableRecordsFnForTest(t *Transport, fn func(gen uint32) (bool, error)) {
	t.walHasReplayableRecordsFn = fn
}

// SetAckAnomalyLimiterForTest swaps the rate limiter that gates the WARN
// emitted on Anomaly outcomes. Tests pass either a permissive limiter
// (rate.Inf) or a strict one (rate.Every(time.Hour)) to exercise the
// rate-limit contract.
func SetAckAnomalyLimiterForTest(t *Transport, l *rate.Limiter) {
	t.ackAnomalyLimiter = l
}

// PersistedAckForTest returns the current persistedAck cursor for assertions.
func PersistedAckForTest(t *Transport) AckCursor {
	return t.persistedAck
}

// PersistedAckPresentForTest returns the current persistedAckPresent flag.
func PersistedAckPresentForTest(t *Transport) bool {
	return t.persistedAckPresent
}

// RemoteReplayCursorForTest returns the current remoteReplayCursor.
func RemoteReplayCursorForTest(t *Transport) AckCursor {
	return t.remoteReplayCursor
}

// ApplyServerAckTupleForTest invokes the unexported applyServerAckTuple
// helper directly so unit tests can exercise the helper without going
// through the SessionAck dispatch.
func ApplyServerAckTupleForTest(t *Transport, gen uint32, seq uint64) AckOutcome {
	return t.applyServerAckTuple(gen, seq)
}

// ComputeReplayStartForTest invokes the unexported computeReplayStart
// helper directly so unit tests can exercise it without driving the
// Run loop.
func ComputeReplayStartForTest(t *Transport, replay AckCursor, persisted AckCursor) (*wal.LossRecord, uint64, error) {
	return t.computeReplayStart(replay, persisted)
}

// ComputeReplayPlanForTest invokes the unexported computeReplayPlan
// helper directly so unit tests can exercise the multi-generation
// orchestration without driving the Run loop or opening real Readers.
func ComputeReplayPlanForTest(t *Transport, replay AckCursor, persisted AckCursor) ([]ReplayStage, error) {
	return t.computeReplayPlan(replay, persisted)
}

// LoggerForTest returns the resolved logger so tests can sanity-check the
// New() default wiring.
func LoggerForTest(t *Transport) *slog.Logger {
	return t.opts.Logger
}

// RecvSessionForTest is the round-22 integration-test seam that returns
// the live per-connection recvSession so external tests can assert
// lifecycle properties (eventCh capacity, errCh contents, ctx state).
// Returns nil when no recv goroutine is running. NEVER call from
// production code — the recvSession is not part of the public surface.
func RecvSessionForTest(t *Transport) *RecvSessionHandle {
	if t.recv == nil {
		return nil
	}
	return &RecvSessionHandle{
		ctx:      t.recv.ctx,
		cancelFn: t.recv.cancelFn,
		eventCh:  t.recv.eventCh,
		errCh:    t.recv.errCh,
		done:     t.recv.done,
	}
}

// RecvSessionHandle is the test-only view onto a recvSession. The fields
// expose just enough to drive integration tests without leaking the
// internal recvAckEvent type to package-external test code (the helper
// methods below let tests assert on event metadata instead).
type RecvSessionHandle struct {
	ctx      context.Context
	cancelFn context.CancelFunc
	eventCh  chan recvAckEvent
	errCh    chan error
	done     chan struct{}
}

// Ctx returns the per-connection context — tests assert it is alive
// (or cancelled) via ctx.Err().
func (h *RecvSessionHandle) Ctx() context.Context { return h.ctx }

// Cancel triggers per-connection cancellation. Mirrors the production
// teardown path (round-22 Finding 2) so tests can assert the recv
// goroutine wakes up and exits without going through state-machine
// transitions.
func (h *RecvSessionHandle) Cancel() { h.cancelFn() }

// EventCh returns the event channel so tests can drain events directly
// (mirrors what the main goroutine does in the state-handler select
// arms). Returns a generic interface{} channel facade so the recvAckEvent
// type can stay package-internal; assertions go through the helper
// methods on EventForTest.
func (h *RecvSessionHandle) EventCh() <-chan recvAckEvent { return h.eventCh }

// ErrCh returns the recv-error channel so tests can observe stream
// errors and fail-closed control-frame signals.
func (h *RecvSessionHandle) ErrCh() <-chan error { return h.errCh }

// EventLen returns the current event channel queue depth — used by
// integration tests to fill the channel and assert back-pressure.
func (h *RecvSessionHandle) EventLen() int { return len(h.eventCh) }

// EventCap returns the event channel capacity (rounds-22 design fixes
// this at 4 — see recv_multiplexer.go::newRecvSession).
func (h *RecvSessionHandle) EventCap() int { return cap(h.eventCh) }

// Done returns the recv goroutine's done channel, closed by runRecv
// immediately before it returns. Round-23 Finding 4 test seam: external
// integration tests use this to assert the recv goroutine has fully
// exited after triggering cancel / control-frame / recv-error paths,
// rather than relying on ctx.Err() or errCh delivery (neither of which
// proves the goroutine has actually returned from runRecv).
func (h *RecvSessionHandle) Done() <-chan struct{} { return h.done }

// TrySendStaleEventForTest attempts a non-blocking send of the given
// event into the underlying eventCh. Round-23 Finding 3 test seam:
// external integration tests use this on a TORN-DOWN handle (where the
// recv goroutine has exited) to prove that a stale write to an orphaned
// eventCh cannot bleed into a freshly-allocated successor session's
// eventCh. Returns true if the send succeeded (channel had buffer
// capacity), false otherwise. Production code MUST NOT use this — the
// recv goroutine is the only legitimate writer to eventCh during the
// session's lifetime.
func (h *RecvSessionHandle) TrySendStaleEventForTest(ev recvAckEvent) bool {
	select {
	case h.eventCh <- ev:
		return true
	default:
		return false
	}
}

// FrameForTest returns a stable string label for the event kind so
// external tests can assert order without referencing the internal
// recvAckEventKind enum values.
func FrameForTest(ev recvAckEvent) string {
	switch ev.kind {
	case recvAckEventBatchAck:
		return "batch_ack"
	case recvAckEventHeartbeat:
		return "server_heartbeat"
	default:
		return "unknown"
	}
}

// GenForTest returns the event generation. For heartbeats this is zero
// on the wire — production substitutes t.persistedAck.Generation at
// apply time.
func GenForTest(ev recvAckEvent) uint32 { return ev.gen }

// SeqForTest returns the event sequence — populated for both kinds.
func SeqForTest(ev recvAckEvent) uint64 { return ev.seq }

// MakeBatchAckEventForTest constructs a recvAckEvent of kind BatchAck
// from a wire frame. Round-23 Finding 3 test seam: external integration
// tests use this to fabricate a stale event for the
// "send-onto-old-eventCh-after-teardown-and-prove-no-bleed" probe in
// TestRecvMultiplexer_ReconnectDoesNotLeakStateAcrossSessions. Production
// code MUST NOT use this — events are produced exclusively by the recv
// goroutine in runRecv.
func MakeBatchAckEventForTest(frame *wtpv1.ServerMessage) recvAckEvent {
	a := frame.GetBatchAck()
	return recvAckEvent{
		kind: recvAckEventBatchAck,
		gen:  a.GetGeneration(),
		seq:  a.GetAckHighWatermarkSeq(),
	}
}

// StartRecvForTest starts the recv goroutine bound to the given parent
// ctx, attaches a fresh recvSession to t.recv, and returns the handle.
// External integration tests use this to drive the recv-goroutine path
// against a fake Conn without going through runConnecting.
func StartRecvForTest(t *Transport, parent context.Context) *RecvSessionHandle {
	rs := newRecvSession(parent)
	t.recv = rs
	go t.runRecv(rs)
	return &RecvSessionHandle{
		ctx:      rs.ctx,
		cancelFn: rs.cancelFn,
		eventCh:  rs.eventCh,
		errCh:    rs.errCh,
		done:     rs.done,
	}
}

// TeardownRecvForTest invokes the production teardownRecv helper so
// integration tests can assert the round-22 lifecycle (cancel + nil
// out the field) without touching unexported state.
func TeardownRecvForTest(t *Transport) { t.teardownRecv() }
