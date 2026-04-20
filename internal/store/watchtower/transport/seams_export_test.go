package transport

import (
	"log/slog"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
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
