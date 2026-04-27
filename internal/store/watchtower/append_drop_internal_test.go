package watchtower

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"github.com/agentsh/agentsh/pkg/types"
)

// lossSpy records AppendLoss calls and returns an injectable error.
type lossSpy struct {
	calls    int
	lastLoss wal.LossRecord
	err      error // injected error to return
}

func (sp *lossSpy) AppendLoss(loss wal.LossRecord) error {
	sp.calls++
	sp.lastLoss = loss
	return sp.err
}

// fakeSink implements chain.SinkChainAPI for tests that need a non-nil sink
// (specifically, tests that trigger the ambiguous-error path in emitInFlightLoss
// which calls s.sink.Fatal).
type fakeSink struct {
	fatalErr error
}

func (f *fakeSink) Compute(_ int, _ int64, _ uint32, _ []byte) (*audit.ComputeResult, error) {
	return nil, nil
}
func (f *fakeSink) Commit(_ *audit.ComputeResult) error { return nil }
func (f *fakeSink) Fatal(err error)                     { f.fatalErr = err }
func (f *fakeSink) PeekPrevHash() string                { return "" }
func (f *fakeSink) State() audit.SinkChainState         { return audit.SinkChainState{} }

// Verify fakeSink satisfies the interface at compile time.
var _ chain.SinkChainAPI = (*fakeSink)(nil)

// newDropTestStore builds a minimal Store wired with a counter-asserting
// *WTPMetrics, a buffered JSON slog handler, and a lossSpy that records
// AppendLoss calls. The flag arg controls Options.EmitExtendedLossReasons.
// Returns the Store, the metrics handle, the log buffer, and the spy.
func newDropTestStore(t *testing.T, emitExtended bool) (*Store, *metrics.WTPMetrics, *bytes.Buffer, *lossSpy) {
	t.Helper()
	col := metrics.New()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	spy := &lossSpy{}
	fs := &fakeSink{}
	s := &Store{
		opts: Options{
			Logger:                  logger,
			SessionID:               "s-test",
			AgentID:                 "a-test",
			EmitExtendedLossReasons: emitExtended,
		},
		metrics:      col.WTP(),
		appendLossFn: spy.AppendLoss,
		sink:         fs,
	}
	return s, col.WTP(), &buf, spy
}

// findWarnEntry returns the single decoded WARN log entry from buf, or
// fails the test if zero or more than one entry is present.
func findWarnEntry(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var warnLines []string
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse log entry: %v", err)
		}
		if entry["level"] == "WARN" {
			warnLines = append(warnLines, line)
		}
	}
	if len(warnLines) != 1 {
		t.Fatalf("expected exactly 1 WARN log entry, got %d: %q", len(warnLines), buf.String())
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(warnLines[0]), &entry); err != nil {
		t.Fatalf("parse warn entry: %v", err)
	}
	return entry
}

func TestRecordSequenceOverflow_IncrementsCounterAndEmitsWarn(t *testing.T) {
	s, m, buf, _ := newDropTestStore(t, false)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 99, Generation: 7},
	}
	s.recordSequenceOverflow(ev)

	if got := m.DroppedSequenceOverflow(); got != 1 {
		t.Fatalf("DroppedSequenceOverflow() = %d, want 1", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "sequence_overflow" {
		t.Fatalf("reason = %v, want sequence_overflow", got)
	}
	if got := entry["event_seq"]; got != float64(99) {
		t.Fatalf("event_seq = %v, want 99", got)
	}
	if got := entry["event_gen"]; got != float64(7) {
		t.Fatalf("event_gen = %v, want 7", got)
	}
	if got := entry["session_id"]; got != "s-test" {
		t.Fatalf("session_id = %v, want s-test", got)
	}
	if got := entry["agent_id"]; got != "a-test" {
		t.Fatalf("agent_id = %v, want a-test", got)
	}
}

func TestRecordCompactEncodeFailure_ClassifiesInvalidMapper(t *testing.T) {
	s, m, buf, _ := newDropTestStore(t, false)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	s.recordCompactEncodeFailure(compact.ErrInvalidMapper, ev)

	if got := m.DroppedInvalidMapper(); got != 1 {
		t.Fatalf("DroppedInvalidMapper() = %d, want 1", got)
	}
	if got := m.DroppedInvalidTimestamp(); got != 0 {
		t.Fatalf("DroppedInvalidTimestamp() = %d, want 0 (wrong branch fired)", got)
	}
	if got := m.DroppedMapperFailure(); got != 0 {
		t.Fatalf("DroppedMapperFailure() = %d, want 0 (wrong branch fired)", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "invalid_mapper" {
		t.Fatalf("reason = %v, want invalid_mapper", got)
	}
	if got := entry["err"]; got == nil || !strings.Contains(got.(string), "mapper is required") {
		t.Fatalf("err attr = %v, want non-empty containing %q", got, "mapper is required")
	}
}

func TestRecordCompactEncodeFailure_ClassifiesInvalidTimestamp(t *testing.T) {
	s, m, buf, _ := newDropTestStore(t, false)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 2, Generation: 1},
	}
	wrapped := fmt.Errorf("compact.Encode: %w", compact.ErrInvalidTimestamp)
	s.recordCompactEncodeFailure(wrapped, ev)

	if got := m.DroppedInvalidTimestamp(); got != 1 {
		t.Fatalf("DroppedInvalidTimestamp() = %d, want 1", got)
	}
	if got := m.DroppedInvalidMapper(); got != 0 {
		t.Fatalf("DroppedInvalidMapper() = %d, want 0 (wrong branch fired)", got)
	}
	if got := m.DroppedMapperFailure(); got != 0 {
		t.Fatalf("DroppedMapperFailure() = %d, want 0 (wrong branch fired)", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "invalid_timestamp" {
		t.Fatalf("reason = %v, want invalid_timestamp", got)
	}
}

func TestRecordCompactEncodeFailure_ClassifiesMapperFailureCatchAll(t *testing.T) {
	s, m, buf, _ := newDropTestStore(t, false)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 3, Generation: 1},
	}
	// A mapper-side error wrapped exactly the way compact.Encode wraps
	// every Mapper.Map error post-#6177 fix — via the ErrMapperFailure
	// sentinel.
	wrapped := fmt.Errorf("%w: %w", compact.ErrMapperFailure, errors.New("synthetic mapper failure"))
	s.recordCompactEncodeFailure(wrapped, ev)

	if got := m.DroppedMapperFailure(); got != 1 {
		t.Fatalf("DroppedMapperFailure() = %d, want 1", got)
	}
	if got := m.DroppedInvalidMapper(); got != 0 {
		t.Fatalf("DroppedInvalidMapper() = %d, want 0 (wrong branch fired)", got)
	}
	if got := m.DroppedInvalidTimestamp(); got != 0 {
		t.Fatalf("DroppedInvalidTimestamp() = %d, want 0 (wrong branch fired)", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "mapper_failure" {
		t.Fatalf("reason = %v, want mapper_failure", got)
	}
}

// TestRecordCompactEncodeFailure_MapperReturningSentinelStaysMapperFailure
// pins roborev #6177 (Medium): a Mapper that happens to return
// compact.ErrInvalidMapper or compact.ErrInvalidTimestamp from inside
// its Map method MUST be classified as `mapper_failure`, not as the
// validation-gate counter the inner sentinel would otherwise match.
// compact.Encode wraps every mapper-side error with ErrMapperFailure,
// so the classifier's priority order (ErrMapperFailure first) keeps
// the inner sentinel from leaking into the wrong counter.
func TestRecordCompactEncodeFailure_MapperReturningSentinelStaysMapperFailure(t *testing.T) {
	cases := []struct {
		name  string
		inner error
	}{
		{"inner=ErrInvalidMapper", compact.ErrInvalidMapper},
		{"inner=ErrInvalidTimestamp", compact.ErrInvalidTimestamp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, m, buf, _ := newDropTestStore(t, false)

			ev := types.Event{
				Timestamp: time.Unix(1700000000, 0),
				Chain:     &types.ChainState{Sequence: 5, Generation: 3},
			}
			// Mirror the exact wrap compact.Encode applies in its
			// `m.Map(ev)` error branch.
			wrapped := fmt.Errorf("%w: %w", compact.ErrMapperFailure, tc.inner)
			s.recordCompactEncodeFailure(wrapped, ev)

			if got := m.DroppedMapperFailure(); got != 1 {
				t.Fatalf("DroppedMapperFailure() = %d, want 1", got)
			}
			if got := m.DroppedInvalidMapper(); got != 0 {
				t.Fatalf("DroppedInvalidMapper() = %d, want 0 (mapper-originated sentinel must NOT leak)", got)
			}
			if got := m.DroppedInvalidTimestamp(); got != 0 {
				t.Fatalf("DroppedInvalidTimestamp() = %d, want 0 (mapper-originated sentinel must NOT leak)", got)
			}

			entry := findWarnEntry(t, buf)
			if got := entry["reason"]; got != "mapper_failure" {
				t.Fatalf("reason = %v, want mapper_failure", got)
			}
		})
	}
}

func TestRecordCanonicalFailure_ClassifiesInvalidUTF8(t *testing.T) {
	s, m, buf, _ := newDropTestStore(t, false)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 4, Generation: 2},
	}
	wrapped := fmt.Errorf("chain.EncodeCanonical: %w", chain.ErrInvalidUTF8)
	s.recordCanonicalFailure(wrapped, ev)

	if got := m.DroppedInvalidUTF8(); got != 1 {
		t.Fatalf("DroppedInvalidUTF8() = %d, want 1", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "invalid_utf8" {
		t.Fatalf("reason = %v, want invalid_utf8", got)
	}
	if got := entry["event_seq"]; got != float64(4) {
		t.Fatalf("event_seq = %v, want 4", got)
	}
	if got := entry["event_gen"]; got != float64(2) {
		t.Fatalf("event_gen = %v, want 2", got)
	}
	if got := entry["session_id"]; got != "s-test" {
		t.Fatalf("session_id = %v, want s-test", got)
	}
	if got := entry["agent_id"]; got != "a-test" {
		t.Fatalf("agent_id = %v, want a-test", got)
	}
	if got := entry["err"]; got == nil {
		t.Fatalf("err attr missing, want non-empty string")
	}
}

// --- emitInFlightLoss helper tests ---

func TestEmitInFlightLoss_FlagOff_NoAppendLossCall(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, false /* flag */)
	ev := types.Event{Chain: &types.ChainState{Sequence: 100, Generation: 1}}
	s.emitInFlightLoss(ev, wal.LossReasonInvalidUTF8)
	if spy.calls != 0 {
		t.Fatalf("AppendLoss called %d times; want 0 (flag off)", spy.calls)
	}
}

func TestEmitInFlightLoss_FlagOn_CallsAppendLoss(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, true)
	ev := types.Event{Chain: &types.ChainState{Sequence: 100, Generation: 1}}
	s.emitInFlightLoss(ev, wal.LossReasonInvalidUTF8)
	if spy.calls != 1 {
		t.Fatalf("AppendLoss = %d; want 1", spy.calls)
	}
	if spy.lastLoss.FromSequence != 100 || spy.lastLoss.ToSequence != 100 {
		t.Fatalf("from/to = %d/%d; want 100/100", spy.lastLoss.FromSequence, spy.lastLoss.ToSequence)
	}
	if spy.lastLoss.Generation != 1 {
		t.Fatalf("generation = %d; want 1", spy.lastLoss.Generation)
	}
	if spy.lastLoss.Reason != wal.LossReasonInvalidUTF8 {
		t.Fatalf("reason = %q; want %q", spy.lastLoss.Reason, wal.LossReasonInvalidUTF8)
	}
}

func TestEmitInFlightLoss_AmbiguousFailure_LatchesFatal(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, true)
	spy.err = &wal.AppendError{Class: wal.FailureAmbiguous, Op: "test", Err: errors.New("simulated I/O failure")}
	ev := types.Event{Chain: &types.ChainState{Sequence: 100, Generation: 1}}
	s.emitInFlightLoss(ev, wal.LossReasonInvalidUTF8)
	if !s.fatalLatched.Load() {
		t.Fatalf("Store should be fatal-latched after ambiguous AppendLoss")
	}
}

func TestEmitInFlightLoss_CleanFailure_NoFatalLatch(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, true)
	spy.err = &wal.AppendError{Class: wal.FailureClean, Op: "test", Err: errors.New("WAL closed")}
	ev := types.Event{Chain: &types.ChainState{Sequence: 100, Generation: 1}}
	s.emitInFlightLoss(ev, wal.LossReasonInvalidUTF8)
	if s.fatalLatched.Load() {
		t.Fatalf("Store should NOT be fatal-latched after clean AppendLoss failure")
	}
}

// --- drop-site wire-through tests ---

func TestRecordSequenceOverflow_EmitsInFlightLoss_WhenFlagOn(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, true)
	ev := types.Event{Chain: &types.ChainState{Sequence: 99, Generation: 7}}
	s.recordSequenceOverflow(ev)
	if spy.calls != 1 {
		t.Fatalf("AppendLoss calls = %d; want 1", spy.calls)
	}
	if spy.lastLoss.Reason != wal.LossReasonSequenceOverflow {
		t.Fatalf("reason = %q; want %q", spy.lastLoss.Reason, wal.LossReasonSequenceOverflow)
	}
}

func TestRecordCanonicalFailure_EmitsInFlightLoss_WhenFlagOn(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, true)
	ev := types.Event{Chain: &types.ChainState{Sequence: 200, Generation: 3}}
	s.recordCanonicalFailure(chain.ErrInvalidUTF8, ev)
	if spy.calls != 1 {
		t.Fatalf("AppendLoss calls = %d; want 1", spy.calls)
	}
	if spy.lastLoss.Reason != wal.LossReasonInvalidUTF8 {
		t.Fatalf("reason = %q; want %q", spy.lastLoss.Reason, wal.LossReasonInvalidUTF8)
	}
}

func TestRecordCompactEncodeFailure_MapperFailure_EmitsInFlightLoss(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, true)
	ev := types.Event{Chain: &types.ChainState{Sequence: 50, Generation: 1}}
	err := fmt.Errorf("compact.Encode: %w", compact.ErrMapperFailure)
	s.recordCompactEncodeFailure(err, ev)
	if spy.calls != 1 {
		t.Fatalf("AppendLoss = %d; want 1", spy.calls)
	}
	if spy.lastLoss.Reason != wal.LossReasonMapperFailure {
		t.Fatalf("reason = %q; want %q", spy.lastLoss.Reason, wal.LossReasonMapperFailure)
	}
}

func TestRecordCompactEncodeFailure_InvalidMapper_EmitsInFlightLoss(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, true)
	ev := types.Event{Chain: &types.ChainState{Sequence: 51, Generation: 1}}
	err := fmt.Errorf("compact.Encode: %w", compact.ErrInvalidMapper)
	s.recordCompactEncodeFailure(err, ev)
	if spy.lastLoss.Reason != wal.LossReasonInvalidMapper {
		t.Fatalf("reason = %q; want %q", spy.lastLoss.Reason, wal.LossReasonInvalidMapper)
	}
}

func TestRecordCompactEncodeFailure_InvalidTimestamp_EmitsInFlightLoss(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, true)
	ev := types.Event{Chain: &types.ChainState{Sequence: 52, Generation: 1}}
	err := fmt.Errorf("compact.Encode: %w", compact.ErrInvalidTimestamp)
	s.recordCompactEncodeFailure(err, ev)
	if spy.lastLoss.Reason != wal.LossReasonInvalidTimestamp {
		t.Fatalf("reason = %q; want %q", spy.lastLoss.Reason, wal.LossReasonInvalidTimestamp)
	}
}

func TestRecordCompactEncodeFailure_FallthroughClassifiedAsMapperFailure(t *testing.T) {
	s, _, _, spy := newDropTestStore(t, true)
	ev := types.Event{Chain: &types.ChainState{Sequence: 53, Generation: 1}}
	err := errors.New("some unrelated error")
	s.recordCompactEncodeFailure(err, ev)
	if spy.lastLoss.Reason != wal.LossReasonMapperFailure {
		t.Fatalf("reason = %q; want %q (fallthrough)", spy.lastLoss.Reason, wal.LossReasonMapperFailure)
	}
}
