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

	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/pkg/types"
)

// newDropTestStore builds a minimal Store wired with a counter-asserting
// *WTPMetrics and a buffered JSON slog handler so the recordX helpers
// can be unit-tested without standing up a WAL / transport / chain.
// Returns the Store, the metrics handle, and the log buffer.
func newDropTestStore(t *testing.T) (*Store, *metrics.WTPMetrics, *bytes.Buffer) {
	t.Helper()
	col := metrics.New()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s := &Store{
		opts: Options{
			Logger:    logger,
			SessionID: "s-test",
			AgentID:   "a-test",
		},
		metrics: col.WTP(),
	}
	return s, col.WTP(), &buf
}

// findWarnEntry returns the single decoded WARN log entry from buf, or
// fails the test if zero or more than one entry is present.
func findWarnEntry(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("expected exactly 1 WARN log entry, got %d: %q", len(lines), buf.String())
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse log entry: %v", err)
	}
	return entry
}

func TestRecordSequenceOverflow_IncrementsCounterAndEmitsWarn(t *testing.T) {
	s, m, buf := newDropTestStore(t)

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
	s, m, buf := newDropTestStore(t)

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
	s, m, buf := newDropTestStore(t)

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
	s, m, buf := newDropTestStore(t)

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
			s, m, buf := newDropTestStore(t)

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
	s, m, buf := newDropTestStore(t)

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

