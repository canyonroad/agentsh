package watchtower

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/metrics"
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
