package watchtower_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/pkg/types"
)

// failingMapper is a Mapper that always returns the configured error.
// Used to drive AppendEvent into the mapper_failure catch-all branch
// without depending on a particular OCSF mapper's failure modes.
type failingMapper struct{ err error }

func (f failingMapper) Map(_ types.Event) (compact.MappedEvent, error) {
	return compact.MappedEvent{}, f.err
}

// dropTestFixture wires a Store with a counter-asserting collector and
// a captured logger so each test can assert the precise observability
// emitted on a drop. The Store is constructed via watchtower.New so
// the test exercises the real reject-site wiring, not the helpers
// directly. A testserver is started so Options.Dialer is satisfied;
// the transport never actually delivers anything in these tests
// because every test path errors before WAL append.
type dropTestFixture struct {
	store     *watchtower.Store
	collector *metrics.Collector
	logBuf    *bytes.Buffer
}

func newDropFixture(t *testing.T, optsMutator func(*watchtower.Options)) *dropTestFixture {
	t.Helper()
	col := metrics.New()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	opts := watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a-test",
		SessionID:       "s-test",
		KeyFingerprint:  "sha256:drop-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 8,
		BatchMaxBytes:   8 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		Metrics:         col,
		Logger:          logger,
	}
	if optsMutator != nil {
		optsMutator(&opts)
	}

	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	return &dropTestFixture{store: s, collector: col, logBuf: &logBuf}
}

// dropWarnEntries returns every parsed log entry whose msg matches the
// drop WARN string. Helper used by both findDropWarn (asserts exactly
// one) and the happy-path test (asserts zero) so the message string
// lives in one place.
func dropWarnEntries(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var matches []map[string]any
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if entry["msg"] == "wtp: dropping event before WAL append" {
			matches = append(matches, entry)
		}
	}
	return matches
}

// findDropWarn parses the captured log buffer and returns the single
// drop WARN entry. Fails the test if zero or multiple entries match.
func (f *dropTestFixture) findDropWarn(t *testing.T) map[string]any {
	t.Helper()
	matches := dropWarnEntries(t, f.logBuf)
	if len(matches) != 1 {
		t.Fatalf("expected 1 drop WARN, got %d (full buf: %q)", len(matches), f.logBuf.String())
	}
	return matches[0]
}

func TestAppendEvent_DropsOnInvalidTimestamp(t *testing.T) {
	f := newDropFixture(t, nil)

	ev := types.Event{
		Type:      "exec",
		SessionID: "s-test",
		Timestamp: time.Time{}, // zero value trips compact.ErrInvalidTimestamp
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	err := f.store.AppendEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("AppendEvent: expected error, got nil")
	}
	if !errors.Is(err, compact.ErrInvalidTimestamp) {
		t.Fatalf("error = %v, want errors.Is(_, ErrInvalidTimestamp)", err)
	}

	if got := f.collector.WTP().DroppedInvalidTimestamp(); got != 1 {
		t.Fatalf("DroppedInvalidTimestamp() = %d, want 1", got)
	}

	entry := f.findDropWarn(t)
	if got := entry["reason"]; got != "invalid_timestamp" {
		t.Fatalf("reason = %v, want invalid_timestamp", got)
	}
	if got := entry["event_seq"]; got != float64(1) {
		t.Fatalf("event_seq = %v, want 1", got)
	}
	if got := entry["event_gen"]; got != float64(1) {
		t.Fatalf("event_gen = %v, want 1", got)
	}
	if got := entry["session_id"]; got != "s-test" {
		t.Fatalf("session_id = %v, want s-test", got)
	}
	if got := entry["agent_id"]; got != "a-test" {
		t.Fatalf("agent_id = %v, want a-test", got)
	}
}

func TestAppendEvent_DropsOnMapperFailure(t *testing.T) {
	mapperErr := errors.New("synthetic mapper failure")
	f := newDropFixture(t, func(opts *watchtower.Options) {
		// failingMapper is not a StubMapper, so AllowStubMapper does not need to flip.
		opts.Mapper = failingMapper{err: mapperErr}
	})

	ev := types.Event{
		Type:      "exec",
		SessionID: "s-test",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	err := f.store.AppendEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("AppendEvent: expected error, got nil")
	}
	if !errors.Is(err, mapperErr) {
		t.Fatalf("error = %v, want errors.Is(_, mapperErr)", err)
	}

	if got := f.collector.WTP().DroppedMapperFailure(); got != 1 {
		t.Fatalf("DroppedMapperFailure() = %d, want 1", got)
	}

	entry := f.findDropWarn(t)
	if got := entry["reason"]; got != "mapper_failure" {
		t.Fatalf("reason = %v, want mapper_failure", got)
	}
	if got := entry["err"]; got == nil || !strings.Contains(got.(string), "synthetic mapper failure") {
		t.Fatalf("err attr = %v, want non-empty containing %q", got, "synthetic mapper failure")
	}
}

func TestAppendEvent_DropsOnSequenceOverflow(t *testing.T) {
	f := newDropFixture(t, nil)

	ev := types.Event{
		Type:      "exec",
		SessionID: "s-test",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: math.MaxInt64 + 1, Generation: 1},
	}
	err := f.store.AppendEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("AppendEvent: expected error, got nil")
	}
	// sequence_overflow has no sentinel — assert on the message substring.
	if !strings.Contains(err.Error(), "overflows int64") {
		t.Fatalf("error = %v, want message containing %q", err, "overflows int64")
	}

	if got := f.collector.WTP().DroppedSequenceOverflow(); got != 1 {
		t.Fatalf("DroppedSequenceOverflow() = %d, want 1", got)
	}

	entry := f.findDropWarn(t)
	if got := entry["reason"]; got != "sequence_overflow" {
		t.Fatalf("reason = %v, want sequence_overflow", got)
	}
	// No "err" attr expected — sequence_overflow is our own range check, not a wrapped sentinel.
	if _, present := entry["err"]; present {
		t.Fatalf("err attr present in sequence_overflow WARN; want absent")
	}
}

func TestAppendEvent_HappyPath_NoDrops(t *testing.T) {
	// Explicit no-op mutator so we go through the same fixture path as
	// the failing tests; the contract under test is "valid input bumps
	// no drop counter and emits no drop WARN."
	f := newDropFixture(t, nil)

	ev := types.Event{
		Type:      "exec",
		SessionID: "s-test",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	if err := f.store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent (happy path): %v", err)
	}

	wtp := f.collector.WTP()
	if got := wtp.DroppedSequenceOverflow(); got != 0 {
		t.Errorf("DroppedSequenceOverflow() = %d, want 0", got)
	}
	if got := wtp.DroppedInvalidMapper(); got != 0 {
		t.Errorf("DroppedInvalidMapper() = %d, want 0", got)
	}
	if got := wtp.DroppedInvalidTimestamp(); got != 0 {
		t.Errorf("DroppedInvalidTimestamp() = %d, want 0", got)
	}
	if got := wtp.DroppedMapperFailure(); got != 0 {
		t.Errorf("DroppedMapperFailure() = %d, want 0", got)
	}
	if got := wtp.DroppedInvalidUTF8(); got != 0 {
		t.Errorf("DroppedInvalidUTF8() = %d, want 0", got)
	}

	// No drop WARN should have fired.
	if drops := dropWarnEntries(t, f.logBuf); len(drops) > 0 {
		t.Fatalf("happy-path append emitted %d drop WARN(s); want 0: %v", len(drops), drops)
	}
}
