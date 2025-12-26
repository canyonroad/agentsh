package simulation

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

func TestNewSessionRecorder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recording.jsonl")

	r, err := NewSessionRecorder(RecorderConfig{
		SessionID:  "sess-123",
		OutputPath: path,
	})
	if err != nil {
		t.Fatalf("NewSessionRecorder error: %v", err)
	}
	defer r.Close()

	if r == nil {
		t.Fatal("NewSessionRecorder returned nil")
	}
}

func TestSessionRecorder_Record(t *testing.T) {
	buf := &bytes.Buffer{}
	r := NewSessionRecorderWriter("sess-123", nopCloser{buf})

	op := &Operation{
		Type: "file_read",
		Path: "/workspace/file.txt",
	}

	err := r.Record(op, DecisionAllow, "workspace", 100*time.Microsecond)
	if err != nil {
		t.Fatalf("Record error: %v", err)
	}

	if r.EventCount() != 1 {
		t.Errorf("EventCount() = %d, want 1", r.EventCount())
	}

	// Parse the output
	var event RecordedEvent
	if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if event.Type != "file_read" {
		t.Errorf("Type = %q, want file_read", event.Type)
	}
	if event.Decision != "allow" {
		t.Errorf("Decision = %q, want allow", event.Decision)
	}
	if event.PolicyRule != "workspace" {
		t.Errorf("PolicyRule = %q, want workspace", event.PolicyRule)
	}
	if event.SessionID != "sess-123" {
		t.Errorf("SessionID = %q, want sess-123", event.SessionID)
	}
}

func TestSessionRecorder_RecordMultiple(t *testing.T) {
	buf := &bytes.Buffer{}
	r := NewSessionRecorderWriter("sess-123", nopCloser{buf})

	for i := 0; i < 3; i++ {
		op := &Operation{Type: "file_read", Path: "/test"}
		r.Record(op, DecisionAllow, "", time.Microsecond)
	}

	if r.EventCount() != 3 {
		t.Errorf("EventCount() = %d, want 3", r.EventCount())
	}

	// Should be 3 newline-delimited JSON objects
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("got %d lines, want 3", len(lines))
	}
}

func TestSessionRecorder_Duration(t *testing.T) {
	buf := &bytes.Buffer{}
	r := NewSessionRecorderWriter("sess-123", nopCloser{buf})

	time.Sleep(10 * time.Millisecond)

	d := r.Duration()
	if d < 10*time.Millisecond {
		t.Errorf("Duration() = %v, expected >= 10ms", d)
	}
}

func TestSessionRecorder_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recording.jsonl")

	r, err := NewSessionRecorder(RecorderConfig{
		SessionID:  "sess-123",
		OutputPath: path,
	})
	if err != nil {
		t.Fatalf("NewSessionRecorder error: %v", err)
	}

	// Close should be idempotent
	if err := r.Close(); err != nil {
		t.Errorf("First Close() error: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Second Close() error: %v", err)
	}

	// Recording after close should error
	op := &Operation{Type: "test"}
	if err := r.Record(op, DecisionAllow, "", 0); err == nil {
		t.Error("Record() should error after Close()")
	}
}

func TestNewSessionReplayer(t *testing.T) {
	eval := &mockEvaluator{}
	r := NewSessionReplayer("/path/to/recording.jsonl", eval)

	if r == nil {
		t.Fatal("NewSessionReplayer returned nil")
	}
}

func TestSessionReplayer_ReplayReader(t *testing.T) {
	eval := &mockEvaluator{
		results: map[string]TestResult{
			"file_read:/workspace/file.txt": {Decision: "allow"},
			"file_read:/etc/passwd":         {Decision: "deny"}, // Changed from allow
		},
	}

	// Create recording data
	events := []RecordedEvent{
		{
			Type:     "file_read",
			Decision: "allow",
			Request:  json.RawMessage(`{"type":"file_read","path":"/workspace/file.txt"}`),
		},
		{
			Type:     "file_read",
			Decision: "allow", // Was allow, now deny
			Request:  json.RawMessage(`{"type":"file_read","path":"/etc/passwd"}`),
		},
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		enc.Encode(e)
	}

	r := NewSessionReplayer("", eval)
	results, err := r.ReplayReader(&buf)
	if err != nil {
		t.Fatalf("ReplayReader error: %v", err)
	}

	if results.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d, want 2", results.TotalEvents)
	}
	if results.Matched != 1 {
		t.Errorf("Matched = %d, want 1", results.Matched)
	}
	if len(results.Differences) != 1 {
		t.Errorf("Differences = %d, want 1", len(results.Differences))
	}

	if results.Differences[0].OldDecision != "allow" {
		t.Errorf("OldDecision = %q, want allow", results.Differences[0].OldDecision)
	}
	if results.Differences[0].NewDecision != "deny" {
		t.Errorf("NewDecision = %q, want deny", results.Differences[0].NewDecision)
	}
}

func TestReplayResults_Summary(t *testing.T) {
	tests := []struct {
		results *ReplayResults
		want    string
	}{
		{
			results: &ReplayResults{TotalEvents: 0},
			want:    "No events replayed",
		},
		{
			results: &ReplayResults{TotalEvents: 10, Matched: 10},
			want:    "MATCH: All 10 events matched",
		},
		{
			results: &ReplayResults{
				TotalEvents: 10,
				Matched:     8,
				Differences: make([]Difference, 2),
			},
			want: "DIFF: 2/10 events differ (8 matched)",
		},
	}

	for _, tt := range tests {
		got := tt.results.Summary()
		if got != tt.want {
			t.Errorf("Summary() = %q, want %q", got, tt.want)
		}
	}
}

func TestReplayResults_HasDifferences(t *testing.T) {
	r := &ReplayResults{}
	if r.HasDifferences() {
		t.Error("HasDifferences() should return false with no differences")
	}

	r.Differences = []Difference{{}}
	if !r.HasDifferences() {
		t.Error("HasDifferences() should return true with differences")
	}
}

func TestLoadRecording(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recording.jsonl")

	// Create recording file
	events := []RecordedEvent{
		{Type: "file_read", Decision: "allow", Request: json.RawMessage(`{}`)},
		{Type: "net_connect", Decision: "deny", Request: json.RawMessage(`{}`)},
	}

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	for _, e := range events {
		enc.Encode(e)
	}
	f.Close()

	loaded, err := LoadRecording(path)
	if err != nil {
		t.Fatalf("LoadRecording error: %v", err)
	}

	if len(loaded) != 2 {
		t.Errorf("loaded %d events, want 2", len(loaded))
	}
}

func TestGetRecordingStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recording.jsonl")

	now := time.Now()
	events := []RecordedEvent{
		{Type: "file_read", Decision: "allow", Timestamp: now, SessionID: "sess-1", Request: json.RawMessage(`{}`)},
		{Type: "file_read", Decision: "allow", Timestamp: now.Add(time.Second), Request: json.RawMessage(`{}`)},
		{Type: "net_connect", Decision: "deny", Timestamp: now.Add(2 * time.Second), Request: json.RawMessage(`{}`)},
	}

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	for _, e := range events {
		enc.Encode(e)
	}
	f.Close()

	stats, err := GetRecordingStats(path)
	if err != nil {
		t.Fatalf("GetRecordingStats error: %v", err)
	}

	if stats.EventCount != 3 {
		t.Errorf("EventCount = %d, want 3", stats.EventCount)
	}
	if stats.EventsByType["file_read"] != 2 {
		t.Errorf("EventsByType[file_read] = %d, want 2", stats.EventsByType["file_read"])
	}
	if stats.DecisionCount["allow"] != 2 {
		t.Errorf("DecisionCount[allow] = %d, want 2", stats.DecisionCount["allow"])
	}
	if stats.SessionID != "sess-1" {
		t.Errorf("SessionID = %q, want sess-1", stats.SessionID)
	}
}

func TestGetRecordingStats_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")

	os.WriteFile(path, []byte{}, 0644)

	stats, err := GetRecordingStats(path)
	if err != nil {
		t.Fatalf("GetRecordingStats error: %v", err)
	}

	if stats.EventCount != 0 {
		t.Errorf("EventCount = %d, want 0", stats.EventCount)
	}
}
