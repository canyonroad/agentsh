package simulation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// RecordedEvent represents a recorded operation event.
type RecordedEvent struct {
	Timestamp  time.Time       `json:"ts"`
	Type       string          `json:"type"`
	SessionID  string          `json:"session_id,omitempty"`
	AgentID    string          `json:"agent_id,omitempty"`
	Request    json.RawMessage `json:"request"`
	Decision   string          `json:"decision"`
	PolicyRule string          `json:"policy_rule,omitempty"`
	Latency    time.Duration   `json:"latency_ns"`
}

// SessionRecorder records session events to a file.
type SessionRecorder struct {
	sessionID  string
	output     io.WriteCloser
	encoder    *json.Encoder
	mu         sync.Mutex
	eventCount int
	startTime  time.Time
	closed     bool
}

// RecorderConfig configures the session recorder.
type RecorderConfig struct {
	SessionID  string
	OutputPath string
	Append     bool
}

// NewSessionRecorder creates a new session recorder.
func NewSessionRecorder(config RecorderConfig) (*SessionRecorder, error) {
	flags := os.O_CREATE | os.O_WRONLY
	if config.Append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	file, err := os.OpenFile(config.OutputPath, flags, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening output file: %w", err)
	}

	return &SessionRecorder{
		sessionID: config.SessionID,
		output:    file,
		encoder:   json.NewEncoder(file),
		startTime: time.Now(),
	}, nil
}

// NewSessionRecorderWriter creates a recorder with a custom writer.
func NewSessionRecorderWriter(sessionID string, w io.WriteCloser) *SessionRecorder {
	return &SessionRecorder{
		sessionID: sessionID,
		output:    w,
		encoder:   json.NewEncoder(w),
		startTime: time.Now(),
	}
}

// Record records an event.
func (r *SessionRecorder) Record(op *Operation, decision Decision, policyRule string, latency time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("recorder is closed")
	}

	request, err := json.Marshal(op)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	event := RecordedEvent{
		Timestamp:  time.Now(),
		Type:       op.Type,
		SessionID:  r.sessionID,
		Request:    request,
		Decision:   string(decision),
		PolicyRule: policyRule,
		Latency:    latency,
	}

	if err := r.encoder.Encode(event); err != nil {
		return fmt.Errorf("encoding event: %w", err)
	}

	r.eventCount++
	return nil
}

// RecordRaw records a raw event.
func (r *SessionRecorder) RecordRaw(event RecordedEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("recorder is closed")
	}

	if err := r.encoder.Encode(event); err != nil {
		return fmt.Errorf("encoding event: %w", err)
	}

	r.eventCount++
	return nil
}

// EventCount returns the number of recorded events.
func (r *SessionRecorder) EventCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.eventCount
}

// Duration returns the recording duration.
func (r *SessionRecorder) Duration() time.Duration {
	return time.Since(r.startTime)
}

// Close closes the recorder.
func (r *SessionRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	r.closed = true
	return r.output.Close()
}

// SessionReplayer replays recorded sessions against a policy.
type SessionReplayer struct {
	recordingPath string
	evaluator     PolicyEvaluator
}

// ReplayResults contains the results of replaying a session.
type ReplayResults struct {
	TotalEvents int          `json:"total_events"`
	Matched     int          `json:"matched"`
	Differences []Difference `json:"differences,omitempty"`
	Errors      []string     `json:"errors,omitempty"`
}

// Difference describes a decision difference during replay.
type Difference struct {
	Event       RecordedEvent `json:"event"`
	OldDecision string        `json:"old_decision"`
	NewDecision string        `json:"new_decision"`
	OldRule     string        `json:"old_rule,omitempty"`
	NewRule     string        `json:"new_rule,omitempty"`
}

// NewSessionReplayer creates a new session replayer.
func NewSessionReplayer(recordingPath string, evaluator PolicyEvaluator) *SessionReplayer {
	return &SessionReplayer{
		recordingPath: recordingPath,
		evaluator:     evaluator,
	}
}

// Replay replays the recorded session and compares decisions.
func (r *SessionReplayer) Replay() (*ReplayResults, error) {
	file, err := os.Open(r.recordingPath)
	if err != nil {
		return nil, fmt.Errorf("opening recording: %w", err)
	}
	defer file.Close()

	return r.ReplayReader(file)
}

// ReplayReader replays from a reader.
func (r *SessionReplayer) ReplayReader(reader io.Reader) (*ReplayResults, error) {
	results := &ReplayResults{}
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event RecordedEvent
		if err := json.Unmarshal(line, &event); err != nil {
			results.Errors = append(results.Errors, fmt.Sprintf("parsing event: %v", err))
			continue
		}

		results.TotalEvents++

		// Parse the request back to an Operation
		var op Operation
		if err := json.Unmarshal(event.Request, &op); err != nil {
			results.Errors = append(results.Errors, fmt.Sprintf("parsing request: %v", err))
			continue
		}

		// Evaluate with current policy
		newResult := r.evaluator.Evaluate(&op)

		if newResult.Decision == event.Decision {
			results.Matched++
		} else {
			results.Differences = append(results.Differences, Difference{
				Event:       event,
				OldDecision: event.Decision,
				NewDecision: newResult.Decision,
				OldRule:     event.PolicyRule,
				NewRule:     newResult.PolicyRule,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading recording: %w", err)
	}

	return results, nil
}

// Summary returns a human-readable summary.
func (r *ReplayResults) Summary() string {
	if r.TotalEvents == 0 {
		return "No events replayed"
	}

	diffCount := len(r.Differences)
	if diffCount == 0 {
		return fmt.Sprintf("MATCH: All %d events matched", r.TotalEvents)
	}

	return fmt.Sprintf("DIFF: %d/%d events differ (%d matched)",
		diffCount, r.TotalEvents, r.Matched)
}

// HasDifferences returns true if there are any differences.
func (r *ReplayResults) HasDifferences() bool {
	return len(r.Differences) > 0
}

// LoadRecording loads all events from a recording file.
func LoadRecording(path string) ([]RecordedEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []RecordedEvent
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event RecordedEvent
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		events = append(events, event)
	}

	return events, scanner.Err()
}

// RecordingStats returns statistics about a recording.
type RecordingStats struct {
	EventCount    int                  `json:"event_count"`
	Duration      time.Duration        `json:"duration"`
	FirstEvent    time.Time            `json:"first_event"`
	LastEvent     time.Time            `json:"last_event"`
	EventsByType  map[string]int       `json:"events_by_type"`
	DecisionCount map[string]int       `json:"decisions"`
	SessionID     string               `json:"session_id,omitempty"`
}

// GetRecordingStats returns statistics about a recording file.
func GetRecordingStats(path string) (*RecordingStats, error) {
	events, err := LoadRecording(path)
	if err != nil {
		return nil, err
	}

	if len(events) == 0 {
		return &RecordingStats{}, nil
	}

	stats := &RecordingStats{
		EventCount:    len(events),
		EventsByType:  make(map[string]int),
		DecisionCount: make(map[string]int),
		FirstEvent:    events[0].Timestamp,
		LastEvent:     events[len(events)-1].Timestamp,
		SessionID:     events[0].SessionID,
	}

	for _, e := range events {
		stats.EventsByType[e.Type]++
		stats.DecisionCount[e.Decision]++
	}

	stats.Duration = stats.LastEvent.Sub(stats.FirstEvent)

	return stats, nil
}
