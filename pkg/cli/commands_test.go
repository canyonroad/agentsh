package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// mockClient implements Client for testing.
type mockClient struct {
	sessions       []SessionInfo
	sessionDetail  *SessionDetail
	events         []Event
	status         *Status
	metrics        *Metrics
	config         map[string]any
	validationErr  error
	testResults    *TestResults
	policyDiff     *PolicyDiff
	lintIssues     []LintIssue
	simulationResult *SimulationResult
}

func (m *mockClient) ListSessions(ctx context.Context, opts ListSessionsOpts) ([]SessionInfo, error) {
	return m.sessions, nil
}

func (m *mockClient) GetSession(ctx context.Context, id string) (*SessionDetail, error) {
	return m.sessionDetail, nil
}

func (m *mockClient) GetSessionLogs(ctx context.Context, id string, follow bool) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("log line 1\nlog line 2\n")), nil
}

func (m *mockClient) GetSessionEvents(ctx context.Context, id string, opts EventsOpts) ([]Event, error) {
	return m.events, nil
}

func (m *mockClient) TerminateSession(ctx context.Context, id string, force bool, reason string) error {
	return nil
}

func (m *mockClient) ValidatePolicy(ctx context.Context, path string) (*ValidationResult, error) {
	if m.validationErr != nil {
		return &ValidationResult{Valid: false, Errors: []string{m.validationErr.Error()}}, nil
	}
	return &ValidationResult{Valid: true}, nil
}

func (m *mockClient) TestPolicy(ctx context.Context, policyDir, testDir string) (*TestResults, error) {
	if m.testResults != nil {
		return m.testResults, nil
	}
	return &TestResults{Passed: 5, Total: 5}, nil
}

func (m *mockClient) DiffPolicies(ctx context.Context, oldPath, newPath string) (*PolicyDiff, error) {
	if m.policyDiff != nil {
		return m.policyDiff, nil
	}
	return &PolicyDiff{}, nil
}

func (m *mockClient) LintPolicy(ctx context.Context, path string) ([]LintIssue, error) {
	return m.lintIssues, nil
}

func (m *mockClient) TraceSession(ctx context.Context, id string, duration time.Duration) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (m *mockClient) SimulateRecording(ctx context.Context, recordingPath, policyDir string) (*SimulationResult, error) {
	if m.simulationResult != nil {
		return m.simulationResult, nil
	}
	return &SimulationResult{TotalEvents: 10, Matched: 10}, nil
}

func (m *mockClient) GetStatus(ctx context.Context) (*Status, error) {
	if m.status != nil {
		return m.status, nil
	}
	return &Status{
		Version:        "1.0.0",
		Uptime:         "1h30m",
		Platform:       "linux",
		ActiveSessions: 5,
		Healthy:        true,
	}, nil
}

func (m *mockClient) GetMetrics(ctx context.Context) (*Metrics, error) {
	if m.metrics != nil {
		return m.metrics, nil
	}
	return &Metrics{
		SessionsTotal:  100,
		SessionsActive: 5,
		OperationsTotal: 10000,
	}, nil
}

func (m *mockClient) ValidateConfig(ctx context.Context) error {
	return m.validationErr
}

func (m *mockClient) GetConfig(ctx context.Context, effective bool) (map[string]any, error) {
	if m.config != nil {
		return m.config, nil
	}
	return map[string]any{"key": "value"}, nil
}

func (m *mockClient) SetConfig(ctx context.Context, key, value string) error {
	return nil
}

func TestNewCommander(t *testing.T) {
	client := &mockClient{}
	buf := &bytes.Buffer{}

	cmd := NewCommander(client, buf)
	if cmd == nil {
		t.Fatal("expected non-nil commander")
	}
}

func TestCommander_SessionList(t *testing.T) {
	client := &mockClient{
		sessions: []SessionInfo{
			{ID: "sess-1", AgentID: "agent-1", State: "running", Duration: "10m"},
			{ID: "sess-2", AgentID: "agent-2", State: "stopped", Duration: "5m"},
		},
	}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)

	ctx := context.Background()
	if err := cmd.SessionList(ctx, ListSessionsOpts{}); err != nil {
		t.Fatalf("SessionList error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "sess-1") {
		t.Error("output should contain sess-1")
	}
	if !strings.Contains(output, "agent-1") {
		t.Error("output should contain agent-1")
	}
}

func TestCommander_SessionList_JSON(t *testing.T) {
	client := &mockClient{
		sessions: []SessionInfo{
			{ID: "sess-1", State: "running"},
		},
	}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)
	cmd.SetJSONOutput(true)

	ctx := context.Background()
	if err := cmd.SessionList(ctx, ListSessionsOpts{}); err != nil {
		t.Fatalf("SessionList error: %v", err)
	}

	var sessions []SessionInfo
	if err := json.Unmarshal(buf.Bytes(), &sessions); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(sessions) != 1 || sessions[0].ID != "sess-1" {
		t.Error("unexpected JSON output")
	}
}

func TestCommander_SessionList_Empty(t *testing.T) {
	client := &mockClient{sessions: []SessionInfo{}}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)

	ctx := context.Background()
	cmd.SessionList(ctx, ListSessionsOpts{})

	if !strings.Contains(buf.String(), "No sessions found") {
		t.Error("should show no sessions message")
	}
}

func TestCommander_SessionGet(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running", AgentID: "agent-1"},
			EventCount:  100,
			ResourceUsage: &ResourceUsage{
				CPUPercent: 25.5,
				MemoryMB:   512,
			},
		},
	}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)

	ctx := context.Background()
	if err := cmd.SessionGet(ctx, "sess-1"); err != nil {
		t.Fatalf("SessionGet error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "sess-1") {
		t.Error("output should contain session ID")
	}
	if !strings.Contains(output, "25.5%") {
		t.Error("output should contain CPU usage")
	}
}

func TestCommander_SessionEvents(t *testing.T) {
	client := &mockClient{
		events: []Event{
			{Type: "file_read", Path: "/test/file.txt", Decision: "allow", Latency: "0.5ms"},
		},
	}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)

	ctx := context.Background()
	if err := cmd.SessionEvents(ctx, "sess-1", EventsOpts{}); err != nil {
		t.Fatalf("SessionEvents error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "file_read") {
		t.Error("output should contain event type")
	}
}

func TestCommander_PolicyValidate(t *testing.T) {
	client := &mockClient{}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)

	ctx := context.Background()
	if err := cmd.PolicyValidate(ctx, "/path/to/policy.yaml"); err != nil {
		t.Fatalf("PolicyValidate error: %v", err)
	}

	if !strings.Contains(buf.String(), "valid") {
		t.Error("should show valid message")
	}
}

func TestCommander_PolicyTest(t *testing.T) {
	client := &mockClient{
		testResults: &TestResults{Passed: 3, Failed: 1, Total: 4},
	}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)

	ctx := context.Background()
	err := cmd.PolicyTest(ctx, "/policy", "/tests")

	// Should return error because there are failures
	if err == nil {
		t.Error("should return error on test failures")
	}

	if !strings.Contains(buf.String(), "FAIL") {
		t.Error("should show FAIL status")
	}
}

func TestCommander_PolicyDiff(t *testing.T) {
	client := &mockClient{
		policyDiff: &PolicyDiff{
			Added:   []string{"rule1"},
			Removed: []string{"rule2"},
		},
	}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)

	ctx := context.Background()
	if err := cmd.PolicyDiff(ctx, "/old", "/new"); err != nil {
		t.Fatalf("PolicyDiff error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "+ rule1") {
		t.Error("should show added rules")
	}
	if !strings.Contains(output, "- rule2") {
		t.Error("should show removed rules")
	}
}

func TestCommander_StatusShow(t *testing.T) {
	client := &mockClient{
		status: &Status{
			Version:        "1.0.0",
			Uptime:         "2h",
			Platform:       "linux",
			ActiveSessions: 3,
			Healthy:        true,
		},
	}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)

	ctx := context.Background()
	if err := cmd.StatusShow(ctx); err != nil {
		t.Fatalf("StatusShow error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "1.0.0") {
		t.Error("should show version")
	}
	if !strings.Contains(output, "linux") {
		t.Error("should show platform")
	}
}

func TestCommander_MetricsShow(t *testing.T) {
	client := &mockClient{
		metrics: &Metrics{
			SessionsTotal:    100,
			SessionsActive:   5,
			OperationsTotal:  10000,
			OperationsByType: map[string]int64{"file_read": 5000},
		},
	}
	buf := &bytes.Buffer{}
	cmd := NewCommander(client, buf)

	ctx := context.Background()
	if err := cmd.MetricsShow(ctx); err != nil {
		t.Fatalf("MetricsShow error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "100") {
		t.Error("should show total sessions")
	}
	if !strings.Contains(output, "file_read") {
		t.Error("should show operations by type")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{2*time.Hour + 30*time.Minute, "2h30m"},
		{26 * time.Hour, "1d2h"},
	}

	for _, tt := range tests {
		got := FormatDuration(tt.d)
		if got != tt.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestTruncatePath(t *testing.T) {
	tests := []struct {
		path   string
		maxLen int
		want   string
	}{
		{"/short", 20, "/short"},
		{"/very/long/path/to/file.txt", 20, ".../path/to/file.txt"},
	}

	for _, tt := range tests {
		got := TruncatePath(tt.path, tt.maxLen)
		if got != tt.want {
			t.Errorf("TruncatePath(%q, %d) = %q, want %q", tt.path, tt.maxLen, got, tt.want)
		}
	}
}

func TestParseKeyValue(t *testing.T) {
	k, v, err := ParseKeyValue("key=value")
	if err != nil {
		t.Fatalf("ParseKeyValue error: %v", err)
	}
	if k != "key" || v != "value" {
		t.Errorf("got (%q, %q), want (key, value)", k, v)
	}

	_, _, err = ParseKeyValue("invalid")
	if err == nil {
		t.Error("should error on invalid format")
	}
}
