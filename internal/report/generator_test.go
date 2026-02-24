package report

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

type mockEventStore struct {
	events []types.Event
}

func (m *mockEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return m.events, nil
}

func (m *mockEventStore) AppendEvent(ctx context.Context, ev types.Event) error { return nil }
func (m *mockEventStore) Close() error                                         { return nil }

func TestGenerateSummaryReport(t *testing.T) {
	store := &mockEventStore{
		events: []types.Event{
			{ID: "1", Type: "file_read", Path: "/workspace/main.go", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
			{ID: "2", Type: "file_write", Path: "/workspace/main.go", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
			{ID: "3", Type: "net_connect", Domain: "api.github.com", Remote: "api.github.com:443", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		},
	}

	sess := types.Session{
		ID:        "test-session",
		State:     types.SessionStateCompleted,
		CreatedAt: time.Now().Add(-10 * time.Minute),
		Policy:    "default",
	}

	gen := NewGenerator(store)
	report, err := gen.Generate(context.Background(), sess, LevelSummary)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if report.SessionID != "test-session" {
		t.Errorf("wrong session ID: %s", report.SessionID)
	}
	if report.Level != LevelSummary {
		t.Errorf("wrong level: %s", report.Level)
	}
	if report.Decisions.Allowed != 3 {
		t.Errorf("expected 3 allowed, got %d", report.Decisions.Allowed)
	}
	if report.Activity.FileOps != 2 {
		t.Errorf("expected 2 file ops, got %d", report.Activity.FileOps)
	}
	if report.Activity.NetworkOps != 1 {
		t.Errorf("expected 1 network op, got %d", report.Activity.NetworkOps)
	}
}

func TestExtractMCPSummary_AllEventTypes(t *testing.T) {
	events := []types.Event{
		// mcp_tool_seen — existing
		{
			ID: "1", Type: "mcp_tool_seen",
			Fields: map[string]any{
				"server_id": "weather", "tool_name": "get_weather",
				"tool_hash": "sha256:abc",
			},
		},
		// mcp_tool_changed — existing
		{ID: "2", Type: "mcp_tool_changed", Fields: map[string]any{
			"server_id": "weather", "tool_name": "get_weather",
			"new_hash": "sha256:def",
		}},
		// mcp_tool_called — NEW
		{ID: "3", Type: "mcp_tool_called", Fields: map[string]any{
			"server_id": "weather", "tool_name": "get_weather",
		}},
		// mcp_tool_call_intercepted allow — NEW
		{ID: "4", Type: "mcp_tool_call_intercepted", Fields: map[string]any{
			"server_id": "weather", "tool_name": "get_weather",
			"action": "allow",
		}},
		// mcp_tool_call_intercepted block — NEW
		{ID: "5", Type: "mcp_tool_call_intercepted", Fields: map[string]any{
			"server_id": "weather", "tool_name": "get_weather",
			"action": "block", "reason": "version_pin",
		}},
		// mcp_cross_server_blocked — NEW
		{ID: "6", Type: "mcp_cross_server_blocked", Fields: map[string]any{
			"rule":              "read_then_send",
			"severity":          "critical",
			"blocked_server_id": "evil-server",
			"blocked_tool_name": "exfiltrate",
			"reason":            "cross-server data flow",
		}},
		// mcp_network_connection — NEW
		{ID: "7", Type: "mcp_network_connection", Fields: map[string]any{
			"server_id": "api-server",
		}},
		{ID: "8", Type: "mcp_network_connection", Fields: map[string]any{
			"server_id": "api-server",
		}},
	}

	summary := extractMCPSummary(events)
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if summary.ToolsSeen != 1 {
		t.Errorf("ToolsSeen: got %d, want 1", summary.ToolsSeen)
	}
	if summary.ChangedTools != 1 {
		t.Errorf("ChangedTools: got %d, want 1", summary.ChangedTools)
	}
	if summary.ToolCallsTotal != 1 {
		t.Errorf("ToolCallsTotal: got %d, want 1", summary.ToolCallsTotal)
	}
	if summary.InterceptedTotal != 2 {
		t.Errorf("InterceptedTotal: got %d, want 2", summary.InterceptedTotal)
	}
	if summary.InterceptedBlocked != 1 {
		t.Errorf("InterceptedBlocked: got %d, want 1", summary.InterceptedBlocked)
	}
	if summary.CrossServerBlocked != 1 {
		t.Errorf("CrossServerBlocked: got %d, want 1", summary.CrossServerBlocked)
	}
	if summary.NetworkConnections != 2 {
		t.Errorf("NetworkConnections: got %d, want 2", summary.NetworkConnections)
	}
}

func TestExtractMCPSummary_OnlyNewEvents(t *testing.T) {
	// Verify that a session with only intercepted/cross-server events
	// still returns a non-nil summary (guard relaxation).
	events := []types.Event{
		{ID: "1", Type: "mcp_tool_call_intercepted", Fields: map[string]any{
			"server_id": "s", "tool_name": "t", "action": "block",
		}},
	}

	summary := extractMCPSummary(events)
	if summary == nil {
		t.Fatal("expected non-nil summary for intercepted-only events")
	}
	if summary.InterceptedTotal != 1 {
		t.Errorf("InterceptedTotal: got %d, want 1", summary.InterceptedTotal)
	}
	if summary.InterceptedBlocked != 1 {
		t.Errorf("InterceptedBlocked: got %d, want 1", summary.InterceptedBlocked)
	}
}

func TestGenerateDetailedReport(t *testing.T) {
	store := &mockEventStore{
		events: []types.Event{
			{ID: "1", Type: "file_read", Path: "/workspace/main.go", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		},
	}

	sess := types.Session{
		ID:        "test-session",
		State:     types.SessionStateCompleted,
		CreatedAt: time.Now().Add(-10 * time.Minute),
	}

	gen := NewGenerator(store)
	report, err := gen.Generate(context.Background(), sess, LevelDetailed)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(report.Timeline) != 1 {
		t.Errorf("expected timeline with 1 event, got %d", len(report.Timeline))
	}
	if report.AllFilePaths == nil {
		t.Error("expected AllFilePaths to be populated")
	}
}
