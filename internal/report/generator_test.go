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
