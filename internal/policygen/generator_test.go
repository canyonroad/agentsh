// internal/policygen/generator_test.go
package policygen

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
func (m *mockEventStore) Close() error                                          { return nil }

func TestGenerator_EmptySession(t *testing.T) {
	store := &mockEventStore{events: nil}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	_, err := gen.Generate(context.Background(), sess, DefaultOptions())

	if err == nil {
		t.Error("expected error for empty session")
	}
}

func TestGenerator_FileEvents(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		{Type: "file_write", Path: "/workspace/src/a.ts", Timestamp: now, Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{Type: "file_write", Path: "/workspace/src/b.ts", Timestamp: now.Add(time.Second), Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{Type: "file_read", Path: "/workspace/src/c.ts", Timestamp: now.Add(2 * time.Second), Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	opts := DefaultOptions()
	opts.Threshold = 2 // Low threshold for test

	policy, err := gen.Generate(context.Background(), sess, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policy.FileRules) == 0 {
		t.Error("expected file rules to be generated")
	}
}

func TestGenerator_BlockedEvents(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		{Type: "file_write", Path: "/workspace/src/a.ts", Timestamp: now, Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{Type: "file_write", Path: "/etc/hosts", Timestamp: now.Add(time.Second), Policy: &types.PolicyInfo{Decision: types.DecisionDeny, Message: "system file"}},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	opts := DefaultOptions()
	opts.IncludeBlocked = true

	policy, err := gen.Generate(context.Background(), sess, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policy.BlockedFiles) == 0 {
		t.Error("expected blocked file rules")
	}
}

func TestGenerator_NetworkEvents(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		{Type: "net_connect", Domain: "api.github.com", Timestamp: now, Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{Type: "net_connect", Domain: "raw.github.com", Timestamp: now.Add(time.Second), Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	policy, err := gen.Generate(context.Background(), sess, DefaultOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policy.NetworkRules) == 0 {
		t.Error("expected network rules")
	}
	// Should collapse to *.github.com
	if policy.NetworkRules[0].Domains[0] != "*.github.com" {
		t.Errorf("expected '*.github.com', got %q", policy.NetworkRules[0].Domains[0])
	}
}
