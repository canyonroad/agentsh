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

func TestGenerator_CommandRulesWithRiskyDetection(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		{
			ID:        "cmd-1",
			Type:      "exec",
			Path:      "/usr/bin/curl",
			Timestamp: now,
			Fields:    map[string]interface{}{"command": "curl"},
			Policy:    &types.PolicyInfo{Decision: types.DecisionAllow},
		},
		{
			ID:        "cmd-2",
			Type:      "exec",
			Path:      "/usr/bin/ls",
			Timestamp: now.Add(time.Second),
			Fields:    map[string]interface{}{"command": "ls"},
			Policy:    &types.PolicyInfo{Decision: types.DecisionAllow},
		},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	policy, err := gen.Generate(context.Background(), sess, DefaultOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policy.CommandRules) == 0 {
		t.Fatal("expected command rules to be generated")
	}

	// Find curl rule - should be marked as risky
	var curlRule *CommandRuleGen
	var lsRule *CommandRuleGen
	for i := range policy.CommandRules {
		if policy.CommandRules[i].Name == "curl" {
			curlRule = &policy.CommandRules[i]
		}
		if policy.CommandRules[i].Name == "ls" {
			lsRule = &policy.CommandRules[i]
		}
	}

	if curlRule == nil {
		t.Fatal("expected curl command rule")
	}
	if !curlRule.Risky {
		t.Error("expected curl to be marked as risky")
	}
	if curlRule.RiskyReason != "network" {
		t.Errorf("expected curl risky reason 'network', got %q", curlRule.RiskyReason)
	}

	if lsRule == nil {
		t.Fatal("expected ls command rule")
	}
	if lsRule.Risky {
		t.Error("expected ls to NOT be marked as risky")
	}
}
