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

func TestGenerator_MCPEvents(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		// mcp_tool_seen with hash
		{ID: "1", Type: "mcp_tool_seen", Timestamp: now, Fields: map[string]any{
			"server_id": "weather", "tool_name": "get_weather",
			"tool_hash": "sha256:abc123", "server_type": "stdio",
		}},
		// mcp_tool_seen — different tool, same server
		{ID: "2", Type: "mcp_tool_seen", Timestamp: now.Add(time.Second), Fields: map[string]any{
			"server_id": "weather", "tool_name": "get_forecast",
			"tool_hash": "sha256:def456", "server_type": "stdio",
		}},
		// mcp_tool_called — confirms usage
		{ID: "3", Type: "mcp_tool_called", Timestamp: now.Add(2 * time.Second), Fields: map[string]any{
			"server_id": "weather", "tool_name": "get_weather",
		}},
		// mcp_tool_call_intercepted — allowed
		{ID: "4", Type: "mcp_tool_call_intercepted", Timestamp: now.Add(3 * time.Second), Fields: map[string]any{
			"server_id": "weather", "tool_name": "get_weather",
			"action": "allow", "tool_hash": "sha256:abc123",
		}},
		// mcp_tool_call_intercepted — blocked
		{ID: "5", Type: "mcp_tool_call_intercepted", Timestamp: now.Add(4 * time.Second), Fields: map[string]any{
			"server_id": "weather", "tool_name": "execute_cmd",
			"action": "block", "reason": "version_pin",
		}},
		// mcp_tool_changed — triggers version pinning
		{ID: "6", Type: "mcp_tool_changed", Timestamp: now.Add(5 * time.Second), Fields: map[string]any{
			"server_id": "weather", "tool_name": "get_weather",
			"new_hash": "sha256:changed",
		}},
		// mcp_cross_server_blocked
		{ID: "7", Type: "mcp_cross_server_blocked", Timestamp: now.Add(6 * time.Second), Fields: map[string]any{
			"rule": "read_then_send", "severity": "critical",
			"blocked_server_id": "evil", "blocked_tool_name": "exfil",
		}},
		// mcp_network_connection
		{ID: "8", Type: "mcp_network_connection", Timestamp: now.Add(7 * time.Second), Fields: map[string]any{
			"server_id": "weather",
		}},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	policy, err := gen.Generate(context.Background(), sess, DefaultOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have MCP tool rules (from mcp_tool_seen)
	if len(policy.MCPToolRules) != 2 {
		t.Errorf("expected 2 MCP tool rules, got %d", len(policy.MCPToolRules))
	}

	// Should have blocked tools (from intercepted block)
	if len(policy.MCPBlockedTools) != 1 {
		t.Errorf("expected 1 blocked MCP tool, got %d", len(policy.MCPBlockedTools))
	}
	if len(policy.MCPBlockedTools) > 0 && policy.MCPBlockedTools[0].BlockReason != "version_pin" {
		t.Errorf("expected block reason 'version_pin', got %q", policy.MCPBlockedTools[0].BlockReason)
	}

	// Should have servers
	if len(policy.MCPServers) == 0 {
		t.Error("expected MCP servers")
	}

	// Should have MCP config
	if policy.MCPConfig == nil {
		t.Fatal("expected MCPConfig to be set")
	}
	if !policy.MCPConfig.VersionPinning {
		t.Error("expected version pinning to be enabled (mcp_tool_changed present)")
	}
	if policy.MCPConfig.VersionOnChange != "block" {
		t.Errorf("expected version on_change 'block', got %q", policy.MCPConfig.VersionOnChange)
	}
	if !policy.MCPConfig.CrossServer {
		t.Error("expected cross-server to be enabled")
	}
}

func TestGenerator_MCPEvents_NoMCPActivity(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		{Type: "file_read", Path: "/workspace/main.go", Timestamp: now,
			Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	policy, err := gen.Generate(context.Background(), sess, DefaultOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policy.MCPToolRules) != 0 {
		t.Error("expected no MCP tool rules for non-MCP session")
	}
	if policy.MCPConfig != nil {
		t.Error("expected nil MCPConfig for non-MCP session")
	}
}
