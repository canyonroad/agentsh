package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestMCPInterceptedToEvent_Allow(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	ev := mcpinspect.MCPToolCallInterceptedEvent{
		Type:       "mcp_tool_call_intercepted",
		Timestamp:  ts,
		SessionID:  "sess-1",
		RequestID:  "req_abc123",
		Dialect:    "anthropic",
		ToolName:   "get_weather",
		ToolCallID: "toolu_01",
		Input:      json.RawMessage(`{"city":"NYC"}`),
		ServerID:   "weather-server",
		ServerType: "stdio",
		ServerAddr: "",
		ToolHash:   "sha256:deadbeef",
		Action:     "allow",
		Reason:     "",
	}

	out := mcpInterceptedToEvent(ev)

	if out.ID == "" {
		t.Error("expected non-empty ID")
	}
	if out.Timestamp != ts {
		t.Errorf("timestamp: got %v, want %v", out.Timestamp, ts)
	}
	if out.Type != "mcp_tool_call_intercepted" {
		t.Errorf("type: got %q, want %q", out.Type, "mcp_tool_call_intercepted")
	}
	if out.SessionID != "sess-1" {
		t.Errorf("session_id: got %q, want %q", out.SessionID, "sess-1")
	}
	if out.Source != "llm_proxy" {
		t.Errorf("source: got %q, want %q", out.Source, "llm_proxy")
	}
	if out.Path != "get_weather" {
		t.Errorf("path: got %q, want %q", out.Path, "get_weather")
	}
	if out.Domain != "weather-server" {
		t.Errorf("domain: got %q, want %q", out.Domain, "weather-server")
	}
	if out.EffectiveAction != "allow" {
		t.Errorf("effective_action: got %q, want %q", out.EffectiveAction, "allow")
	}
	if out.Policy == nil {
		t.Fatal("expected non-nil Policy")
	}
	if out.Policy.Decision != types.DecisionAllow {
		t.Errorf("policy.decision: got %q, want %q", out.Policy.Decision, types.DecisionAllow)
	}
	if out.Policy.EffectiveDecision != types.DecisionAllow {
		t.Errorf("policy.effective_decision: got %q, want %q", out.Policy.EffectiveDecision, types.DecisionAllow)
	}
	if out.Policy.Rule != "mcp-allow" {
		t.Errorf("policy.rule: got %q, want %q", out.Policy.Rule, "mcp-allow")
	}

	// Verify Fields contains expected keys
	expectedKeys := []string{"request_id", "dialect", "tool_name", "tool_call_id", "server_id", "server_type", "server_addr", "tool_hash", "action", "reason"}
	for _, k := range expectedKeys {
		if _, ok := out.Fields[k]; !ok {
			t.Errorf("fields missing key %q", k)
		}
	}

	// Verify Input is NOT in Fields (plan explicitly excludes it)
	if _, ok := out.Fields["input"]; ok {
		t.Error("fields should not contain 'input'")
	}
}

func TestMCPInterceptedToEvent_Block(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	ev := mcpinspect.MCPToolCallInterceptedEvent{
		Type:       "mcp_tool_call_intercepted",
		Timestamp:  ts,
		SessionID:  "sess-2",
		RequestID:  "req_xyz789",
		Dialect:    "openai",
		ToolName:   "delete_all",
		ToolCallID: "call_01",
		Input:      json.RawMessage(`{}`),
		ServerID:   "danger-server",
		ServerType: "http",
		ServerAddr: "localhost:8080",
		ToolHash:   "sha256:cafebabe",
		Action:     "block",
		Reason:     "tool not in allowlist",
	}

	out := mcpInterceptedToEvent(ev)

	if out.EffectiveAction != "block" {
		t.Errorf("effective_action: got %q, want %q", out.EffectiveAction, "block")
	}
	if out.Policy == nil {
		t.Fatal("expected non-nil Policy")
	}
	if out.Policy.Decision != types.DecisionDeny {
		t.Errorf("policy.decision: got %q, want %q", out.Policy.Decision, types.DecisionDeny)
	}
	if out.Policy.Rule != "mcp-block" {
		t.Errorf("policy.rule: got %q, want %q", out.Policy.Rule, "mcp-block")
	}
	if out.Policy.Message != "tool not in allowlist" {
		t.Errorf("policy.message: got %q, want %q", out.Policy.Message, "tool not in allowlist")
	}

	if out.Fields["server_addr"] != "localhost:8080" {
		t.Errorf("fields.server_addr: got %v, want %q", out.Fields["server_addr"], "localhost:8080")
	}
	if out.Fields["dialect"] != "openai" {
		t.Errorf("fields.dialect: got %v, want %q", out.Fields["dialect"], "openai")
	}
}
