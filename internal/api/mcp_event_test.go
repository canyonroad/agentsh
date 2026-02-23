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

func TestMCPCrossServerToEvent(t *testing.T) {
	ts := time.Date(2026, 2, 23, 10, 30, 0, 0, time.UTC)
	relatedTS := time.Date(2026, 2, 23, 10, 29, 55, 0, time.UTC)
	ev := mcpinspect.MCPCrossServerEvent{
		Type:            "mcp_cross_server_blocked",
		Timestamp:       ts,
		SessionID:       "sess-cross-1",
		Rule:            "read_then_send",
		Severity:        "critical",
		BlockedServerID: "exfil-server",
		BlockedToolName: "send_email",
		RelatedCalls: []mcpinspect.ToolCallRecord{
			{
				Timestamp: relatedTS,
				ServerID:  "db-server",
				ToolName:  "read_secrets",
				RequestID: "req_001",
				Action:    "allow",
				Category:  "read",
			},
		},
		Reason: `Server "exfil-server" attempted send after "db-server" read data 5s ago`,
	}

	out := mcpCrossServerToEvent(ev)

	if out.ID == "" {
		t.Error("expected non-empty ID")
	}
	if out.Timestamp != ts {
		t.Errorf("timestamp: got %v, want %v", out.Timestamp, ts)
	}
	if out.Type != "mcp_cross_server_blocked" {
		t.Errorf("type: got %q, want %q", out.Type, "mcp_cross_server_blocked")
	}
	if out.SessionID != "sess-cross-1" {
		t.Errorf("session_id: got %q, want %q", out.SessionID, "sess-cross-1")
	}
	if out.Source != "llm_proxy" {
		t.Errorf("source: got %q, want %q", out.Source, "llm_proxy")
	}
	if out.Path != "send_email" {
		t.Errorf("path: got %q, want %q", out.Path, "send_email")
	}
	if out.Domain != "exfil-server" {
		t.Errorf("domain: got %q, want %q", out.Domain, "exfil-server")
	}
	if out.EffectiveAction != "block" {
		t.Errorf("effective_action: got %q, want %q", out.EffectiveAction, "block")
	}

	// Policy checks
	if out.Policy == nil {
		t.Fatal("expected non-nil Policy")
	}
	if out.Policy.Decision != types.DecisionDeny {
		t.Errorf("policy.decision: got %q, want %q", out.Policy.Decision, types.DecisionDeny)
	}
	if out.Policy.EffectiveDecision != types.DecisionDeny {
		t.Errorf("policy.effective_decision: got %q, want %q", out.Policy.EffectiveDecision, types.DecisionDeny)
	}
	if out.Policy.Rule != "cross_server_read_then_send" {
		t.Errorf("policy.rule: got %q, want %q", out.Policy.Rule, "cross_server_read_then_send")
	}
	if out.Policy.Message != ev.Reason {
		t.Errorf("policy.message: got %q, want %q", out.Policy.Message, ev.Reason)
	}

	// Fields checks
	expectedKeys := []string{"rule", "severity", "blocked_server_id", "blocked_tool_name", "reason", "related_calls"}
	for _, k := range expectedKeys {
		if _, ok := out.Fields[k]; !ok {
			t.Errorf("fields missing key %q", k)
		}
	}
	if out.Fields["rule"] != "read_then_send" {
		t.Errorf("fields.rule: got %v, want %q", out.Fields["rule"], "read_then_send")
	}
	if out.Fields["severity"] != "critical" {
		t.Errorf("fields.severity: got %v, want %q", out.Fields["severity"], "critical")
	}
	if out.Fields["blocked_server_id"] != "exfil-server" {
		t.Errorf("fields.blocked_server_id: got %v, want %q", out.Fields["blocked_server_id"], "exfil-server")
	}
	if out.Fields["blocked_tool_name"] != "send_email" {
		t.Errorf("fields.blocked_tool_name: got %v, want %q", out.Fields["blocked_tool_name"], "send_email")
	}

	// Verify related_calls is a slice with one entry
	rc, ok := out.Fields["related_calls"].([]map[string]any)
	if !ok {
		t.Fatalf("related_calls: expected []map[string]any, got %T", out.Fields["related_calls"])
	}
	if len(rc) != 1 {
		t.Fatalf("related_calls: expected 1 entry, got %d", len(rc))
	}
	if rc[0]["server_id"] != "db-server" {
		t.Errorf("related_calls[0].server_id: got %v, want %q", rc[0]["server_id"], "db-server")
	}
	if rc[0]["tool_name"] != "read_secrets" {
		t.Errorf("related_calls[0].tool_name: got %v, want %q", rc[0]["tool_name"], "read_secrets")
	}
	if rc[0]["category"] != "read" {
		t.Errorf("related_calls[0].category: got %v, want %q", rc[0]["category"], "read")
	}
}

func TestMCPCrossServerToEvent_EmptyRelatedCalls(t *testing.T) {
	ts := time.Date(2026, 2, 23, 11, 0, 0, 0, time.UTC)
	ev := mcpinspect.MCPCrossServerEvent{
		Type:            "mcp_cross_server_blocked",
		Timestamp:       ts,
		SessionID:       "sess-cross-2",
		Rule:            "shadow_tool",
		Severity:        "critical",
		BlockedServerID: "evil-server",
		BlockedToolName: "read_file",
		RelatedCalls:    nil,
		Reason:          `Tool "read_file" was shadowed`,
	}

	out := mcpCrossServerToEvent(ev)

	if out.Policy.Rule != "cross_server_shadow_tool" {
		t.Errorf("policy.rule: got %q, want %q", out.Policy.Rule, "cross_server_shadow_tool")
	}

	rc, ok := out.Fields["related_calls"].([]map[string]any)
	if !ok {
		t.Fatalf("related_calls: expected []map[string]any, got %T", out.Fields["related_calls"])
	}
	if len(rc) != 0 {
		t.Errorf("related_calls: expected 0 entries, got %d", len(rc))
	}
}

func TestMCPCrossServerToEvent_CrossServerFlowNoDoublePrefix(t *testing.T) {
	ev := mcpinspect.MCPCrossServerEvent{
		Type:            "mcp_cross_server_blocked",
		Timestamp:       time.Now(),
		SessionID:       "sess-cross-3",
		Rule:            "cross_server_flow",
		Severity:        "high",
		BlockedServerID: "attacker-server",
		BlockedToolName: "exec_cmd",
		Reason:          "cross-server data flow detected",
	}

	out := mcpCrossServerToEvent(ev)

	// Must NOT double-prefix to "cross_server_cross_server_flow".
	if out.Policy.Rule != "cross_server_flow" {
		t.Errorf("policy.rule: got %q, want %q (should not double-prefix)", out.Policy.Rule, "cross_server_flow")
	}
}
