package api

import (
	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// mcpInterceptedToEvent converts an MCPToolCallInterceptedEvent from the LLM
// proxy into a types.Event suitable for the event store and broker.
func mcpInterceptedToEvent(ev mcpinspect.MCPToolCallInterceptedEvent) types.Event {
	decision := types.DecisionAllow
	if ev.Action == "block" {
		decision = types.DecisionDeny
	}

	// Derive a rule identifier from the action. The proxy-level event doesn't
	// carry the matched config.MCPToolRule, so we synthesise a short label.
	rule := "mcp-" + ev.Action // "mcp-allow" or "mcp-block"

	return types.Event{
		ID:        uuid.NewString(),
		Timestamp: ev.Timestamp,
		Type:      "mcp_tool_call_intercepted",
		SessionID: ev.SessionID,
		Source:    "llm_proxy",
		Path:      ev.ToolName,
		Domain:    ev.ServerID,
		EffectiveAction: ev.Action,
		Policy: &types.PolicyInfo{
			Decision:          decision,
			EffectiveDecision: decision,
			Rule:              rule,
			Message:           ev.Reason,
		},
		Fields: map[string]any{
			"request_id":  ev.RequestID,
			"dialect":     ev.Dialect,
			"tool_name":   ev.ToolName,
			"tool_call_id": ev.ToolCallID,
			"server_id":   ev.ServerID,
			"server_type": ev.ServerType,
			"server_addr": ev.ServerAddr,
			"tool_hash":   ev.ToolHash,
			"action":      ev.Action,
			"reason":      ev.Reason,
		},
	}
}
