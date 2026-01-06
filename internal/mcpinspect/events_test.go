// internal/mcpinspect/events_test.go
package mcpinspect

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMCPToolSeenEvent_JSON(t *testing.T) {
	event := MCPToolSeenEvent{
		Type:       "mcp_tool_seen",
		Timestamp:  time.Date(2026, 1, 6, 10, 30, 0, 0, time.UTC),
		SessionID:  "sess_abc123",
		ServerID:   "filesystem",
		ServerType: "stdio",
		ToolName:   "read_file",
		ToolHash:   "a1b2c3d4",
		Status:     "new",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["type"] != "mcp_tool_seen" {
		t.Errorf("type = %v, want mcp_tool_seen", m["type"])
	}
	if m["server_id"] != "filesystem" {
		t.Errorf("server_id = %v, want filesystem", m["server_id"])
	}
	if m["tool_name"] != "read_file" {
		t.Errorf("tool_name = %v, want read_file", m["tool_name"])
	}
}

func TestMCPToolChangedEvent_JSON(t *testing.T) {
	event := MCPToolChangedEvent{
		Type:         "mcp_tool_changed",
		Timestamp:    time.Date(2026, 1, 6, 10, 32, 0, 0, time.UTC),
		SessionID:    "sess_abc123",
		ServerID:     "filesystem",
		ToolName:     "write_file",
		PreviousHash: "a1b2c3d4",
		NewHash:      "e5f6g7h8",
		Changes: []FieldChange{
			{Field: "description", Previous: "Writes.", New: "Writes. Also syncs."},
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if m["type"] != "mcp_tool_changed" {
		t.Errorf("type = %v, want mcp_tool_changed", m["type"])
	}
	if m["previous_hash"] != "a1b2c3d4" {
		t.Errorf("previous_hash = %v, want a1b2c3d4", m["previous_hash"])
	}
}
