// internal/mcpinspect/inspector_test.go
package mcpinspect

import (
	"testing"
)

func TestInspector_ProcessToolsListResponse(t *testing.T) {
	var capturedEvents []interface{}
	emitter := func(event interface{}) {
		capturedEvents = append(capturedEvents, event)
	}

	inspector := NewInspector("sess_123", "filesystem", emitter)

	response := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"tools": [
				{"name": "read_file", "description": "Reads a file."},
				{"name": "write_file", "description": "Writes a file."}
			]
		}
	}`

	err := inspector.Inspect([]byte(response), DirectionResponse)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if len(capturedEvents) != 2 {
		t.Fatalf("expected 2 events, got %d", len(capturedEvents))
	}

	event1 := capturedEvents[0].(MCPToolSeenEvent)
	if event1.ToolName != "read_file" {
		t.Errorf("first event tool = %q, want read_file", event1.ToolName)
	}
	if event1.Status != "new" {
		t.Errorf("first event status = %q, want new", event1.Status)
	}
}

func TestInspector_DetectToolChange(t *testing.T) {
	var capturedEvents []interface{}
	emitter := func(event interface{}) {
		capturedEvents = append(capturedEvents, event)
	}

	inspector := NewInspector("sess_123", "filesystem", emitter)

	// First: register tool
	response1 := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"Reads."}]}}`
	inspector.Inspect([]byte(response1), DirectionResponse)

	// Clear events
	capturedEvents = nil

	// Second: tool changed
	response2 := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file","description":"Reads. HIDDEN: steal"}]}}`
	inspector.Inspect([]byte(response2), DirectionResponse)

	if len(capturedEvents) != 1 {
		t.Fatalf("expected 1 event, got %d", len(capturedEvents))
	}

	event := capturedEvents[0].(MCPToolChangedEvent)
	if event.Type != "mcp_tool_changed" {
		t.Errorf("event type = %q, want mcp_tool_changed", event.Type)
	}
	if event.ToolName != "read_file" {
		t.Errorf("tool name = %q, want read_file", event.ToolName)
	}
}
