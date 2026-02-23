package mcpinspect

import (
	"encoding/json"
	"testing"
)

func TestParseToolsCallRequest(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantArgs string
		wantID   string // raw JSON of the ID field
		wantErr  bool
	}{
		{
			name: "valid tools/call with numeric ID",
			input: `{
				"jsonrpc": "2.0",
				"id": 42,
				"method": "tools/call",
				"params": {
					"name": "get_weather",
					"arguments": {"city": "London"}
				}
			}`,
			wantName: "get_weather",
			wantArgs: `{"city": "London"}`,
			wantID:   "42",
		},
		{
			name: "valid tools/call with string ID",
			input: `{
				"jsonrpc": "2.0",
				"id": "req-123",
				"method": "tools/call",
				"params": {
					"name": "read_file",
					"arguments": {"path": "/tmp/test.txt"}
				}
			}`,
			wantName: "read_file",
			wantArgs: `{"path": "/tmp/test.txt"}`,
			wantID:   `"req-123"`,
		},
		{
			name: "tools/call with no arguments",
			input: `{
				"jsonrpc": "2.0",
				"id": 1,
				"method": "tools/call",
				"params": {
					"name": "list_files"
				}
			}`,
			wantName: "list_files",
			wantArgs: "",
			wantID:   "1",
		},
		{
			name: "tools/call with complex arguments",
			input: `{
				"jsonrpc": "2.0",
				"id": 7,
				"method": "tools/call",
				"params": {
					"name": "execute_query",
					"arguments": {
						"query": "SELECT * FROM users",
						"params": [1, 2, 3],
						"options": {"timeout": 30}
					}
				}
			}`,
			wantName: "execute_query",
			wantArgs: `{"query": "SELECT * FROM users", "params": [1, 2, 3], "options": {"timeout": 30}}`,
			wantID:   "7",
		},
		{
			name: "tools/call with large integer ID (precision test)",
			input: `{
				"jsonrpc": "2.0",
				"id": 9007199254740993,
				"method": "tools/call",
				"params": {
					"name": "precision_test"
				}
			}`,
			wantName: "precision_test",
			wantArgs: "",
			wantID:   "9007199254740993",
		},
		{
			name:    "invalid JSON",
			input:   `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseToolsCallRequest([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if req.Params.Name != tt.wantName {
				t.Errorf("tool name = %q, want %q", req.Params.Name, tt.wantName)
			}

			if string(req.ID) != tt.wantID {
				t.Errorf("ID = %s, want %s", string(req.ID), tt.wantID)
			}

			if tt.wantArgs == "" {
				if len(req.Params.Arguments) > 0 {
					t.Errorf("expected nil/empty arguments, got %s", req.Params.Arguments)
				}
			} else {
				// Compare as normalized JSON.
				var wantParsed, gotParsed any
				if err := json.Unmarshal([]byte(tt.wantArgs), &wantParsed); err != nil {
					t.Fatalf("bad test wantArgs: %v", err)
				}
				if err := json.Unmarshal(req.Params.Arguments, &gotParsed); err != nil {
					t.Fatalf("failed to parse got arguments: %v", err)
				}
				wantBytes, _ := json.Marshal(wantParsed)
				gotBytes, _ := json.Marshal(gotParsed)
				if string(wantBytes) != string(gotBytes) {
					t.Errorf("arguments = %s, want %s", gotBytes, wantBytes)
				}
			}
		})
	}
}

func TestDetectMessageType_ToolsCall(t *testing.T) {
	data := []byte(`{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "tools/call",
		"params": {
			"name": "get_weather",
			"arguments": {"city": "London"}
		}
	}`)

	msgType, err := DetectMessageType(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != MessageToolsCall {
		t.Errorf("message type = %v, want %v", msgType, MessageToolsCall)
	}
}

func TestInspector_HandleToolsCall_EmitsEvent(t *testing.T) {
	var emitted []interface{}
	emitter := func(event interface{}) {
		emitted = append(emitted, event)
	}

	inspector := NewInspector("session-1", "server-1", emitter)

	data := []byte(`{
		"jsonrpc": "2.0",
		"id": 42,
		"method": "tools/call",
		"params": {
			"name": "get_weather",
			"arguments": {"city": "London"}
		}
	}`)

	err := inspector.Inspect(data, DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}

	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	event, ok := emitted[0].(MCPToolCalledEvent)
	if !ok {
		t.Fatalf("expected MCPToolCalledEvent, got %T", emitted[0])
	}

	if event.Type != "mcp_tool_called" {
		t.Errorf("event.Type = %q, want %q", event.Type, "mcp_tool_called")
	}
	if event.SessionID != "session-1" {
		t.Errorf("event.SessionID = %q, want %q", event.SessionID, "session-1")
	}
	if event.ServerID != "server-1" {
		t.Errorf("event.ServerID = %q, want %q", event.ServerID, "server-1")
	}
	if event.ToolName != "get_weather" {
		t.Errorf("event.ToolName = %q, want %q", event.ToolName, "get_weather")
	}

	// Check JSONRPC ID
	var id float64
	if err := json.Unmarshal(event.JSONRPCID, &id); err != nil {
		t.Fatalf("failed to unmarshal JSONRPCID: %v", err)
	}
	if id != 42 {
		t.Errorf("event.JSONRPCID = %v, want 42", id)
	}

	// Check Input
	var input map[string]interface{}
	if err := json.Unmarshal(event.Input, &input); err != nil {
		t.Fatalf("failed to unmarshal Input: %v", err)
	}
	if input["city"] != "London" {
		t.Errorf("event.Input city = %v, want London", input["city"])
	}

	if event.Timestamp.IsZero() {
		t.Error("event.Timestamp is zero")
	}
}

func TestInspector_HandleToolsCall_NoArgsEmitsEvent(t *testing.T) {
	var emitted []interface{}
	emitter := func(event interface{}) {
		emitted = append(emitted, event)
	}

	inspector := NewInspector("session-2", "server-2", emitter)

	data := []byte(`{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "tools/call",
		"params": {
			"name": "list_tools"
		}
	}`)

	err := inspector.Inspect(data, DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}

	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	event, ok := emitted[0].(MCPToolCalledEvent)
	if !ok {
		t.Fatalf("expected MCPToolCalledEvent, got %T", emitted[0])
	}

	if event.ToolName != "list_tools" {
		t.Errorf("event.ToolName = %q, want %q", event.ToolName, "list_tools")
	}

	// Input should be nil/empty when no arguments provided
	if len(event.Input) > 0 {
		t.Errorf("expected nil/empty Input, got %s", event.Input)
	}
}

func TestInspector_HandleToolsCall_StringID(t *testing.T) {
	var emitted []interface{}
	emitter := func(event interface{}) {
		emitted = append(emitted, event)
	}

	inspector := NewInspector("session-3", "server-3", emitter)

	data := []byte(`{
		"jsonrpc": "2.0",
		"id": "req-abc",
		"method": "tools/call",
		"params": {
			"name": "read_file",
			"arguments": {"path": "/etc/hosts"}
		}
	}`)

	err := inspector.Inspect(data, DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}

	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	event := emitted[0].(MCPToolCalledEvent)

	// String ID should be marshaled as a JSON string
	var id string
	if err := json.Unmarshal(event.JSONRPCID, &id); err != nil {
		t.Fatalf("failed to unmarshal JSONRPCID as string: %v", err)
	}
	if id != "req-abc" {
		t.Errorf("event.JSONRPCID = %q, want %q", id, "req-abc")
	}
}

func TestMCPToolCalledEvent_JSON(t *testing.T) {
	event := MCPToolCalledEvent{
		Type:      "mcp_tool_called",
		SessionID: "sess-1",
		ServerID:  "srv-1",
		ToolName:  "test_tool",
		JSONRPCID: json.RawMessage(`42`),
		Input:     json.RawMessage(`{"key":"value"}`),
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal event JSON: %v", err)
	}

	if decoded["type"] != "mcp_tool_called" {
		t.Errorf("type = %v, want mcp_tool_called", decoded["type"])
	}
	if decoded["tool_name"] != "test_tool" {
		t.Errorf("tool_name = %v, want test_tool", decoded["tool_name"])
	}
	if decoded["jsonrpc_id"] != float64(42) {
		t.Errorf("jsonrpc_id = %v, want 42", decoded["jsonrpc_id"])
	}
}
