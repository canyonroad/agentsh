// internal/mcpinspect/protocol_test.go
package mcpinspect

import (
	"testing"
)

func TestParseToolsListResponse(t *testing.T) {
	input := `{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"tools": [
				{
					"name": "read_file",
					"description": "Reads a file from the filesystem.",
					"inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
				}
			]
		}
	}`

	resp, err := ParseToolsListResponse([]byte(input))
	if err != nil {
		t.Fatalf("ParseToolsListResponse failed: %v", err)
	}
	if len(resp.Result.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(resp.Result.Tools))
	}
	if resp.Result.Tools[0].Name != "read_file" {
		t.Errorf("expected tool name 'read_file', got %q", resp.Result.Tools[0].Name)
	}
}

func TestDetectMessageType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected MessageType
	}{
		{
			name:     "tools/list request",
			input:    `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			expected: MessageToolsList,
		},
		{
			name:     "tools/list response",
			input:    `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"test"}]}}`,
			expected: MessageToolsListResponse,
		},
		{
			name:     "tools/call request",
			input:    `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}`,
			expected: MessageToolsCall,
		},
		{
			name:     "tools/call response with content",
			input:    `{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"hello"}]}}`,
			expected: MessageToolsCallResponse,
		},
		{
			name:     "tools/call error response",
			input:    `{"jsonrpc":"2.0","id":4,"error":{"code":-1,"message":"tool failed"}}`,
			expected: MessageToolsCallResponse,
		},
		{
			name:     "sampling request",
			input:    `{"jsonrpc":"2.0","id":3,"method":"sampling/createMessage"}`,
			expected: MessageSamplingRequest,
		},
		{
			name:     "unknown message",
			input:    `{"jsonrpc":"2.0","id":4,"method":"resources/list"}`,
			expected: MessageUnknown,
		},
		{
			name:     "notifications/tools/list_changed",
			input:    `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`,
			expected: MessageToolsListChanged,
		},
		{
			name:     "notifications/tools/list_changed with no id field",
			input:    `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`,
			expected: MessageToolsListChanged,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectMessageType([]byte(tt.input))
			if err != nil {
				t.Fatalf("DetectMessageType failed: %v", err)
			}
			if got != tt.expected {
				t.Errorf("DetectMessageType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMessageToolsListChanged_String(t *testing.T) {
	got := MessageToolsListChanged.String()
	want := "notifications/tools/list_changed"
	if got != want {
		t.Errorf("MessageToolsListChanged.String() = %q, want %q", got, want)
	}
}
