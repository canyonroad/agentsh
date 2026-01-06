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
