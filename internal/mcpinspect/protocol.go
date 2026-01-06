// internal/mcpinspect/protocol.go
package mcpinspect

import (
	"encoding/json"
	"fmt"
)

// ToolDefinition represents an MCP tool from tools/list response.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ToolsListResponse is the JSON-RPC response to tools/list.
type ToolsListResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  struct {
		Tools []ToolDefinition `json:"tools"`
	} `json:"result"`
}

// ParseToolsListResponse parses a tools/list response from raw JSON.
func ParseToolsListResponse(data []byte) (*ToolsListResponse, error) {
	var resp ToolsListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse tools/list response: %w", err)
	}
	return &resp, nil
}
