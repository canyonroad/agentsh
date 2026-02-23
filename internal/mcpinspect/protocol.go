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
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
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

// ToolsCallRequest is the JSON-RPC request for tools/call.
type ToolsCallRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"` // "tools/call"
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

// ParseToolsCallRequest parses a tools/call request from raw JSON.
func ParseToolsCallRequest(data []byte) (*ToolsCallRequest, error) {
	var req ToolsCallRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parse tools/call request: %w", err)
	}
	return &req, nil
}

// MessageType identifies the type of MCP message.
type MessageType int

const (
	MessageUnknown MessageType = iota
	MessageToolsList
	MessageToolsListResponse
	MessageToolsCall
	MessageToolsCallResponse
	MessageSamplingRequest
)

// String returns the string representation of MessageType.
func (m MessageType) String() string {
	switch m {
	case MessageToolsList:
		return "tools/list"
	case MessageToolsListResponse:
		return "tools/list_response"
	case MessageToolsCall:
		return "tools/call"
	case MessageToolsCallResponse:
		return "tools/call_response"
	case MessageSamplingRequest:
		return "sampling/createMessage"
	default:
		return "unknown"
	}
}

// DetectMessageType determines the MCP message type from raw JSON.
func DetectMessageType(data []byte) (MessageType, error) {
	var msg struct {
		Method string `json:"method"`
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}

	if err := json.Unmarshal(data, &msg); err != nil {
		return MessageUnknown, fmt.Errorf("parse message: %w", err)
	}

	switch msg.Method {
	case "tools/list":
		return MessageToolsList, nil
	case "tools/call":
		return MessageToolsCall, nil
	case "sampling/createMessage":
		return MessageSamplingRequest, nil
	}

	// Check for tools/list response (has tools array in result)
	if len(msg.Result.Tools) > 0 {
		return MessageToolsListResponse, nil
	}

	return MessageUnknown, nil
}
