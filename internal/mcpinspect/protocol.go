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

// ContentBlock represents a content block in an MCP tool result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ToolsCallResponse is the JSON-RPC response to tools/call.
type ToolsCallResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  struct {
		Content []ContentBlock `json:"content"`
	} `json:"result"`
}

// ParseToolsCallResponse parses a tools/call response from raw JSON.
func ParseToolsCallResponse(data []byte) (*ToolsCallResponse, error) {
	var resp ToolsCallResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse tools/call response: %w", err)
	}
	return &resp, nil
}

// SamplingCreateMessageRequest is the JSON-RPC request for sampling/createMessage.
type SamplingCreateMessageRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"` // "sampling/createMessage"
	Params  struct {
		Messages         []SamplingMessage `json:"messages"`
		ModelPreferences *struct {
			Hints []struct {
				Name string `json:"name"`
			} `json:"hints"`
		} `json:"modelPreferences,omitempty"`
		MaxTokens int `json:"maxTokens"`
	} `json:"params"`
}

// SamplingMessage represents a message in a sampling/createMessage request.
type SamplingMessage struct {
	Role    string `json:"role"`
	Content struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

// ParseSamplingRequest parses a sampling/createMessage request from raw JSON.
func ParseSamplingRequest(data []byte) (*SamplingCreateMessageRequest, error) {
	var req SamplingCreateMessageRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parse sampling/createMessage request: %w", err)
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
	MessageToolsListChanged
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
	case MessageToolsListChanged:
		return "notifications/tools/list_changed"
	default:
		return "unknown"
	}
}

// DetectMessageType determines the MCP message type from raw JSON.
func DetectMessageType(data []byte) (MessageType, error) {
	var msg struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
		Result struct {
			Tools   []json.RawMessage `json:"tools"`
			Content []json.RawMessage `json:"content"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
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
	case "notifications/tools/list_changed":
		return MessageToolsListChanged, nil
	}

	// Responses have an ID but no method.
	if len(msg.ID) > 0 && msg.Method == "" {
		// Check for tools/list response (has tools array in result)
		if len(msg.Result.Tools) > 0 {
			return MessageToolsListResponse, nil
		}

		// Any other response (has content, empty content, or error) is treated
		// as a tools/call response so that pending-calls can be cleaned up.
		if len(msg.Result.Content) > 0 || len(msg.Error) > 0 {
			return MessageToolsCallResponse, nil
		}
	}

	return MessageUnknown, nil
}
