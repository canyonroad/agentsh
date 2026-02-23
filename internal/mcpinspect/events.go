// internal/mcpinspect/events.go
package mcpinspect

import (
	"encoding/json"
	"time"
)

// MCPToolSeenEvent is logged when a tool definition is observed.
type MCPToolSeenEvent struct {
	Type      string    `json:"type"` // "mcp_tool_seen"
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`

	// Server identity
	ServerID   string `json:"server_id"`
	ServerType string `json:"server_type"` // "stdio" | "http"

	// Tool info
	ToolName    string `json:"tool_name"`
	ToolHash    string `json:"tool_hash"`
	Description string `json:"description,omitempty"`

	// Registration status
	Status string `json:"status"` // "new" | "unchanged" | "changed"

	// Detection results (if any)
	Detections []DetectionResult `json:"detections,omitempty"`

	// Severity (highest from detections)
	MaxSeverity string `json:"max_severity,omitempty"`
}

// MCPToolChangedEvent is logged when a tool definition changes (rug pull).
type MCPToolChangedEvent struct {
	Type      string    `json:"type"` // "mcp_tool_changed"
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`

	// Server identity
	ServerID string `json:"server_id"`

	// Tool info
	ToolName     string `json:"tool_name"`
	PreviousHash string `json:"previous_hash"`
	NewHash      string `json:"new_hash"`

	// What changed
	Changes []FieldChange `json:"changes"`

	// New detection results
	Detections []DetectionResult `json:"detections,omitempty"`
}

// MCPToolCalledEvent is logged when a tools/call JSON-RPC request is observed
// on an MCP server's stdin.
type MCPToolCalledEvent struct {
	Type      string    `json:"type"` // "mcp_tool_called"
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`
	ServerID  string    `json:"server_id"`

	// From JSON-RPC request
	ToolName  string          `json:"tool_name"`
	JSONRPCID json.RawMessage `json:"jsonrpc_id"`
	Input     json.RawMessage `json:"input,omitempty"`
}

// MCPDetectionEvent is logged when suspicious patterns are detected.
type MCPDetectionEvent struct {
	Type      string    `json:"type"` // "mcp_detection"
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`

	// Server and tool
	ServerID string `json:"server_id"`
	ToolName string `json:"tool_name"`

	// Detection details
	Detection DetectionResult `json:"detection"`

	// Action taken
	Action string `json:"action"` // "alert" | "warn" | "block"
}

// MCPToolCallInterceptedEvent is logged when the LLM proxy detects a
// tool_use/tool_calls block that matches a registered MCP tool.
type MCPToolCallInterceptedEvent struct {
	Type      string    `json:"type"`       // "mcp_tool_call_intercepted"
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`
	RequestID string    `json:"request_id"` // LLM proxy request ID
	Dialect   string    `json:"dialect"`    // "anthropic" | "openai"

	// From LLM response
	ToolName   string          `json:"tool_name"`
	ToolCallID string          `json:"tool_call_id"` // "toolu_..." or "call_..."
	Input      json.RawMessage `json:"input"`

	// From registry lookup
	ServerID   string `json:"server_id"`
	ServerType string `json:"server_type"` // "stdio" | "http" | "sse"
	ServerAddr string `json:"server_addr,omitempty"`
	ToolHash   string `json:"tool_hash"`

	// Policy decision
	Action string `json:"action"`           // "allow" | "block"
	Reason string `json:"reason,omitempty"`

	// Cross-server detection metadata (populated when blocked by a cross-server rule).
	CrossServerRule     string           `json:"cross_server_rule,omitempty"`
	CrossServerSeverity string           `json:"cross_server_severity,omitempty"`
	CrossServerRelated  []ToolCallRecord `json:"cross_server_related,omitempty"`
}

// MCPCrossServerEvent is logged when a cross-server pattern is detected and
// a tool call is blocked due to suspicious multi-server interaction.
type MCPCrossServerEvent struct {
	Type      string    `json:"type"`       // "mcp_cross_server_blocked"
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`

	// Which detection rule fired
	Rule     string `json:"rule"`     // "read_then_send", "burst", "cross_server_flow", "shadow_tool"
	Severity string `json:"severity"` // "critical", "high", "medium"

	// The tool call that was blocked
	BlockedServerID string `json:"blocked_server_id"`
	BlockedToolName string `json:"blocked_tool_name"`

	// Recent tool calls that contributed to the detection
	RelatedCalls []ToolCallRecord `json:"related_calls"`

	// Human-readable explanation of why the call was blocked
	Reason string `json:"reason"`
}

// ToolCallRecord captures a single tool call for cross-server analysis.
type ToolCallRecord struct {
	Timestamp time.Time `json:"timestamp"`
	ServerID  string    `json:"server_id"`
	ToolName  string    `json:"tool_name"`
	RequestID string    `json:"request_id"`
	Action    string    `json:"action"`   // "allow" or "block"
	Category  string    `json:"category"` // "read", "write", "send", "compute", "unknown"
}

// FieldChange describes what changed in a tool definition.
type FieldChange struct {
	Field    string `json:"field"`
	Previous string `json:"previous"`
	New      string `json:"new"`
}

// DetectionResult holds the result of pattern matching.
type DetectionResult struct {
	Pattern  string   `json:"pattern"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Matches  []Match  `json:"matches"`
	Field    string   `json:"field"` // "description", "inputSchema", etc.
}

// Match represents a single pattern match location.
type Match struct {
	Text     string `json:"text"`
	Position int    `json:"position"`
	Context  string `json:"context"` // Surrounding text
}

// Severity levels for detections.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the string representation of Severity.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MarshalJSON implements json.Marshaler for Severity.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}
