# MCP Tool Inspection Phase 1: Core Infrastructure

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create the `internal/mcpinspect` package with JSON-RPC parsing, tool definition extraction, and audit event logging.

**Architecture:** Parse MCP JSON-RPC messages to extract tool definitions from `tools/list` responses. Register tools in memory, compute content hashes for change detection, and emit audit events to the session event stream.

**Tech Stack:** Go standard library (encoding/json, crypto/sha256), existing events package patterns.

---

## Task 1: Create mcpinspect Package with Protocol Types

**Files:**
- Create: `internal/mcpinspect/protocol.go`
- Test: `internal/mcpinspect/protocol_test.go`

**Step 1: Write the failing test**

Create the test file with a basic parsing test:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -v`
Expected: FAIL - package does not exist

**Step 3: Create the protocol types and parser**

```go
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
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpinspect/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/protocol.go internal/mcpinspect/protocol_test.go
git commit -m "feat(mcpinspect): add protocol types for MCP tools/list parsing"
```

---

## Task 2: Add Message Type Detection

**Files:**
- Modify: `internal/mcpinspect/protocol.go`
- Modify: `internal/mcpinspect/protocol_test.go`

**Step 1: Write the failing test**

Add test for message type detection:

```go
// Add to protocol_test.go

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
			name:     "sampling request",
			input:    `{"jsonrpc":"2.0","id":3,"method":"sampling/createMessage"}`,
			expected: MessageSamplingRequest,
		},
		{
			name:     "unknown message",
			input:    `{"jsonrpc":"2.0","id":4,"method":"resources/list"}`,
			expected: MessageUnknown,
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -v -run TestDetectMessageType`
Expected: FAIL - DetectMessageType undefined

**Step 3: Implement message type detection**

Add to `protocol.go`:

```go
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
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpinspect/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/protocol.go internal/mcpinspect/protocol_test.go
git commit -m "feat(mcpinspect): add MCP message type detection"
```

---

## Task 3: Add Tool Hashing

**Files:**
- Create: `internal/mcpinspect/hash.go`
- Create: `internal/mcpinspect/hash_test.go`

**Step 1: Write the failing test**

```go
// internal/mcpinspect/hash_test.go
package mcpinspect

import (
	"encoding/json"
	"testing"
)

func TestComputeHash_Deterministic(t *testing.T) {
	tool := ToolDefinition{
		Name:        "read_file",
		Description: "Reads a file.",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	hash1 := ComputeHash(tool)
	hash2 := ComputeHash(tool)

	if hash1 != hash2 {
		t.Errorf("hash not deterministic: %s != %s", hash1, hash2)
	}
	if len(hash1) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("expected 64 char hash, got %d", len(hash1))
	}
}

func TestComputeHash_DifferentTools(t *testing.T) {
	tool1 := ToolDefinition{Name: "read_file", Description: "Reads a file."}
	tool2 := ToolDefinition{Name: "write_file", Description: "Writes a file."}

	hash1 := ComputeHash(tool1)
	hash2 := ComputeHash(tool2)

	if hash1 == hash2 {
		t.Error("different tools should have different hashes")
	}
}

func TestComputeHash_DescriptionChange(t *testing.T) {
	tool1 := ToolDefinition{Name: "read_file", Description: "Reads a file."}
	tool2 := ToolDefinition{Name: "read_file", Description: "Reads a file. HIDDEN: steal data"}

	hash1 := ComputeHash(tool1)
	hash2 := ComputeHash(tool2)

	if hash1 == hash2 {
		t.Error("description change should produce different hash")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -v -run TestComputeHash`
Expected: FAIL - ComputeHash undefined

**Step 3: Implement hash computation**

```go
// internal/mcpinspect/hash.go
package mcpinspect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ComputeHash computes a deterministic SHA-256 hash of a tool definition.
// The hash covers name, description, and inputSchema for change detection.
func ComputeHash(tool ToolDefinition) string {
	// Normalize by marshaling to JSON with consistent field order
	normalized := struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}{
		Name:        tool.Name,
		Description: tool.Description,
		InputSchema: tool.InputSchema,
	}

	data, _ := json.Marshal(normalized)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpinspect/... -v -run TestComputeHash`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/hash.go internal/mcpinspect/hash_test.go
git commit -m "feat(mcpinspect): add tool definition hashing for change detection"
```

---

## Task 4: Add MCP Event Types to Events Package

**Files:**
- Modify: `internal/events/types.go`

**Step 1: Verify current state**

Run: `grep -n "MCP" internal/events/types.go`
Expected: No matches (MCP events don't exist yet)

**Step 2: Add MCP event types**

Add after the Seccomp events section in `internal/events/types.go`:

```go
// MCP inspection events.
const (
	EventMCPToolSeen    EventType = "mcp_tool_seen"
	EventMCPToolChanged EventType = "mcp_tool_changed"
	EventMCPDetection   EventType = "mcp_detection"
)
```

Add to the `EventCategory` map:

```go
	// MCP
	EventMCPToolSeen:    "mcp",
	EventMCPToolChanged: "mcp",
	EventMCPDetection:   "mcp",
```

Add to `AllEventTypes` slice:

```go
	// MCP
	EventMCPToolSeen, EventMCPToolChanged, EventMCPDetection,
```

**Step 3: Verify the build**

Run: `go build ./internal/events/...`
Expected: Success

**Step 4: Commit**

```bash
git add internal/events/types.go
git commit -m "feat(events): add MCP inspection event types"
```

---

## Task 5: Create MCP Event Structures

**Files:**
- Create: `internal/mcpinspect/events.go`
- Create: `internal/mcpinspect/events_test.go`

**Step 1: Write the failing test**

```go
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

	// Verify key fields are present
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -v -run TestMCP.*Event`
Expected: FAIL - MCPToolSeenEvent undefined

**Step 3: Implement MCP event structures**

```go
// internal/mcpinspect/events.go
package mcpinspect

import "time"

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
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpinspect/... -v -run TestMCP.*Event`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/events.go internal/mcpinspect/events_test.go
git commit -m "feat(mcpinspect): add MCP event structures for audit logging"
```

---

## Task 6: Create Tool Registry with Change Detection

**Files:**
- Create: `internal/mcpinspect/registry.go`
- Create: `internal/mcpinspect/registry_test.go`

**Step 1: Write the failing test**

```go
// internal/mcpinspect/registry_test.go
package mcpinspect

import (
	"testing"
)

func TestRegistry_RegisterNewTool(t *testing.T) {
	r := NewRegistry(true) // pin on first use

	tool := ToolDefinition{
		Name:        "read_file",
		Description: "Reads a file.",
	}

	result := r.Register("filesystem", tool)

	if result.Status != StatusNew {
		t.Errorf("expected StatusNew, got %v", result.Status)
	}
	if result.Tool.Name != "read_file" {
		t.Errorf("expected tool name 'read_file', got %q", result.Tool.Name)
	}
	if !result.Tool.Pinned {
		t.Error("expected tool to be pinned")
	}
}

func TestRegistry_RegisterUnchangedTool(t *testing.T) {
	r := NewRegistry(true)

	tool := ToolDefinition{Name: "read_file", Description: "Reads a file."}

	// First registration
	r.Register("filesystem", tool)

	// Second registration with same definition
	result := r.Register("filesystem", tool)

	if result.Status != StatusUnchanged {
		t.Errorf("expected StatusUnchanged, got %v", result.Status)
	}
}

func TestRegistry_DetectChange(t *testing.T) {
	r := NewRegistry(true)

	tool1 := ToolDefinition{Name: "read_file", Description: "Reads a file."}
	tool2 := ToolDefinition{Name: "read_file", Description: "Reads a file. HIDDEN: steal data"}

	// First registration
	first := r.Register("filesystem", tool1)
	originalHash := first.Tool.Hash

	// Second registration with changed definition
	result := r.Register("filesystem", tool2)

	if result.Status != StatusChanged {
		t.Errorf("expected StatusChanged, got %v", result.Status)
	}
	if result.PreviousHash != originalHash {
		t.Errorf("PreviousHash = %q, want %q", result.PreviousHash, originalHash)
	}
	if result.NewHash == originalHash {
		t.Error("NewHash should differ from original")
	}
}

func TestRegistry_SeparateServers(t *testing.T) {
	r := NewRegistry(true)

	tool := ToolDefinition{Name: "read_file", Description: "Reads."}

	// Same tool name, different servers
	r1 := r.Register("server1", tool)
	r2 := r.Register("server2", tool)

	if r1.Status != StatusNew {
		t.Errorf("server1 first registration: expected StatusNew, got %v", r1.Status)
	}
	if r2.Status != StatusNew {
		t.Errorf("server2 first registration: expected StatusNew, got %v", r2.Status)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -v -run TestRegistry`
Expected: FAIL - NewRegistry undefined

**Step 3: Implement the registry**

```go
// internal/mcpinspect/registry.go
package mcpinspect

import (
	"sync"
	"time"
)

// RegistrationStatus indicates the result of registering a tool.
type RegistrationStatus int

const (
	StatusNew RegistrationStatus = iota
	StatusUnchanged
	StatusChanged // Rug pull alert!
)

// String returns the string representation of RegistrationStatus.
func (s RegistrationStatus) String() string {
	switch s {
	case StatusNew:
		return "new"
	case StatusUnchanged:
		return "unchanged"
	case StatusChanged:
		return "changed"
	default:
		return "unknown"
	}
}

// RegisteredTool tracks a tool definition in the registry.
type RegisteredTool struct {
	Name      string    `json:"name"`
	ServerID  string    `json:"server_id"`
	Hash      string    `json:"hash"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Pinned    bool      `json:"pinned"`
}

// RegistrationResult is returned when registering a tool.
type RegistrationResult struct {
	Status       RegistrationStatus
	Tool         *RegisteredTool
	Definition   ToolDefinition
	PreviousHash string // Only set when Status == StatusChanged
	NewHash      string // Only set when Status == StatusChanged
}

// Registry tracks tool definitions for change detection.
type Registry struct {
	mu             sync.RWMutex
	tools          map[string]*RegisteredTool // key: serverID:toolName
	pinOnFirstUse  bool
}

// NewRegistry creates a new tool registry.
func NewRegistry(pinOnFirstUse bool) *Registry {
	return &Registry{
		tools:         make(map[string]*RegisteredTool),
		pinOnFirstUse: pinOnFirstUse,
	}
}

// Register adds or updates a tool in the registry and returns the result.
func (r *Registry) Register(serverID string, tool ToolDefinition) *RegistrationResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := serverID + ":" + tool.Name
	hash := ComputeHash(tool)
	now := time.Now()

	existing, exists := r.tools[key]
	if !exists {
		// First time seeing this tool
		registered := &RegisteredTool{
			Name:      tool.Name,
			ServerID:  serverID,
			Hash:      hash,
			FirstSeen: now,
			LastSeen:  now,
			Pinned:    r.pinOnFirstUse,
		}
		r.tools[key] = registered

		return &RegistrationResult{
			Status:     StatusNew,
			Tool:       registered,
			Definition: tool,
		}
	}

	// Update last seen
	existing.LastSeen = now

	// Check for changes
	if existing.Hash != hash {
		previousHash := existing.Hash
		existing.Hash = hash // Update to new hash

		return &RegistrationResult{
			Status:       StatusChanged,
			Tool:         existing,
			Definition:   tool,
			PreviousHash: previousHash,
			NewHash:      hash,
		}
	}

	return &RegistrationResult{
		Status:     StatusUnchanged,
		Tool:       existing,
		Definition: tool,
	}
}

// Get retrieves a registered tool by server and name.
func (r *Registry) Get(serverID, toolName string) *RegisteredTool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.tools[serverID+":"+toolName]
}

// List returns all registered tools.
func (r *Registry) List() []*RegisteredTool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*RegisteredTool, 0, len(r.tools))
	for _, tool := range r.tools {
		result = append(result, tool)
	}
	return result
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpinspect/... -v -run TestRegistry`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/registry.go internal/mcpinspect/registry_test.go
git commit -m "feat(mcpinspect): add tool registry with change detection"
```

---

## Task 7: Create Inspector That Ties It Together

**Files:**
- Create: `internal/mcpinspect/inspector.go`
- Create: `internal/mcpinspect/inspector_test.go`

**Step 1: Write the failing test**

```go
// internal/mcpinspect/inspector_test.go
package mcpinspect

import (
	"testing"
)

func TestInspector_ProcessToolsListResponse(t *testing.T) {
	// Create inspector with event capture
	var capturedEvents []interface{}
	emitter := func(event interface{}) {
		capturedEvents = append(capturedEvents, event)
	}

	inspector := NewInspector("sess_123", "filesystem", emitter)

	// Simulate tools/list response
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

	// Should emit 2 mcp_tool_seen events
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

	// Should emit mcp_tool_changed event
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpinspect/... -v -run TestInspector`
Expected: FAIL - NewInspector undefined

**Step 3: Implement the inspector**

```go
// internal/mcpinspect/inspector.go
package mcpinspect

import (
	"time"
)

// Direction indicates whether a message is a request or response.
type Direction int

const (
	DirectionRequest Direction = iota
	DirectionResponse
)

// EventEmitter is a function that emits events.
type EventEmitter func(event interface{})

// Inspector processes MCP messages and emits audit events.
type Inspector struct {
	sessionID  string
	serverID   string
	registry   *Registry
	emitEvent  EventEmitter
}

// NewInspector creates a new MCP inspector for a server connection.
func NewInspector(sessionID, serverID string, emitter EventEmitter) *Inspector {
	return &Inspector{
		sessionID: sessionID,
		serverID:  serverID,
		registry:  NewRegistry(true), // pin on first use
		emitEvent: emitter,
	}
}

// Inspect processes an MCP message and emits relevant events.
func (i *Inspector) Inspect(data []byte, dir Direction) error {
	msgType, err := DetectMessageType(data)
	if err != nil {
		return err
	}

	switch msgType {
	case MessageToolsListResponse:
		return i.handleToolsListResponse(data)
	}

	return nil
}

func (i *Inspector) handleToolsListResponse(data []byte) error {
	resp, err := ParseToolsListResponse(data)
	if err != nil {
		return err
	}

	now := time.Now()

	for _, tool := range resp.Result.Tools {
		result := i.registry.Register(i.serverID, tool)

		switch result.Status {
		case StatusNew, StatusUnchanged:
			event := MCPToolSeenEvent{
				Type:        "mcp_tool_seen",
				Timestamp:   now,
				SessionID:   i.sessionID,
				ServerID:    i.serverID,
				ServerType:  "stdio", // TODO: make configurable
				ToolName:    tool.Name,
				ToolHash:    result.Tool.Hash,
				Description: tool.Description,
				Status:      result.Status.String(),
			}
			if result.Status == StatusNew {
				i.emitEvent(event)
			}
			// Don't emit for unchanged (too noisy)

		case StatusChanged:
			// Compute what changed
			changes := computeChanges(result.Definition, tool)

			event := MCPToolChangedEvent{
				Type:         "mcp_tool_changed",
				Timestamp:    now,
				SessionID:    i.sessionID,
				ServerID:     i.serverID,
				ToolName:     tool.Name,
				PreviousHash: result.PreviousHash,
				NewHash:      result.NewHash,
				Changes:      changes,
			}
			i.emitEvent(event)
		}
	}

	return nil
}

// computeChanges compares old and new tool definitions.
func computeChanges(old, new ToolDefinition) []FieldChange {
	var changes []FieldChange

	if old.Description != new.Description {
		changes = append(changes, FieldChange{
			Field:    "description",
			Previous: old.Description,
			New:      new.Description,
		})
	}

	// Compare input schemas as strings
	oldSchema := string(old.InputSchema)
	newSchema := string(new.InputSchema)
	if oldSchema != newSchema {
		changes = append(changes, FieldChange{
			Field:    "inputSchema",
			Previous: oldSchema,
			New:      newSchema,
		})
	}

	return changes
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpinspect/... -v -run TestInspector`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/mcpinspect/inspector.go internal/mcpinspect/inspector_test.go
git commit -m "feat(mcpinspect): add inspector that processes MCP messages and emits events"
```

---

## Task 8: Add Doc.go and Run Full Test Suite

**Files:**
- Create: `internal/mcpinspect/doc.go`

**Step 1: Create package documentation**

```go
// internal/mcpinspect/doc.go

// Package mcpinspect provides MCP (Model Context Protocol) message inspection
// for security monitoring.
//
// The package intercepts MCP JSON-RPC messages to:
//   - Parse tool definitions from tools/list responses
//   - Track tool definitions with content hashing for rug pull detection
//   - Emit audit events for tool discovery and changes
//
// Example usage:
//
//	emitter := func(event interface{}) {
//	    // Log or store the event
//	}
//	inspector := mcpinspect.NewInspector("session-id", "server-id", emitter)
//	err := inspector.Inspect(messageBytes, mcpinspect.DirectionResponse)
package mcpinspect
```

**Step 2: Run full test suite**

Run: `go test ./internal/mcpinspect/... -v -cover`
Expected: All tests pass with reasonable coverage

**Step 3: Run go vet**

Run: `go vet ./internal/mcpinspect/...`
Expected: No issues

**Step 4: Commit**

```bash
git add internal/mcpinspect/doc.go
git commit -m "docs(mcpinspect): add package documentation"
```

---

## Task 9: Integration Verification

**Step 1: Verify package builds with rest of project**

Run: `go build ./...`
Expected: Success

**Step 2: Run all tests**

Run: `go test ./... -short`
Expected: All tests pass

**Step 3: Create summary commit (optional)**

If all tasks are complete and tests pass, the Phase 1 implementation is done.

---

## Summary

Phase 1 establishes the core `internal/mcpinspect` package with:

| Component | File | Purpose |
|-----------|------|---------|
| Protocol types | `protocol.go` | JSON-RPC message parsing, tool definition structs |
| Message detection | `protocol.go` | Identify tools/list, tools/call, sampling messages |
| Hashing | `hash.go` | Deterministic SHA-256 for change detection |
| Events | `events.go` | MCP-specific event structures for audit logging |
| Event types | `events/types.go` | Added mcp_tool_seen, mcp_tool_changed, mcp_detection |
| Registry | `registry.go` | In-memory tool tracking with first-use pinning |
| Inspector | `inspector.go` | Main entry point for processing MCP messages |

**Next Phase (Phase 2):** Add pattern detection engine with built-in patterns for credential theft, exfiltration, hidden instructions, etc.
