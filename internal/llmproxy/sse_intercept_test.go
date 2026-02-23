package llmproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

// --- Test helpers ---

// newTestPolicy creates a denylist policy that blocks the given tools.
func newTestPolicy(deniedTools ...config.MCPToolRule) *mcpinspect.PolicyEvaluator {
	return mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
		DeniedTools:   deniedTools,
	})
}

// newTestAllowPolicy creates an allowlist policy that allows only the given tools.
func newTestAllowPolicy(allowedTools ...config.MCPToolRule) *mcpinspect.PolicyEvaluator {
	return mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "allowlist",
		AllowedTools:  allowedTools,
	})
}

// buildAnthropicSSE constructs a realistic Anthropic SSE stream with a text block
// at index 0 and a tool_use block at index 1.
func buildAnthropicSSE(toolName, toolID string) string {
	var b strings.Builder

	// message_start
	b.WriteString("event: message_start\n")
	b.WriteString(`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}`)
	b.WriteString("\n\n")

	// text block: content_block_start (index 0)
	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
	b.WriteString("\n\n")

	// text block: content_block_delta (index 0)
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me check the weather."}}`)
	b.WriteString("\n\n")

	// text block: content_block_stop (index 0)
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":0}`)
	b.WriteString("\n\n")

	// tool_use block: content_block_start (index 1)
	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"` + toolID + `","name":"` + toolName + `"}}`)
	b.WriteString("\n\n")

	// tool_use block: content_block_delta (index 1)
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"San Francisco\"}"}}`)
	b.WriteString("\n\n")

	// tool_use block: content_block_stop (index 1)
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":1}`)
	b.WriteString("\n\n")

	// message_delta with stop_reason
	b.WriteString("event: message_delta\n")
	b.WriteString(`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":25}}`)
	b.WriteString("\n\n")

	// message_stop
	b.WriteString("event: message_stop\n")
	b.WriteString(`data: {"type":"message_stop"}`)
	b.WriteString("\n\n")

	return b.String()
}

func TestSSEInterceptor_Anthropic_SingleBlocked(t *testing.T) {
	// --- Setup ---

	// Build an Anthropic SSE stream: text block at index 0, tool_use "get_weather" at index 1.
	sseInput := buildAnthropicSSE("get_weather", "toolu_01A09q90qw90lq917835lq9")

	// Registry: get_weather from "weather-server"
	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	// Policy: denylist blocking get_weather
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "get_weather"})

	// Collect event callbacks
	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Execute ---
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_1", "req_1", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	buffered := interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// --- Assertions ---

	// 1. The blocked tool_use content_block_start (index 1, type tool_use) must NOT appear.
	if strings.Contains(clientOutput, `"type":"tool_use"`) {
		t.Error("blocked tool_use content_block_start should be suppressed from client output")
	}

	// 2. The original text block (index 0) must pass through.
	if !strings.Contains(clientOutput, "Let me check the weather.") {
		t.Error("original text block delta should pass through to client")
	}

	// 3. Replacement text block with the blocked message must be present.
	expectedMsg := "[agentsh] Tool 'get_weather' blocked by policy"
	if !strings.Contains(clientOutput, expectedMsg) {
		t.Errorf("expected replacement text %q in client output, got:\n%s", expectedMsg, clientOutput)
	}

	// 4. stop_reason must be rewritten to "end_turn" (all tool_use blocked).
	if !strings.Contains(clientOutput, `"end_turn"`) {
		t.Error("stop_reason should be rewritten to end_turn when all tool_use are blocked")
	}
	// The original stop_reason "tool_use" in message_delta should NOT appear.
	// (It gets rewritten, so we check the data line doesn't have stop_reason: tool_use)
	lines := strings.Split(clientOutput, "\n")
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		var evt struct {
			Type  string `json:"type"`
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}
		if evt.Type == "message_delta" && evt.Delta.StopReason == "tool_use" {
			t.Error("message_delta stop_reason should not be 'tool_use' when all tools are blocked")
		}
	}

	// 5. message_stop must be present.
	if !strings.Contains(clientOutput, `"message_stop"`) {
		t.Error("message_stop event should be present in output")
	}

	// 6. Event callback should have fired with action=block.
	if len(events) != 1 {
		t.Fatalf("expected 1 event callback, got %d", len(events))
	}
	evt := events[0]
	if evt.Action != "block" {
		t.Errorf("expected event action %q, got %q", "block", evt.Action)
	}
	if evt.ToolName != "get_weather" {
		t.Errorf("expected event tool name %q, got %q", "get_weather", evt.ToolName)
	}
	if evt.ToolCallID != "toolu_01A09q90qw90lq917835lq9" {
		t.Errorf("expected event tool call ID %q, got %q", "toolu_01A09q90qw90lq917835lq9", evt.ToolCallID)
	}
	if evt.ServerID != "weather-server" {
		t.Errorf("expected event server ID %q, got %q", "weather-server", evt.ServerID)
	}
	if evt.SessionID != "sess_1" {
		t.Errorf("expected event session ID %q, got %q", "sess_1", evt.SessionID)
	}
	if evt.RequestID != "req_1" {
		t.Errorf("expected event request ID %q, got %q", "req_1", evt.RequestID)
	}
	if evt.Dialect != "anthropic" {
		t.Errorf("expected event dialect %q, got %q", "anthropic", evt.Dialect)
	}
	if evt.Reason == "" {
		t.Error("expected non-empty event reason for blocked tool")
	}

	// 7. Buffered output must match client output.
	if string(buffered) != clientOutput {
		t.Errorf("buffered output does not match client output.\nbuffered len=%d, client len=%d", len(buffered), len(clientOutput))
	}

	// 8. Verify the replacement text block is a proper SSE sequence
	// (content_block_start + content_block_delta + content_block_stop).
	replacementStartFound := false
	replacementDeltaFound := false
	replacementStopFound := false
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		if strings.Contains(data, expectedMsg) {
			replacementDeltaFound = true
		}
		var block struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(data), &block); err != nil {
			continue
		}
		// The replacement block should reuse the same index as the blocked tool.
		if block.Type == "content_block_start" && block.ContentBlock.Type == "text" && block.Index == 1 {
			replacementStartFound = true
		}
		if block.Type == "content_block_stop" && block.Index == 1 {
			replacementStopFound = true
		}
	}
	if !replacementStartFound {
		t.Error("expected replacement content_block_start for text block at index 1")
	}
	if !replacementDeltaFound {
		t.Error("expected replacement content_block_delta with blocked message")
	}
	if !replacementStopFound {
		t.Error("expected replacement content_block_stop at index 1")
	}

	// 9. The tool_use delta at index 1 (input_json_delta) must be suppressed.
	if strings.Contains(clientOutput, "input_json_delta") {
		t.Error("input_json_delta for blocked tool should be suppressed")
	}

	// 10. No orphan "event:" lines — every event: line must be followed by a data: line
	// (either immediately next or separated only by empty lines).
	// This verifies that the event: line for suppressed events is also suppressed.
	eventLines := 0
	dataLines := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "event:") {
			eventLines++
		}
		if strings.HasPrefix(line, "data:") {
			dataLines++
		}
	}
	if eventLines != dataLines {
		t.Errorf("SSE output has %d event: lines but %d data: lines; they should match", eventLines, dataLines)
	}
}

func TestSSEInterceptor_Anthropic_SingleAllowed(t *testing.T) {
	// --- Setup ---

	// Build an Anthropic SSE stream: text block at index 0, tool_use "get_weather" at index 1.
	sseInput := buildAnthropicSSE("get_weather", "toolu_01A09q90qw90lq917835lq9")

	// Registry: get_weather from "weather-server"
	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	// Policy: allowlist with get_weather allowed
	policy := newTestAllowPolicy(config.MCPToolRule{Server: "weather-server", Tool: "get_weather"})

	// Collect event callbacks
	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Execute ---
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_1", "req_1", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	buffered := interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// --- Assertions ---

	// 1. The tool_use content_block_start must pass through unmodified.
	if !strings.Contains(clientOutput, `"type":"tool_use"`) {
		t.Error("allowed tool_use content_block_start should pass through to client output")
	}
	if !strings.Contains(clientOutput, `"name":"get_weather"`) {
		t.Error("allowed tool name should appear in client output")
	}

	// 2. The original text block (index 0) must pass through.
	if !strings.Contains(clientOutput, "Let me check the weather.") {
		t.Error("original text block delta should pass through to client")
	}

	// 3. No [agentsh] replacement message should appear.
	if strings.Contains(clientOutput, "[agentsh]") {
		t.Error("no [agentsh] replacement message should appear for allowed tools")
	}

	// 4. stop_reason must remain "tool_use" (not rewritten).
	foundToolUseStopReason := false
	lines := strings.Split(clientOutput, "\n")
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		var evt struct {
			Type  string `json:"type"`
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}
		if evt.Type == "message_delta" && evt.Delta.StopReason == "tool_use" {
			foundToolUseStopReason = true
		}
	}
	if !foundToolUseStopReason {
		t.Error("stop_reason should remain 'tool_use' when tool is allowed")
	}
	if strings.Contains(clientOutput, `"end_turn"`) {
		t.Error("stop_reason should NOT be rewritten to end_turn when tool is allowed")
	}

	// 5. The input_json_delta for the tool must pass through.
	if !strings.Contains(clientOutput, "input_json_delta") {
		t.Error("input_json_delta for allowed tool should pass through")
	}

	// 6. Event callback should have fired with action=allow.
	if len(events) != 1 {
		t.Fatalf("expected 1 event callback, got %d", len(events))
	}
	evt := events[0]
	if evt.Action != "allow" {
		t.Errorf("expected event action %q, got %q", "allow", evt.Action)
	}
	if evt.ToolName != "get_weather" {
		t.Errorf("expected event tool name %q, got %q", "get_weather", evt.ToolName)
	}
	if evt.ToolCallID != "toolu_01A09q90qw90lq917835lq9" {
		t.Errorf("expected event tool call ID %q, got %q", "toolu_01A09q90qw90lq917835lq9", evt.ToolCallID)
	}
	if evt.ServerID != "weather-server" {
		t.Errorf("expected event server ID %q, got %q", "weather-server", evt.ServerID)
	}
	if evt.Dialect != "anthropic" {
		t.Errorf("expected event dialect %q, got %q", "anthropic", evt.Dialect)
	}

	// 7. Buffered output must match client output.
	if string(buffered) != clientOutput {
		t.Errorf("buffered output does not match client output.\nbuffered len=%d, client len=%d", len(buffered), len(clientOutput))
	}

	// 8. message_stop must be present.
	if !strings.Contains(clientOutput, `"message_stop"`) {
		t.Error("message_stop event should be present in output")
	}
}

func TestSSEInterceptor_Anthropic_Unregistered(t *testing.T) {
	// --- Setup ---

	// Build an Anthropic SSE stream with tool "str_replace_editor" (not an MCP tool).
	sseInput := buildAnthropicSSE("str_replace_editor", "toolu_01XYZ999")

	// Registry: empty (no MCP tools registered)
	reg := mcpregistry.NewRegistry()

	// Policy: denylist blocking everything
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "*"})

	// Collect event callbacks
	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Execute ---
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_1", "req_1", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	buffered := interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// --- Assertions ---

	// 1. The tool_use content_block_start must pass through (not an MCP tool, so not intercepted).
	if !strings.Contains(clientOutput, `"type":"tool_use"`) {
		t.Error("unregistered tool_use should pass through silently")
	}
	if !strings.Contains(clientOutput, `"name":"str_replace_editor"`) {
		t.Error("unregistered tool name should appear in client output")
	}

	// 2. No [agentsh] replacement message should appear.
	if strings.Contains(clientOutput, "[agentsh]") {
		t.Error("no [agentsh] message should appear for unregistered (non-MCP) tools")
	}

	// 3. No events should have fired (tool not in registry, so no policy evaluation).
	if len(events) != 0 {
		t.Errorf("expected 0 event callbacks for unregistered tool, got %d", len(events))
	}

	// 4. stop_reason should remain "tool_use" (not rewritten).
	foundToolUseStopReason := false
	lines := strings.Split(clientOutput, "\n")
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		var evt struct {
			Type  string `json:"type"`
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}
		if evt.Type == "message_delta" && evt.Delta.StopReason == "tool_use" {
			foundToolUseStopReason = true
		}
	}
	if !foundToolUseStopReason {
		t.Error("stop_reason should remain 'tool_use' for unregistered tool")
	}

	// 5. The input_json_delta must pass through.
	if !strings.Contains(clientOutput, "input_json_delta") {
		t.Error("input_json_delta for unregistered tool should pass through")
	}

	// 6. Buffered output must match client output.
	if string(buffered) != clientOutput {
		t.Errorf("buffered output does not match client output.\nbuffered len=%d, client len=%d", len(buffered), len(clientOutput))
	}

	// 7. message_stop must be present.
	if !strings.Contains(clientOutput, `"message_stop"`) {
		t.Error("message_stop event should be present in output")
	}
}

// buildAnthropicSSETwoTools constructs an Anthropic SSE stream with a text block
// at index 0 and two tool_use blocks at index 1 and index 2.
func buildAnthropicSSETwoTools(tool1Name, tool1ID, tool2Name, tool2ID string) string {
	var b strings.Builder

	// message_start
	b.WriteString("event: message_start\n")
	b.WriteString(`data: {"type":"message_start","message":{"id":"msg_02","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}`)
	b.WriteString("\n\n")

	// text block: content_block_start (index 0)
	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
	b.WriteString("\n\n")

	// text block: content_block_delta (index 0)
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I'll do both."}}`)
	b.WriteString("\n\n")

	// text block: content_block_stop (index 0)
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":0}`)
	b.WriteString("\n\n")

	// tool_use block 1: content_block_start (index 1)
	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"` + tool1ID + `","name":"` + tool1Name + `"}}`)
	b.WriteString("\n\n")

	// tool_use block 1: content_block_delta (index 1)
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"NYC\"}"}}`)
	b.WriteString("\n\n")

	// tool_use block 1: content_block_stop (index 1)
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":1}`)
	b.WriteString("\n\n")

	// tool_use block 2: content_block_start (index 2)
	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"` + tool2ID + `","name":"` + tool2Name + `"}}`)
	b.WriteString("\n\n")

	// tool_use block 2: content_block_delta (index 2)
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"confirm\": true}"}}`)
	b.WriteString("\n\n")

	// tool_use block 2: content_block_stop (index 2)
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":2}`)
	b.WriteString("\n\n")

	// message_delta with stop_reason
	b.WriteString("event: message_delta\n")
	b.WriteString(`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":40}}`)
	b.WriteString("\n\n")

	// message_stop
	b.WriteString("event: message_stop\n")
	b.WriteString(`data: {"type":"message_stop"}`)
	b.WriteString("\n\n")

	return b.String()
}

func TestSSEInterceptor_Anthropic_PartialBlock(t *testing.T) {
	// --- Setup ---

	// Build an Anthropic SSE stream: text at index 0, get_weather at index 1, delete_all at index 2.
	sseInput := buildAnthropicSSETwoTools(
		"get_weather", "toolu_01AAA",
		"delete_all", "toolu_01BBB",
	)

	// Registry: get_weather from "weather-server", delete_all from "danger-server"
	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})
	reg.Register("danger-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "delete_all", Hash: "def456"},
	})

	// Policy: denylist blocking delete_all only
	policy := newTestPolicy(config.MCPToolRule{Server: "danger-server", Tool: "delete_all"})

	// Collect event callbacks
	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Execute ---
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_1", "req_1", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	buffered := interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// --- Assertions ---

	// 1. get_weather (index 1) must pass through.
	if !strings.Contains(clientOutput, `"name":"get_weather"`) {
		t.Error("allowed tool get_weather should pass through to client output")
	}

	// 2. delete_all tool_use block must be suppressed — the original tool_use start for delete_all must not appear.
	if strings.Contains(clientOutput, `"name":"delete_all"`) {
		t.Error("blocked tool delete_all should be suppressed from client output")
	}

	// 3. Replacement text block with blocked message for delete_all must be present.
	expectedMsg := "[agentsh] Tool 'delete_all' blocked by policy"
	if !strings.Contains(clientOutput, expectedMsg) {
		t.Errorf("expected replacement text %q in client output, got:\n%s", expectedMsg, clientOutput)
	}

	// 4. No replacement message for get_weather.
	if strings.Contains(clientOutput, "[agentsh] Tool 'get_weather'") {
		t.Error("get_weather should not have a blocked message")
	}

	// 5. stop_reason must remain "tool_use" (one tool is still allowed).
	foundToolUseStopReason := false
	lines := strings.Split(clientOutput, "\n")
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		var evt struct {
			Type  string `json:"type"`
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}
		if evt.Type == "message_delta" && evt.Delta.StopReason == "tool_use" {
			foundToolUseStopReason = true
		}
	}
	if !foundToolUseStopReason {
		t.Error("stop_reason should remain 'tool_use' when at least one tool is allowed")
	}
	if strings.Contains(clientOutput, `"end_turn"`) {
		t.Error("stop_reason should NOT be rewritten to end_turn when some tools pass")
	}

	// 6. Exactly 2 events: allow for get_weather, block for delete_all.
	if len(events) != 2 {
		t.Fatalf("expected 2 event callbacks, got %d", len(events))
	}
	// Events fire in order of content_block_start: index 1 (get_weather) then index 2 (delete_all).
	if events[0].Action != "allow" || events[0].ToolName != "get_weather" {
		t.Errorf("expected first event: allow/get_weather, got %s/%s", events[0].Action, events[0].ToolName)
	}
	if events[1].Action != "block" || events[1].ToolName != "delete_all" {
		t.Errorf("expected second event: block/delete_all, got %s/%s", events[1].Action, events[1].ToolName)
	}
	if events[1].Reason == "" {
		t.Error("expected non-empty reason for blocked tool event")
	}

	// 7. No argument deltas for the blocked tool at index 2.
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		var delta struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
			Delta struct {
				Type string `json:"type"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &delta); err != nil {
			continue
		}
		if delta.Type == "content_block_delta" && delta.Index == 2 && delta.Delta.Type == "input_json_delta" {
			t.Error("input_json_delta for blocked tool at index 2 should be suppressed")
		}
	}

	// 8. The original text block (index 0) must pass through.
	if !strings.Contains(clientOutput, "I'll do both.") {
		t.Error("original text block delta should pass through to client")
	}

	// 9. Buffered output must match client output.
	if string(buffered) != clientOutput {
		t.Errorf("buffered output does not match client output.\nbuffered len=%d, client len=%d", len(buffered), len(clientOutput))
	}

	// 10. No orphan event: lines.
	eventLines := 0
	dataLines := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "event:") {
			eventLines++
		}
		if strings.HasPrefix(line, "data:") {
			dataLines++
		}
	}
	if eventLines != dataLines {
		t.Errorf("SSE output has %d event: lines but %d data: lines; they should match", eventLines, dataLines)
	}
}

// buildAnthropicSSETwoToolsOnly constructs an Anthropic SSE stream with
// two tool_use blocks only (no text block). Tool 1 at index 0, tool 2 at index 1.
func buildAnthropicSSETwoToolsOnly(tool1Name, tool1ID, tool2Name, tool2ID string) string {
	var b strings.Builder

	// message_start
	b.WriteString("event: message_start\n")
	b.WriteString(`data: {"type":"message_start","message":{"id":"msg_03","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}`)
	b.WriteString("\n\n")

	// tool_use block 1: content_block_start (index 0)
	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"` + tool1ID + `","name":"` + tool1Name + `"}}`)
	b.WriteString("\n\n")

	// tool_use block 1: content_block_delta (index 0)
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"NYC\"}"}}`)
	b.WriteString("\n\n")

	// tool_use block 1: content_block_stop (index 0)
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":0}`)
	b.WriteString("\n\n")

	// tool_use block 2: content_block_start (index 1)
	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"` + tool2ID + `","name":"` + tool2Name + `"}}`)
	b.WriteString("\n\n")

	// tool_use block 2: content_block_delta (index 1)
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"confirm\": true}"}}`)
	b.WriteString("\n\n")

	// tool_use block 2: content_block_stop (index 1)
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":1}`)
	b.WriteString("\n\n")

	// message_delta with stop_reason
	b.WriteString("event: message_delta\n")
	b.WriteString(`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":30}}`)
	b.WriteString("\n\n")

	// message_stop
	b.WriteString("event: message_stop\n")
	b.WriteString(`data: {"type":"message_stop"}`)
	b.WriteString("\n\n")

	return b.String()
}

func TestSSEInterceptor_Anthropic_AllBlocked(t *testing.T) {
	// --- Setup ---

	// Build an Anthropic SSE stream: two tool_use blocks, get_weather at index 0, delete_all at index 1.
	sseInput := buildAnthropicSSETwoToolsOnly(
		"get_weather", "toolu_01CCC",
		"delete_all", "toolu_01DDD",
	)

	// Registry: both tools registered
	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})
	reg.Register("danger-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "delete_all", Hash: "def456"},
	})

	// Policy: denylist blocking both
	policy := newTestPolicy(
		config.MCPToolRule{Server: "weather-server", Tool: "get_weather"},
		config.MCPToolRule{Server: "danger-server", Tool: "delete_all"},
	)

	// Collect event callbacks
	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Execute ---
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_1", "req_1", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	buffered := interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// --- Assertions ---

	// 1. Both tool_use blocks must be suppressed — no original tool_use content_block_start.
	if strings.Contains(clientOutput, `"type":"tool_use"`) {
		t.Error("both blocked tool_use content_block_start events should be suppressed")
	}

	// 2. Replacement text blocks for both tools must be present.
	expectedMsg1 := "[agentsh] Tool 'get_weather' blocked by policy"
	expectedMsg2 := "[agentsh] Tool 'delete_all' blocked by policy"
	if !strings.Contains(clientOutput, expectedMsg1) {
		t.Errorf("expected replacement text %q in client output", expectedMsg1)
	}
	if !strings.Contains(clientOutput, expectedMsg2) {
		t.Errorf("expected replacement text %q in client output", expectedMsg2)
	}

	// 3. stop_reason must be rewritten to "end_turn" (all tool_use blocked).
	if !strings.Contains(clientOutput, `"end_turn"`) {
		t.Error("stop_reason should be rewritten to end_turn when all tool_use are blocked")
	}
	// The original stop_reason "tool_use" in message_delta should NOT appear.
	lines := strings.Split(clientOutput, "\n")
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		var evt struct {
			Type  string `json:"type"`
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}
		if evt.Type == "message_delta" && evt.Delta.StopReason == "tool_use" {
			t.Error("message_delta stop_reason should not be 'tool_use' when all tools are blocked")
		}
	}

	// 4. Exactly 2 block events.
	if len(events) != 2 {
		t.Fatalf("expected 2 event callbacks, got %d", len(events))
	}
	if events[0].Action != "block" || events[0].ToolName != "get_weather" {
		t.Errorf("expected first event: block/get_weather, got %s/%s", events[0].Action, events[0].ToolName)
	}
	if events[0].ToolCallID != "toolu_01CCC" {
		t.Errorf("expected first event tool call ID %q, got %q", "toolu_01CCC", events[0].ToolCallID)
	}
	if events[1].Action != "block" || events[1].ToolName != "delete_all" {
		t.Errorf("expected second event: block/delete_all, got %s/%s", events[1].Action, events[1].ToolName)
	}
	if events[1].ToolCallID != "toolu_01DDD" {
		t.Errorf("expected second event tool call ID %q, got %q", "toolu_01DDD", events[1].ToolCallID)
	}
	// Both events should have non-empty reasons.
	if events[0].Reason == "" {
		t.Error("expected non-empty reason for first blocked tool event")
	}
	if events[1].Reason == "" {
		t.Error("expected non-empty reason for second blocked tool event")
	}

	// 5. No input_json_delta should appear (both tools blocked).
	if strings.Contains(clientOutput, "input_json_delta") {
		t.Error("input_json_delta for blocked tools should be suppressed")
	}

	// 6. Replacement text blocks should use the correct indices (0 and 1).
	replacementIdx0Start := false
	replacementIdx1Start := false
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		var block struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(data), &block); err != nil {
			continue
		}
		if block.Type == "content_block_start" && block.ContentBlock.Type == "text" && block.Index == 0 {
			replacementIdx0Start = true
		}
		if block.Type == "content_block_start" && block.ContentBlock.Type == "text" && block.Index == 1 {
			replacementIdx1Start = true
		}
	}
	if !replacementIdx0Start {
		t.Error("expected replacement content_block_start for text block at index 0")
	}
	if !replacementIdx1Start {
		t.Error("expected replacement content_block_start for text block at index 1")
	}

	// 7. message_stop must be present.
	if !strings.Contains(clientOutput, `"message_stop"`) {
		t.Error("message_stop event should be present in output")
	}

	// 8. Buffered output must match client output.
	if string(buffered) != clientOutput {
		t.Errorf("buffered output does not match client output.\nbuffered len=%d, client len=%d", len(buffered), len(clientOutput))
	}

	// 9. No orphan event: lines.
	eventLines := 0
	dataLines := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "event:") {
			eventLines++
		}
		if strings.HasPrefix(line, "data:") {
			dataLines++
		}
	}
	if eventLines != dataLines {
		t.Errorf("SSE output has %d event: lines but %d data: lines; they should match", eventLines, dataLines)
	}
}

// --- OpenAI SSE helpers ---

// buildOpenAISingleToolSSE constructs a realistic OpenAI SSE stream with a single tool call.
func buildOpenAISingleToolSSE(toolName, callID string) string {
	var b strings.Builder

	// First chunk: tool call with id + function.name
	b.WriteString(`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"` + callID + `","type":"function","function":{"name":"` + toolName + `","arguments":""}}]},"finish_reason":null}]}`)
	b.WriteString("\n\n")

	// Argument streaming chunk
	b.WriteString(`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"location\": \"NYC\"}"}}]},"finish_reason":null}]}`)
	b.WriteString("\n\n")

	// Finish chunk
	b.WriteString(`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`)
	b.WriteString("\n\n")

	// DONE
	b.WriteString("data: [DONE]")
	b.WriteString("\n\n")

	return b.String()
}

// buildOpenAITwoToolSSE constructs an OpenAI SSE stream with two parallel tool calls.
func buildOpenAITwoToolSSE(tool1Name, call1ID, tool2Name, call2ID string) string {
	var b strings.Builder

	// First chunk: both tool calls with id + function.name
	b.WriteString(`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"` + call1ID + `","type":"function","function":{"name":"` + tool1Name + `","arguments":""}},{"index":1,"id":"` + call2ID + `","type":"function","function":{"name":"` + tool2Name + `","arguments":""}}]},"finish_reason":null}]}`)
	b.WriteString("\n\n")

	// Argument streaming chunk for tool 0
	b.WriteString(`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"location\": \"NYC\"}"}}]},"finish_reason":null}]}`)
	b.WriteString("\n\n")

	// Argument streaming chunk for tool 1
	b.WriteString(`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{}"}}]},"finish_reason":null}]}`)
	b.WriteString("\n\n")

	// Finish chunk
	b.WriteString(`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`)
	b.WriteString("\n\n")

	// DONE
	b.WriteString("data: [DONE]")
	b.WriteString("\n\n")

	return b.String()
}

func TestSSEInterceptor_OpenAI_SingleBlocked(t *testing.T) {
	// --- Setup ---

	// Build an OpenAI SSE stream with a single tool call "get_weather" (blocked).
	sseInput := buildOpenAISingleToolSSE("get_weather", "call_abc123")

	// Registry: get_weather from "weather-server"
	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	// Policy: denylist blocking get_weather
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "get_weather"})

	// Collect event callbacks
	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Execute ---
	interceptor := NewSSEInterceptor(reg, policy, DialectOpenAI, "sess_1", "req_1", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	buffered := interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// --- Assertions ---

	// 1. tool_calls should be removed from the first chunk; content should have the blocked message.
	expectedMsg := "[agentsh] Tool 'get_weather' blocked by policy"
	if !strings.Contains(clientOutput, expectedMsg) {
		t.Errorf("expected blocked message %q in client output, got:\n%s", expectedMsg, clientOutput)
	}

	// 2. The original tool_calls with get_weather function name should NOT appear in output.
	if strings.Contains(clientOutput, `"name":"get_weather"`) {
		t.Error("blocked tool call get_weather should not appear in client output")
	}

	// 3. finish_reason should be rewritten to "stop" (not "tool_calls").
	if strings.Contains(clientOutput, `"finish_reason":"tool_calls"`) {
		t.Error("finish_reason should be rewritten from 'tool_calls' to 'stop' when all tools are blocked")
	}
	if !strings.Contains(clientOutput, `"finish_reason":"stop"`) {
		t.Errorf("expected finish_reason 'stop' in output, got:\n%s", clientOutput)
	}

	// 4. Argument streaming chunks should be suppressed.
	lines := strings.Split(clientOutput, "\n")
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		for _, choice := range chunk.Choices {
			for _, tc := range choice.Delta.ToolCalls {
				if tc.Function.Arguments != "" {
					t.Errorf("argument-streaming chunk for blocked tool should be suppressed, found index %d with args %q", tc.Index, tc.Function.Arguments)
				}
			}
		}
	}

	// 5. data: [DONE] must be present.
	if !strings.Contains(clientOutput, "data: [DONE]") {
		t.Error("[DONE] sentinel should be present in output")
	}

	// 6. Event callback should have fired with action=block.
	if len(events) != 1 {
		t.Fatalf("expected 1 event callback, got %d", len(events))
	}
	evt := events[0]
	if evt.Action != "block" {
		t.Errorf("expected event action %q, got %q", "block", evt.Action)
	}
	if evt.ToolName != "get_weather" {
		t.Errorf("expected event tool name %q, got %q", "get_weather", evt.ToolName)
	}
	if evt.ToolCallID != "call_abc123" {
		t.Errorf("expected event tool call ID %q, got %q", "call_abc123", evt.ToolCallID)
	}
	if evt.ServerID != "weather-server" {
		t.Errorf("expected event server ID %q, got %q", "weather-server", evt.ServerID)
	}
	if evt.Dialect != "openai" {
		t.Errorf("expected event dialect %q, got %q", "openai", evt.Dialect)
	}
	if evt.Reason == "" {
		t.Error("expected non-empty event reason for blocked tool")
	}

	// 7. Buffered output must match client output.
	if string(buffered) != clientOutput {
		t.Errorf("buffered output does not match client output.\nbuffered len=%d, client len=%d", len(buffered), len(clientOutput))
	}
}

func TestSSEInterceptor_MalformedJSON(t *testing.T) {
	// --- Setup ---

	// Build an Anthropic SSE stream that includes an invalid JSON data line between
	// a valid message_start and message_stop. The interceptor must not panic and
	// must pass all lines through unchanged (fail open).
	var b strings.Builder

	// message_start (valid)
	b.WriteString("event: message_start\n")
	b.WriteString(`data: {"type":"message_start","message":{"id":"msg_99","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":5,"output_tokens":0}}}`)
	b.WriteString("\n\n")

	// content_block_start for a text block (valid)
	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
	b.WriteString("\n\n")

	// malformed JSON data line
	b.WriteString("event: content_block_delta\n")
	b.WriteString("data: {INVALID JSON HERE}\n\n")

	// valid text delta
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello world."}}`)
	b.WriteString("\n\n")

	// content_block_stop (valid)
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":0}`)
	b.WriteString("\n\n")

	// message_delta (valid)
	b.WriteString("event: message_delta\n")
	b.WriteString(`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}`)
	b.WriteString("\n\n")

	// message_stop (valid)
	b.WriteString("event: message_stop\n")
	b.WriteString(`data: {"type":"message_stop"}`)
	b.WriteString("\n\n")

	sseInput := b.String()

	// Registry and policy: denylist blocking everything (to stress any blocking logic).
	reg := mcpregistry.NewRegistry()
	reg.Register("some-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "some_tool", Hash: "abc123"},
	})
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "*"})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Execute (must not panic) ---
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_mj", "req_mj", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer

	// Use a deferred recover to catch any panic and fail the test explicitly.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("interceptor panicked on malformed JSON: %v", r)
			}
		}()
		interceptor.Stream(reader, &clientBuf)
	}()

	clientOutput := clientBuf.String()

	// --- Assertions ---

	// 1. The malformed JSON line must pass through unchanged (fail open).
	if !strings.Contains(clientOutput, "{INVALID JSON HERE}") {
		t.Error("malformed JSON data line should pass through unchanged (fail open)")
	}

	// 2. Valid events before and after the malformed line must also pass through.
	if !strings.Contains(clientOutput, `"message_start"`) {
		t.Error("message_start event should be present in output")
	}
	if !strings.Contains(clientOutput, "Hello world.") {
		t.Error("valid text delta after malformed JSON should pass through")
	}
	if !strings.Contains(clientOutput, `"message_stop"`) {
		t.Error("message_stop event should be present in output")
	}

	// 3. No [agentsh] replacement messages — no tool calls were in the stream.
	if strings.Contains(clientOutput, "[agentsh]") {
		t.Error("no [agentsh] message should appear when there are no tool calls")
	}

	// 4. No events should have fired (no MCP tool calls seen).
	if len(events) != 0 {
		t.Errorf("expected 0 event callbacks, got %d", len(events))
	}
}

func TestSSEInterceptor_TextOnlyStream(t *testing.T) {
	// --- Setup ---

	// Build a standard Anthropic text-only SSE stream (no tool calls).
	var b strings.Builder

	// message_start
	b.WriteString("event: message_start\n")
	b.WriteString(`data: {"type":"message_start","message":{"id":"msg_text1","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":8,"output_tokens":0}}}`)
	b.WriteString("\n\n")

	// text content_block_start
	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
	b.WriteString("\n\n")

	// text content_block_delta
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Here is a purely textual response."}}`)
	b.WriteString("\n\n")

	// text content_block_stop
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":0}`)
	b.WriteString("\n\n")

	// message_delta with stop_reason=end_turn
	b.WriteString("event: message_delta\n")
	b.WriteString(`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":10}}`)
	b.WriteString("\n\n")

	// message_stop
	b.WriteString("event: message_stop\n")
	b.WriteString(`data: {"type":"message_stop"}`)
	b.WriteString("\n\n")

	sseInput := b.String()

	// Registry and policy: denylist blocking everything (to ensure non-tool streams are unaffected).
	reg := mcpregistry.NewRegistry()
	reg.Register("some-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "some_tool", Hash: "abc123"},
	})
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "*"})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Execute ---
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_to", "req_to", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	buffered := interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// --- Assertions ---

	// 1. All events must pass through unchanged.
	if !strings.Contains(clientOutput, `"message_start"`) {
		t.Error("message_start should be present in output")
	}
	if !strings.Contains(clientOutput, "Here is a purely textual response.") {
		t.Error("text delta content should pass through unchanged")
	}
	if !strings.Contains(clientOutput, `"message_stop"`) {
		t.Error("message_stop should be present in output")
	}

	// 2. stop_reason must remain "end_turn" — must not be rewritten.
	foundEndTurn := false
	lines := strings.Split(clientOutput, "\n")
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		var evt struct {
			Type  string `json:"type"`
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}
		if evt.Type == "message_delta" && evt.Delta.StopReason == "end_turn" {
			foundEndTurn = true
		}
	}
	if !foundEndTurn {
		t.Error("stop_reason should be 'end_turn' in a text-only stream")
	}

	// 3. No [agentsh] messages — there were no tool calls.
	if strings.Contains(clientOutput, "[agentsh]") {
		t.Error("no [agentsh] message should appear in a text-only stream")
	}

	// 4. No event callbacks — no MCP tool calls were seen.
	if len(events) != 0 {
		t.Errorf("expected 0 event callbacks for text-only stream, got %d", len(events))
	}

	// 5. No orphan event: lines.
	eventLines := 0
	dataLines := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "event:") {
			eventLines++
		}
		if strings.HasPrefix(line, "data:") {
			dataLines++
		}
	}
	if eventLines != dataLines {
		t.Errorf("SSE output has %d event: lines but %d data: lines; they should match", eventLines, dataLines)
	}

	// 6. Buffered output must match client output.
	if string(buffered) != clientOutput {
		t.Errorf("buffered output does not match client output.\nbuffered len=%d, client len=%d", len(buffered), len(clientOutput))
	}
}

func TestSSEInterceptor_OpenAI_PartialBlock(t *testing.T) {
	// --- Setup ---

	// Build an OpenAI SSE stream with two parallel tools:
	// get_weather (allowed, index 0) and delete_all (blocked, index 1).
	sseInput := buildOpenAITwoToolSSE("get_weather", "call_AAA", "delete_all", "call_BBB")

	// Registry: both tools registered
	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})
	reg.Register("danger-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "delete_all", Hash: "def456"},
	})

	// Policy: denylist blocking delete_all only
	policy := newTestPolicy(config.MCPToolRule{Server: "danger-server", Tool: "delete_all"})

	// Collect event callbacks
	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- Execute ---
	interceptor := NewSSEInterceptor(reg, policy, DialectOpenAI, "sess_1", "req_1", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	buffered := interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// --- Assertions ---

	// 1. get_weather (index 0) should be present in the output.
	if !strings.Contains(clientOutput, `"name":"get_weather"`) {
		t.Error("allowed tool get_weather should be present in client output")
	}

	// 2. delete_all (index 1) should NOT be present in the output.
	if strings.Contains(clientOutput, `"name":"delete_all"`) {
		t.Error("blocked tool delete_all should not be present in client output")
	}

	// 3. finish_reason should remain "tool_calls" (not all tools blocked).
	if !strings.Contains(clientOutput, `"finish_reason":"tool_calls"`) {
		t.Errorf("finish_reason should remain 'tool_calls' when some tools are allowed, got:\n%s", clientOutput)
	}

	// 4. Argument chunk for index 0 (get_weather) should pass through.
	foundArgChunkIdx0 := false
	lines := strings.Split(clientOutput, "\n")
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		for _, choice := range chunk.Choices {
			for _, tc := range choice.Delta.ToolCalls {
				if tc.Index == 0 && tc.Function.Arguments != "" {
					foundArgChunkIdx0 = true
				}
			}
		}
	}
	if !foundArgChunkIdx0 {
		t.Error("argument streaming chunk for allowed tool at index 0 should pass through")
	}

	// 5. Argument chunk for index 1 (delete_all) should be suppressed.
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		for _, choice := range chunk.Choices {
			for _, tc := range choice.Delta.ToolCalls {
				if tc.Index == 1 && tc.Function.Arguments != "" {
					t.Error("argument streaming chunk for blocked tool at index 1 should be suppressed")
				}
			}
		}
	}

	// 6. data: [DONE] must be present.
	if !strings.Contains(clientOutput, "data: [DONE]") {
		t.Error("[DONE] sentinel should be present in output")
	}

	// 7. Exactly 2 events: allow for get_weather, block for delete_all.
	if len(events) != 2 {
		t.Fatalf("expected 2 event callbacks, got %d", len(events))
	}
	if events[0].Action != "allow" || events[0].ToolName != "get_weather" {
		t.Errorf("expected first event: allow/get_weather, got %s/%s", events[0].Action, events[0].ToolName)
	}
	if events[0].ToolCallID != "call_AAA" {
		t.Errorf("expected first event tool call ID %q, got %q", "call_AAA", events[0].ToolCallID)
	}
	if events[1].Action != "block" || events[1].ToolName != "delete_all" {
		t.Errorf("expected second event: block/delete_all, got %s/%s", events[1].Action, events[1].ToolName)
	}
	if events[1].ToolCallID != "call_BBB" {
		t.Errorf("expected second event tool call ID %q, got %q", "call_BBB", events[1].ToolCallID)
	}
	if events[1].Reason == "" {
		t.Error("expected non-empty reason for blocked tool event")
	}

	// 8. Buffered output must match client output.
	if string(buffered) != clientOutput {
		t.Errorf("buffered output does not match client output.\nbuffered len=%d, client len=%d", len(buffered), len(clientOutput))
	}
}

// buildOpenAIMultiChoiceSSE constructs an OpenAI SSE stream with two choices
// (n=2). choice 0 has tool1, choice 1 has tool2.
func buildOpenAIMultiChoiceSSE(tool1Name, call1ID, tool2Name, call2ID string) string {
	var b strings.Builder

	// First chunk: both choices with their respective tool calls.
	b.WriteString(`data: {"id":"chatcmpl-mc","object":"chat.completion.chunk","choices":[` +
		`{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"` + call1ID + `","type":"function","function":{"name":"` + tool1Name + `","arguments":""}}]},"finish_reason":null},` +
		`{"index":1,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"` + call2ID + `","type":"function","function":{"name":"` + tool2Name + `","arguments":""}}]},"finish_reason":null}` +
		`]}`)
	b.WriteString("\n\n")

	// Argument streaming: choice 0, tool 0
	b.WriteString(`data: {"id":"chatcmpl-mc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"q\":1}"}}]},"finish_reason":null}]}`)
	b.WriteString("\n\n")

	// Argument streaming: choice 1, tool 0
	b.WriteString(`data: {"id":"chatcmpl-mc","object":"chat.completion.chunk","choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"q\":2}"}}]},"finish_reason":null}]}`)
	b.WriteString("\n\n")

	// Finish: both choices
	b.WriteString(`data: {"id":"chatcmpl-mc","object":"chat.completion.chunk","choices":[` +
		`{"index":0,"delta":{},"finish_reason":"tool_calls"},` +
		`{"index":1,"delta":{},"finish_reason":"tool_calls"}` +
		`]}`)
	b.WriteString("\n\n")

	b.WriteString("data: [DONE]\n\n")

	return b.String()
}

// TestSSEInterceptor_OpenAI_MultiChoice verifies that tool calls in choices
// beyond index 0 are inspected and blocked correctly (fix for C1).
func TestSSEInterceptor_OpenAI_MultiChoice(t *testing.T) {
	// choice 0: get_weather (allowed), choice 1: delete_all (blocked)
	sseInput := buildOpenAIMultiChoiceSSE("get_weather", "call_C0", "delete_all", "call_C1")

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})
	reg.Register("danger-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "delete_all", Hash: "def456"},
	})

	policy := newTestPolicy(config.MCPToolRule{Server: "danger-server", Tool: "delete_all"})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	interceptor := NewSSEInterceptor(reg, policy, DialectOpenAI, "sess_mc", "req_mc", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// 1. get_weather (choice 0) must pass through.
	if !strings.Contains(clientOutput, `"name":"get_weather"`) {
		t.Error("allowed tool get_weather in choice 0 should pass through")
	}

	// 2. delete_all (choice 1) must be blocked — name should not appear.
	if strings.Contains(clientOutput, `"name":"delete_all"`) {
		t.Error("blocked tool delete_all in choice 1 should NOT pass through")
	}

	// 3. Blocked message for delete_all should appear.
	if !strings.Contains(clientOutput, "[agentsh] Tool 'delete_all' blocked by policy") {
		t.Error("expected blocked message for delete_all in choice 1")
	}

	// 4. choice 0 finish_reason should remain "tool_calls" (has an allowed tool).
	// choice 1 finish_reason should be rewritten to "stop" (all tools blocked).
	lines := strings.Split(clientOutput, "\n")
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Index        int     `json:"index"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		for _, c := range chunk.Choices {
			if c.FinishReason == nil {
				continue
			}
			if c.Index == 0 && *c.FinishReason != "tool_calls" {
				t.Errorf("choice 0 finish_reason should remain 'tool_calls', got %q", *c.FinishReason)
			}
			if c.Index == 1 && *c.FinishReason != "stop" {
				t.Errorf("choice 1 finish_reason should be rewritten to 'stop', got %q", *c.FinishReason)
			}
		}
	}

	// 5. Argument chunk for choice 1 tool should be suppressed.
	for _, line := range lines {
		data, ok := extractSSEData(line)
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		for _, c := range chunk.Choices {
			if c.Index == 1 {
				for _, tc := range c.Delta.ToolCalls {
					if tc.Function.Arguments != "" {
						t.Error("argument chunk for blocked tool in choice 1 should be suppressed")
					}
				}
			}
		}
	}

	// 6. Events: allow for get_weather, block for delete_all.
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Action != "allow" || events[0].ToolName != "get_weather" {
		t.Errorf("expected allow/get_weather, got %s/%s", events[0].Action, events[0].ToolName)
	}
	if events[1].Action != "block" || events[1].ToolName != "delete_all" {
		t.Errorf("expected block/delete_all, got %s/%s", events[1].Action, events[1].ToolName)
	}
}

// TestSSEInterceptor_OpenAI_MixedMCPAndNonMCP verifies that finish_reason
// is NOT rewritten when blocked MCP tools coexist with non-MCP tools (fix for M1).
func TestSSEInterceptor_OpenAI_MixedMCPAndNonMCP(t *testing.T) {
	// Stream with two tool calls: str_replace_editor (non-MCP, not in registry)
	// and delete_all (MCP, blocked). finish_reason should remain "tool_calls"
	// because str_replace_editor passes through and the LLM expects a tool result.
	sseInput := buildOpenAITwoToolSSE("str_replace_editor", "call_NM1", "delete_all", "call_NM2")

	// Registry: only delete_all is registered (str_replace_editor is not MCP)
	reg := mcpregistry.NewRegistry()
	reg.Register("danger-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "delete_all", Hash: "def456"},
	})

	// Policy: denylist blocking delete_all
	policy := newTestPolicy(config.MCPToolRule{Server: "danger-server", Tool: "delete_all"})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(evt mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, evt)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	interceptor := NewSSEInterceptor(reg, policy, DialectOpenAI, "sess_mn", "req_mn", onEvent, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)
	var clientBuf bytes.Buffer
	interceptor.Stream(reader, &clientBuf)

	clientOutput := clientBuf.String()

	// 1. str_replace_editor (non-MCP) must pass through.
	if !strings.Contains(clientOutput, `"name":"str_replace_editor"`) {
		t.Error("non-MCP tool str_replace_editor should pass through")
	}

	// 2. delete_all (blocked MCP) must NOT pass through.
	if strings.Contains(clientOutput, `"name":"delete_all"`) {
		t.Error("blocked MCP tool delete_all should not pass through")
	}

	// 3. finish_reason must remain "tool_calls" — NOT rewritten to "stop"
	// because str_replace_editor still needs a tool result.
	if !strings.Contains(clientOutput, `"finish_reason":"tool_calls"`) {
		t.Errorf("finish_reason should remain 'tool_calls' when non-MCP tools pass through, got:\n%s", clientOutput)
	}
	if strings.Contains(clientOutput, `"finish_reason":"stop"`) {
		t.Error("finish_reason should NOT be rewritten to 'stop' when non-MCP tools remain")
	}

	// 4. Only 1 event: block for delete_all (str_replace_editor is not in registry).
	if len(events) != 1 {
		t.Fatalf("expected 1 event callback, got %d", len(events))
	}
	if events[0].Action != "block" || events[0].ToolName != "delete_all" {
		t.Errorf("expected block/delete_all, got %s/%s", events[0].Action, events[0].ToolName)
	}
}

// errorAfterN is a writer that returns an error after writing n bytes.
type errorAfterN struct {
	n       int
	written int
	buf     bytes.Buffer
}

func (e *errorAfterN) Write(p []byte) (int, error) {
	if e.written >= e.n {
		return 0, io.ErrClosedPipe
	}
	e.written += len(p)
	if e.written > e.n {
		// Allow partial write up to limit
		allowed := len(p) - (e.written - e.n)
		e.buf.Write(p[:allowed])
		return allowed, io.ErrClosedPipe
	}
	return e.buf.Write(p)
}

// TestSSEInterceptor_ClientWriteError verifies that the interceptor handles
// client disconnection gracefully, stops writing, and still returns buffered
// output for logging (fix for M3).
func TestSSEInterceptor_ClientWriteError(t *testing.T) {
	// Build a text-only stream with substantial content.
	sseInput := buildAnthropicSSE("get_weather", "toolu_err1")

	reg := mcpregistry.NewRegistry()
	// No tools registered — everything passes through (we're testing write errors, not blocking).

	policy := newTestPolicy() // empty denylist

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_we", "req_we", nil, logger, nil, nil, nil)

	reader := strings.NewReader(sseInput)

	// Client that errors after 100 bytes.
	client := &errorAfterN{n: 100}

	buffered := interceptor.Stream(reader, client)

	// 1. The interceptor must not panic.
	// (If we get here, it didn't.)

	// 2. Client received limited output (≤ n bytes + partial write).
	if client.buf.Len() > 200 {
		t.Errorf("expected client to receive limited output after error, got %d bytes", client.buf.Len())
	}

	// 3. Buffered output should still contain content (for logging).
	// It may be less than the full stream if the scan loop aborted early.
	if len(buffered) == 0 {
		t.Error("buffered output should not be empty even when client disconnects")
	}
}

func TestSSEInterceptor_RateLimitBlocks(t *testing.T) {
	rlCfg := config.MCPRateLimitsConfig{
		Enabled:      true,
		DefaultRPM:   0,
		DefaultBurst: 0,
	}
	rateLimiter := mcpinspect.NewRateLimiterRegistry(rlCfg)

	reg := mcpregistry.NewRegistry()
	reg.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "h1"},
	})
	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, ev)
	}
	logger := slog.Default()

	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_1", "req_1", onEvent, logger, nil, rateLimiter, nil)

	stream := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"stop_reason\":null}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"get_weather\",\"input\":{}}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	var buf bytes.Buffer
	interceptor.Stream(io.NopCloser(strings.NewReader(stream)), &buf)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "block" {
		t.Errorf("event Action = %q, want %q", events[0].Action, "block")
	}
	if !strings.Contains(events[0].Reason, "rate limit") {
		t.Errorf("event Reason = %q, want to contain 'rate limit'", events[0].Reason)
	}
}

func TestSSEInterceptor_VersionPinBlock(t *testing.T) {
	reg := mcpregistry.NewRegistry()
	reg.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v1"},
	})
	reg.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v2"},
	})
	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	vpCfg := &config.MCPVersionPinningConfig{
		Enabled:  true,
		OnChange: "block",
	}

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, ev)
	}
	logger := slog.Default()

	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_1", "req_1", onEvent, logger, nil, nil, vpCfg)

	stream := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"stop_reason\":null}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"get_weather\",\"input\":{}}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	var buf bytes.Buffer
	interceptor.Stream(io.NopCloser(strings.NewReader(stream)), &buf)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "block" {
		t.Errorf("event Action = %q, want %q", events[0].Action, "block")
	}
	if !strings.Contains(events[0].Reason, "hash changed") {
		t.Errorf("event Reason = %q, want to contain 'hash changed'", events[0].Reason)
	}
}

func TestSSEInterceptor_RateLimitBlocks_NilPolicy(t *testing.T) {
	// Rate limiter should block even when policy is nil (EnforcePolicy=false).
	rlCfg := config.MCPRateLimitsConfig{
		Enabled:      true,
		DefaultRPM:   0,
		DefaultBurst: 0,
	}
	rateLimiter := mcpinspect.NewRateLimiterRegistry(rlCfg)

	reg := mcpregistry.NewRegistry()
	reg.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "h1"},
	})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, ev)
	}
	logger := slog.Default()

	// policy is nil — simulating EnforcePolicy=false with rate limiting enabled.
	interceptor := NewSSEInterceptor(reg, nil, DialectAnthropic, "sess_1", "req_1", onEvent, logger, nil, rateLimiter, nil)

	stream := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"stop_reason\":null}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"get_weather\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	var buf bytes.Buffer
	interceptor.Stream(io.NopCloser(strings.NewReader(stream)), &buf)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "block" {
		t.Errorf("event Action = %q, want %q", events[0].Action, "block")
	}
	if !strings.Contains(events[0].Reason, "rate limit") {
		t.Errorf("event Reason = %q, want to contain 'rate limit'", events[0].Reason)
	}
}

func TestSSEInterceptor_VersionPinAlert(t *testing.T) {
	// Version pin alert mode should allow the call but set a reason on the event.
	reg := mcpregistry.NewRegistry()
	reg.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v1"},
	})
	reg.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v2"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	vpCfg := &config.MCPVersionPinningConfig{
		Enabled:  true,
		OnChange: "alert",
	}

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, ev)
	}
	logger := slog.Default()

	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_1", "req_1", onEvent, logger, nil, nil, vpCfg)

	stream := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"stop_reason\":null}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"get_weather\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	var buf bytes.Buffer
	interceptor.Stream(io.NopCloser(strings.NewReader(stream)), &buf)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	// Alert mode should allow the call.
	if events[0].Action != "allow" {
		t.Errorf("event Action = %q, want %q", events[0].Action, "allow")
	}
	// But the event should carry the alert reason.
	if !strings.Contains(events[0].Reason, "hash changed") {
		t.Errorf("event Reason = %q, want to contain 'hash changed'", events[0].Reason)
	}
	// The tool_use block should pass through (not blocked).
	output := buf.String()
	if strings.Contains(output, "blocked by policy") {
		t.Error("alert mode should not block the tool call")
	}
}

func TestSSEInterceptor_OpenAI_VersionPinAlert(t *testing.T) {
	// Version pin alert mode on the OpenAI SSE path should allow the call
	// but propagate the alert reason in the event.
	reg := mcpregistry.NewRegistry()
	reg.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v1"},
	})
	// Re-register with changed hash; pinned hash remains "hash-v1".
	reg.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v2"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	vpCfg := &config.MCPVersionPinningConfig{
		Enabled:  true,
		OnChange: "alert",
	}

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, ev)
	}
	logger := slog.Default()

	interceptor := NewSSEInterceptor(reg, policy, DialectOpenAI, "sess_oai_vpa", "req_oai_vpa", onEvent, logger, nil, nil, vpCfg)

	sseInput := buildOpenAISingleToolSSE("get_weather", "call_vpa_01")

	var buf bytes.Buffer
	interceptor.Stream(io.NopCloser(strings.NewReader(sseInput)), &buf)

	// 1. Exactly one event should fire.
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// 2. Alert mode should allow the call.
	if events[0].Action != "allow" {
		t.Errorf("event Action = %q, want %q", events[0].Action, "allow")
	}

	// 3. The event should carry the alert reason with "hash changed".
	if !strings.Contains(events[0].Reason, "hash changed") {
		t.Errorf("event Reason = %q, want to contain 'hash changed'", events[0].Reason)
	}

	// 4. The tool call should pass through (not blocked).
	output := buf.String()
	if strings.Contains(output, "blocked by policy") {
		t.Error("alert mode should not block the tool call")
	}
	if !strings.Contains(output, `"name":"get_weather"`) {
		t.Error("allowed tool get_weather should pass through in output")
	}

	// 5. finish_reason should remain "tool_calls" (tool was allowed).
	if !strings.Contains(output, `"finish_reason":"tool_calls"`) {
		t.Errorf("finish_reason should remain 'tool_calls' when tool is allowed, got:\n%s", output)
	}
}
