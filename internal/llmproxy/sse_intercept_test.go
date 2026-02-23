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
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess_1", "req_1", onEvent, logger)

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
