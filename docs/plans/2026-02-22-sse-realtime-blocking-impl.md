# Real-Time SSE Stream Blocking — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace audit-only SSE MCP interception with real-time inline blocking that suppresses blocked tool calls mid-stream and emits replacement text blocks.

**Architecture:** A stateful `SSEInterceptor` replaces `io.Copy` in the SSE transport's `RoundTrip`. It reads upstream line-by-line, evaluates policy on `content_block_start` (Anthropic) or first tool chunk (OpenAI), and either passes events through or replaces blocked tool_use blocks with `[agentsh] Tool 'X' blocked by policy` text blocks. When no policy is configured, the existing `io.Copy` fast path is preserved.

**Tech Stack:** Go, `bufio.Scanner`, `encoding/json`, `mcpregistry.Registry`, `mcpinspect.PolicyEvaluator`

**Design doc:** `docs/plans/2026-02-22-sse-realtime-blocking-design.md`

---

## Task 1: SSEInterceptor scaffold + Anthropic single blocked tool

Create the `SSEInterceptor` type and implement Anthropic blocking for the simplest case: a stream with one text block and one tool_use block that gets blocked.

**Files:**
- Create: `internal/llmproxy/sse_intercept.go`
- Create: `internal/llmproxy/sse_intercept_test.go`

**Step 1: Write the failing test**

In `internal/llmproxy/sse_intercept_test.go`:

```go
package llmproxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

// anthropicSSEStream builds a well-formed Anthropic SSE stream from content blocks.
// Each block is a slice of SSE event strings (event: + data: lines).
func anthropicSSEStream(blocks ...[]string) string {
	var b strings.Builder
	b.WriteString("event: message_start\n")
	b.WriteString(`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}`)
	b.WriteString("\n\n")
	for _, block := range blocks {
		for _, line := range block {
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// anthropicTextBlock returns SSE events for a text content block.
func anthropicTextBlock(index int, text string) []string {
	return []string{
		"event: content_block_start",
		fmt.Sprintf(`data: {"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`, index),
		"",
		"event: content_block_delta",
		fmt.Sprintf(`data: {"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":"%s"}}`, index, text),
		"",
		"event: content_block_stop",
		fmt.Sprintf(`data: {"type":"content_block_stop","index":%d}`, index),
	}
}

// anthropicToolBlock returns SSE events for a tool_use content block.
func anthropicToolBlock(index int, id, name, argsJSON string) []string {
	return []string{
		"event: content_block_start",
		fmt.Sprintf(`data: {"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":"%s","name":"%s"}}`, index, id, name),
		"",
		"event: content_block_delta",
		fmt.Sprintf(`data: {"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":"%s"}}`, index, strings.ReplaceAll(argsJSON, `"`, `\"`)),
		"",
		"event: content_block_stop",
		fmt.Sprintf(`data: {"type":"content_block_stop","index":%d}`, index),
	}
}

// anthropicEnd returns the message_delta + message_stop SSE events.
func anthropicEnd(stopReason string) string {
	return "event: message_delta\n" +
		fmt.Sprintf(`data: {"type":"message_delta","delta":{"stop_reason":"%s"},"usage":{"output_tokens":25}}`, stopReason) + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"
}

// newTestPolicy creates a PolicyEvaluator with a denylist blocking the given tool patterns.
func newTestPolicy(deniedTools ...config.MCPToolRule) *mcpinspect.PolicyEvaluator {
	return mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
		DeniedTools:   deniedTools,
	})
}

// newTestAllowPolicy creates a PolicyEvaluator with an allowlist allowing the given tool patterns.
func newTestAllowPolicy(allowedTools ...config.MCPToolRule) *mcpinspect.PolicyEvaluator {
	return mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		FailClosed:    true,
		ToolPolicy:    "allowlist",
		AllowedTools:  allowedTools,
	})
}

func TestSSEInterceptor_Anthropic_SingleBlocked(t *testing.T) {
	// Build SSE stream: text block at index 0, tool_use "get_weather" at index 1
	input := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me check."}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01AAA","name":"get_weather"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"NYC\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":1}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":25}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	// Registry: get_weather is an MCP tool from "weather-server"
	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})

	// Policy: deny get_weather
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "get_weather"})

	// Collect events
	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, ev)
	}

	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess-1", "req-1", onEvent, nil)

	var output bytes.Buffer
	buffered := interceptor.Stream(strings.NewReader(input), &output)

	result := output.String()

	// 1. The blocked tool_use content_block_start should NOT appear
	if strings.Contains(result, `"name":"get_weather"`) && strings.Contains(result, `"type":"tool_use"`) {
		t.Error("blocked tool_use content_block_start should be suppressed")
	}

	// 2. A replacement text block should appear with the blocked message
	if !strings.Contains(result, `[agentsh] Tool 'get_weather' blocked by policy`) {
		t.Error("expected replacement text block with blocked message")
	}

	// 3. The text block at index 0 should still be present
	if !strings.Contains(result, "Let me check.") {
		t.Error("text block should pass through")
	}

	// 4. stop_reason should be rewritten to "end_turn" (all tools blocked)
	if !strings.Contains(result, `"stop_reason":"end_turn"`) {
		t.Error("stop_reason should be rewritten to end_turn when all tools blocked")
	}
	if strings.Contains(result, `"stop_reason":"tool_use"`) {
		t.Error("stop_reason should NOT be tool_use when all tools blocked")
	}

	// 5. message_stop should still be present
	if !strings.Contains(result, `"type":"message_stop"`) {
		t.Error("message_stop should pass through")
	}

	// 6. Event callback should have fired with action=block
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "block" {
		t.Errorf("event action: got %q, want %q", events[0].Action, "block")
	}
	if events[0].ToolName != "get_weather" {
		t.Errorf("event tool_name: got %q, want %q", events[0].ToolName, "get_weather")
	}
	if events[0].ServerID != "weather-server" {
		t.Errorf("event server_id: got %q, want %q", events[0].ServerID, "weather-server")
	}

	// 7. Buffered output should match what was written to client
	if !bytes.Equal(buffered, output.Bytes()) {
		t.Error("buffered output should match client output")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/ -run TestSSEInterceptor_Anthropic_SingleBlocked -v`
Expected: FAIL — `NewSSEInterceptor` not defined

**Step 3: Write minimal implementation**

In `internal/llmproxy/sse_intercept.go`:

```go
package llmproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

// SSEInterceptor inspects SSE events in-flight, suppressing blocked MCP tool
// calls and emitting replacement text blocks. It sits between the upstream LLM
// response body and the client writer.
type SSEInterceptor struct {
	registry  *mcpregistry.Registry
	policy    *mcpinspect.PolicyEvaluator
	dialect   Dialect
	sessionID string
	requestID string
	onEvent   func(mcpinspect.MCPToolCallInterceptedEvent)
	logger    *slog.Logger

	// Anthropic state
	blockedIndices map[int]bool
	totalToolUse   int
	blockedToolUse int

	// OpenAI state
	blockedToolIdx map[int]bool
	totalTools     int
	blockedTools   int

	// buffered copy of what was sent to client
	buf bytes.Buffer
}

// NewSSEInterceptor creates a new SSE interceptor for a single request.
func NewSSEInterceptor(
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	dialect Dialect,
	sessionID, requestID string,
	onEvent func(mcpinspect.MCPToolCallInterceptedEvent),
	logger *slog.Logger,
) *SSEInterceptor {
	if logger == nil {
		logger = slog.Default()
	}
	return &SSEInterceptor{
		registry:       registry,
		policy:         policy,
		dialect:        dialect,
		sessionID:      sessionID,
		requestID:      requestID,
		onEvent:        onEvent,
		logger:         logger,
		blockedIndices: make(map[int]bool),
		blockedToolIdx: make(map[int]bool),
	}
}

// Stream reads SSE events from upstream, applies policy-based interception,
// and writes the (possibly modified) stream to client. Returns the full
// buffered output for logging.
func (s *SSEInterceptor) Stream(upstream io.Reader, client io.Writer) []byte {
	scanner := bufio.NewScanner(upstream)
	scanner.Buffer(make([]byte, 0, sseMaxLineSize), sseMaxLineSize)

	for scanner.Scan() {
		line := scanner.Text()

		// Non-data lines pass through verbatim
		data, isData := extractSSEData(line)
		if !isData {
			s.writeLine(client, line)
			continue
		}

		// data: [DONE] passes through
		if data == "[DONE]" {
			s.writeLine(client, line)
			continue
		}

		// Dispatch to dialect-specific processor
		var outputLines []string
		switch s.dialect {
		case DialectAnthropic:
			outputLines = s.processAnthropicEvent(line, []byte(data))
		case DialectOpenAI:
			outputLines = s.processOpenAIEvent(line, []byte(data))
		default:
			outputLines = []string{line}
		}

		for _, ol := range outputLines {
			s.writeLine(client, ol)
		}
	}

	if err := scanner.Err(); err != nil {
		s.logger.Warn("sse interceptor scanner error", "error", err, "request_id", s.requestID)
	}

	return s.buf.Bytes()
}

// writeLine writes a line + newline to both the client and the internal buffer.
func (s *SSEInterceptor) writeLine(client io.Writer, line string) {
	lineBytes := []byte(line + "\n")
	client.Write(lineBytes)
	s.buf.Write(lineBytes)
	// Flush if the writer supports it
	if f, ok := client.(interface{ Flush() }); ok {
		f.Flush()
	}
}

// lookupAndEvaluate checks a tool name against the registry and policy.
// Returns nil entry if the tool is not in the registry (not an MCP tool).
func (s *SSEInterceptor) lookupAndEvaluate(toolName string) (*mcpregistry.ToolEntry, *mcpinspect.PolicyDecision) {
	entry := s.registry.Lookup(toolName)
	if entry == nil {
		return nil, nil
	}
	decision := s.policy.Evaluate(entry.ServerID, toolName, entry.ToolHash)
	return entry, &decision
}

// fireEvent fires an intercept event via the callback.
func (s *SSEInterceptor) fireEvent(toolName, toolCallID, action, reason string, entry *mcpregistry.ToolEntry) {
	if s.onEvent == nil {
		return
	}
	s.onEvent(mcpinspect.MCPToolCallInterceptedEvent{
		Type:       "mcp_tool_call_intercepted",
		Timestamp:  time.Now(),
		SessionID:  s.sessionID,
		RequestID:  s.requestID,
		Dialect:    string(s.dialect),
		ToolName:   toolName,
		ToolCallID: toolCallID,
		ServerID:   entry.ServerID,
		ServerType: entry.ServerType,
		ServerAddr: entry.ServerAddr,
		ToolHash:   entry.ToolHash,
		Action:     action,
		Reason:     reason,
	})
}

// --- Anthropic dialect ---

// processAnthropicEvent handles a single data: line for Anthropic SSE.
// Returns the lines to emit (may be 0 for suppression, 1 for pass-through,
// or multiple for replacement).
func (s *SSEInterceptor) processAnthropicEvent(originalLine string, data []byte) []string {
	// Quick check: does this line contain anything tool-related?
	// Parse minimal structure to determine event type.
	var evt struct {
		Type         string `json:"type"`
		Index        int    `json:"index"`
		ContentBlock struct {
			Type string `json:"type"`
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"content_block"`
		Delta json.RawMessage `json:"delta"`
	}
	if err := json.Unmarshal(data, &evt); err != nil {
		// Malformed JSON: pass through
		return []string{originalLine}
	}

	switch evt.Type {
	case "content_block_start":
		if evt.ContentBlock.Type == "tool_use" {
			s.totalToolUse++

			entry, decision := s.lookupAndEvaluate(evt.ContentBlock.Name)
			if entry == nil {
				// Not an MCP tool — pass through silently
				return []string{originalLine}
			}

			if !decision.Allowed {
				// BLOCKED: suppress this and emit replacement text block
				s.blockedIndices[evt.Index] = true
				s.blockedToolUse++
				s.fireEvent(evt.ContentBlock.Name, evt.ContentBlock.ID, "block", decision.Reason, entry)
				return s.emitAnthropicTextBlock(evt.Index, evt.ContentBlock.Name)
			}

			// Allowed: pass through, fire event
			s.fireEvent(evt.ContentBlock.Name, evt.ContentBlock.ID, "allow", "", entry)
			return []string{originalLine}
		}
		// Text or other content block — pass through
		return []string{originalLine}

	case "content_block_delta":
		if s.blockedIndices[evt.Index] {
			return nil // suppress
		}
		return []string{originalLine}

	case "content_block_stop":
		if s.blockedIndices[evt.Index] {
			return nil // suppress
		}
		return []string{originalLine}

	case "message_delta":
		// If all tool_use blocks were blocked, rewrite stop_reason
		if s.totalToolUse > 0 && s.blockedToolUse == s.totalToolUse {
			return []string{s.rewriteAnthropicStopReason(data)}
		}
		return []string{originalLine}

	default:
		return []string{originalLine}
	}
}

// emitAnthropicTextBlock generates 3 SSE data lines that form a complete
// replacement text block for a blocked tool.
func (s *SSEInterceptor) emitAnthropicTextBlock(index int, toolName string) []string {
	msg := fmt.Sprintf("[agentsh] Tool '%s' blocked by policy", toolName)
	return []string{
		fmt.Sprintf(`data: {"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`, index),
		fmt.Sprintf(`data: {"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":"%s"}}`, index, msg),
		fmt.Sprintf(`data: {"type":"content_block_stop","index":%d}`, index),
	}
}

// rewriteAnthropicStopReason rewrites the message_delta stop_reason to "end_turn".
func (s *SSEInterceptor) rewriteAnthropicStopReason(data []byte) string {
	// Parse, modify, re-serialize to preserve other fields (like usage)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return "data: " + string(data)
	}

	var delta map[string]json.RawMessage
	if err := json.Unmarshal(raw["delta"], &delta); err != nil {
		return "data: " + string(data)
	}

	delta["stop_reason"] = json.RawMessage(`"end_turn"`)

	deltaBytes, _ := json.Marshal(delta)
	raw["delta"] = json.RawMessage(deltaBytes)
	out, _ := json.Marshal(raw)
	return "data: " + string(out)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/ -run TestSSEInterceptor_Anthropic_SingleBlocked -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/llmproxy/sse_intercept.go internal/llmproxy/sse_intercept_test.go
git commit -m "feat(llmproxy): add SSEInterceptor with Anthropic single-tool blocking"
```

---

## Task 2: Anthropic allowed tool + unregistered tool

**Files:**
- Modify: `internal/llmproxy/sse_intercept_test.go`

**Step 1: Write the failing tests**

Add to `sse_intercept_test.go`:

```go
func TestSSEInterceptor_Anthropic_SingleAllowed(t *testing.T) {
	// Same stream as single-blocked but with an allow policy
	input := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01AAA","name":"get_weather"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"NYC\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})

	// Policy: allow get_weather
	policy := newTestAllowPolicy(config.MCPToolRule{Server: "*", Tool: "get_weather"})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess-1", "req-1",
		func(ev mcpinspect.MCPToolCallInterceptedEvent) { events = append(events, ev) }, nil)

	var output bytes.Buffer
	interceptor.Stream(strings.NewReader(input), &output)

	result := output.String()

	// Tool should pass through unmodified
	if !strings.Contains(result, `"name":"get_weather"`) {
		t.Error("allowed tool should pass through")
	}
	if strings.Contains(result, "[agentsh]") {
		t.Error("allowed tool should not have blocked message")
	}
	if !strings.Contains(result, `"stop_reason":"tool_use"`) {
		t.Error("stop_reason should remain tool_use for allowed tools")
	}

	// Event should fire with action=allow
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "allow" {
		t.Errorf("event action: got %q, want %q", events[0].Action, "allow")
	}
}

func TestSSEInterceptor_Anthropic_Unregistered(t *testing.T) {
	// Stream with a tool that is NOT in the registry (e.g. a native tool)
	input := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01AAA","name":"str_replace_editor"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	// Empty registry — no MCP tools registered
	reg := mcpregistry.NewRegistry()
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "*"})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess-1", "req-1",
		func(ev mcpinspect.MCPToolCallInterceptedEvent) { events = append(events, ev) }, nil)

	var output bytes.Buffer
	interceptor.Stream(strings.NewReader(input), &output)

	result := output.String()

	// Unregistered tool passes through silently
	if !strings.Contains(result, `"name":"str_replace_editor"`) {
		t.Error("unregistered tool should pass through")
	}
	if strings.Contains(result, "[agentsh]") {
		t.Error("unregistered tool should not be blocked")
	}

	// No events for unregistered tools
	if len(events) != 0 {
		t.Fatalf("expected 0 events for unregistered tool, got %d", len(events))
	}
}
```

**Step 2: Run tests to verify they pass**

Run: `go test ./internal/llmproxy/ -run TestSSEInterceptor_Anthropic_Single -v`
Expected: PASS (implementation from Task 1 already handles these cases)

**Step 3: Commit**

```bash
git add internal/llmproxy/sse_intercept_test.go
git commit -m "test(llmproxy): add SSE interceptor tests for allowed + unregistered tools"
```

---

## Task 3: Anthropic partial block (2 tools, 1 blocked)

**Files:**
- Modify: `internal/llmproxy/sse_intercept_test.go`

**Step 1: Write the failing test**

Add to `sse_intercept_test.go`:

```go
func TestSSEInterceptor_Anthropic_PartialBlock(t *testing.T) {
	// Stream: text at 0, allowed tool "get_weather" at 1, blocked tool "delete_all" at 2
	input := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I'll do both."}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		// Tool 1: get_weather (allowed)
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01AAA","name":"get_weather"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"NYC\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":1}` + "\n\n" +
		// Tool 2: delete_all (blocked)
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_01BBB","name":"delete_all"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":2}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":25}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})
	reg.Register("danger-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "delete_all", Hash: "sha256:def"},
	})

	// Allow get_weather, deny delete_all
	policy := newTestPolicy(config.MCPToolRule{Server: "danger-server", Tool: "delete_all"})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess-1", "req-1",
		func(ev mcpinspect.MCPToolCallInterceptedEvent) { events = append(events, ev) }, nil)

	var output bytes.Buffer
	interceptor.Stream(strings.NewReader(input), &output)

	result := output.String()

	// get_weather should pass through
	if !strings.Contains(result, `"name":"get_weather"`) {
		t.Error("allowed tool get_weather should pass through")
	}

	// delete_all should be blocked
	if strings.Contains(result, `"name":"delete_all"`) {
		t.Error("blocked tool delete_all should be suppressed")
	}
	if !strings.Contains(result, `[agentsh] Tool 'delete_all' blocked by policy`) {
		t.Error("expected replacement text block for delete_all")
	}

	// stop_reason stays "tool_use" because get_weather is still allowed
	if !strings.Contains(result, `"stop_reason":"tool_use"`) {
		t.Error("stop_reason should stay tool_use for partial block")
	}

	// Should get 2 events: allow for get_weather, block for delete_all
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Action != "allow" || events[0].ToolName != "get_weather" {
		t.Errorf("event 0: got action=%q tool=%q, want allow/get_weather", events[0].Action, events[0].ToolName)
	}
	if events[1].Action != "block" || events[1].ToolName != "delete_all" {
		t.Errorf("event 1: got action=%q tool=%q, want block/delete_all", events[1].Action, events[1].ToolName)
	}

	// Verify no argument deltas leaked for blocked tool (index 2)
	// Count occurrences of content_block_delta with index 2
	if strings.Contains(result, `"index":2,"delta":{"type":"input_json_delta"`) {
		t.Error("argument deltas for blocked tool should be suppressed")
	}
}
```

**Step 2: Run test to verify it passes**

Run: `go test ./internal/llmproxy/ -run TestSSEInterceptor_Anthropic_PartialBlock -v`
Expected: PASS (implementation from Task 1 handles partial blocking via the `blockedIndices` map and `blockedToolUse < totalToolUse` check)

**Step 3: Commit**

```bash
git add internal/llmproxy/sse_intercept_test.go
git commit -m "test(llmproxy): add SSE interceptor partial block test"
```

---

## Task 4: Anthropic all tools blocked

**Files:**
- Modify: `internal/llmproxy/sse_intercept_test.go`

**Step 1: Write the failing test**

Add to `sse_intercept_test.go`:

```go
func TestSSEInterceptor_Anthropic_AllBlocked(t *testing.T) {
	// Two tool_use blocks, both blocked
	input := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01AAA","name":"get_weather"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01BBB","name":"delete_all"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":1}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":25}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})
	reg.Register("danger-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "delete_all", Hash: "sha256:def"},
	})

	// Block both tools
	policy := newTestPolicy(
		config.MCPToolRule{Server: "*", Tool: "get_weather"},
		config.MCPToolRule{Server: "*", Tool: "delete_all"},
	)

	var events []mcpinspect.MCPToolCallInterceptedEvent
	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess-1", "req-1",
		func(ev mcpinspect.MCPToolCallInterceptedEvent) { events = append(events, ev) }, nil)

	var output bytes.Buffer
	interceptor.Stream(strings.NewReader(input), &output)

	result := output.String()

	// Both tools should be replaced
	if !strings.Contains(result, `[agentsh] Tool 'get_weather' blocked by policy`) {
		t.Error("expected blocked message for get_weather")
	}
	if !strings.Contains(result, `[agentsh] Tool 'delete_all' blocked by policy`) {
		t.Error("expected blocked message for delete_all")
	}

	// stop_reason should be "end_turn" since ALL tools were blocked
	if !strings.Contains(result, `"stop_reason":"end_turn"`) {
		t.Error("stop_reason should be end_turn when all tools blocked")
	}

	// 2 block events
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	for _, ev := range events {
		if ev.Action != "block" {
			t.Errorf("expected all events to be block, got %q for %q", ev.Action, ev.ToolName)
		}
	}
}
```

**Step 2: Run test**

Run: `go test ./internal/llmproxy/ -run TestSSEInterceptor_Anthropic_AllBlocked -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/llmproxy/sse_intercept_test.go
git commit -m "test(llmproxy): add SSE interceptor all-tools-blocked test"
```

---

## Task 5: OpenAI single blocked tool

Implement `processOpenAIEvent` for the case where a single tool call is blocked.

**Files:**
- Modify: `internal/llmproxy/sse_intercept.go`
- Modify: `internal/llmproxy/sse_intercept_test.go`

**Step 1: Write the failing test**

Add to `sse_intercept_test.go`:

```go
func TestSSEInterceptor_OpenAI_SingleBlocked(t *testing.T) {
	// OpenAI SSE stream with one tool call
	input := `data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"location\": \"NYC\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n"

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})

	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "get_weather"})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	interceptor := NewSSEInterceptor(reg, policy, DialectOpenAI, "sess-1", "req-1",
		func(ev mcpinspect.MCPToolCallInterceptedEvent) { events = append(events, ev) }, nil)

	var output bytes.Buffer
	interceptor.Stream(strings.NewReader(input), &output)

	result := output.String()

	// tool_calls should be removed from the first chunk
	if strings.Contains(result, `"tool_calls"`) {
		t.Error("blocked tool_calls should be removed")
	}

	// Should contain the blocked message as content
	if !strings.Contains(result, `[agentsh] Tool 'get_weather' blocked by policy`) {
		t.Error("expected blocked message in content")
	}

	// finish_reason should be "stop" not "tool_calls"
	if !strings.Contains(result, `"finish_reason":"stop"`) {
		t.Error("finish_reason should be rewritten to stop")
	}
	if strings.Contains(result, `"finish_reason":"tool_calls"`) {
		t.Error("finish_reason should NOT be tool_calls")
	}

	// Argument streaming chunks should be suppressed
	if strings.Contains(result, `"arguments":"{\"location\"`) {
		t.Error("argument chunks for blocked tool should be suppressed")
	}

	// data: [DONE] should still be present
	if !strings.Contains(result, "[DONE]") {
		t.Error("data: [DONE] should pass through")
	}

	// Event callback
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "block" {
		t.Errorf("event action: got %q, want block", events[0].Action)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/ -run TestSSEInterceptor_OpenAI_SingleBlocked -v`
Expected: FAIL — `processOpenAIEvent` currently returns the original line (no OpenAI logic yet)

**Step 3: Write implementation**

Add the OpenAI processing methods to `sse_intercept.go`:

```go
// --- OpenAI dialect ---

// processOpenAIEvent handles a single data: line for OpenAI SSE.
func (s *SSEInterceptor) processOpenAIEvent(originalLine string, data []byte) []string {
	// Quick pre-filter: skip JSON parsing for lines that can't contain tool_calls
	if !bytes.Contains(data, []byte(`"tool_calls"`)) && !bytes.Contains(data, []byte(`"finish_reason"`)) {
		return []string{originalLine}
	}

	// Parse the chunk to inspect tool_calls and finish_reason
	var chunk struct {
		Choices []struct {
			Index  int `json:"index"`
			Delta  struct {
				Role      string          `json:"role,omitempty"`
				Content   json.RawMessage `json:"content,omitempty"`
				ToolCalls []struct {
					Index    int    `json:"index"`
					ID       string `json:"id,omitempty"`
					Type     string `json:"type,omitempty"`
					Function struct {
						Name      string `json:"name,omitempty"`
						Arguments string `json:"arguments,omitempty"`
					} `json:"function"`
				} `json:"tool_calls,omitempty"`
			} `json:"delta"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &chunk); err != nil {
		return []string{originalLine}
	}

	if len(chunk.Choices) == 0 {
		return []string{originalLine}
	}

	choice := chunk.Choices[0]

	// Case 1: First tool chunk (has id + function.name)
	if len(choice.Delta.ToolCalls) > 0 && choice.Delta.ToolCalls[0].ID != "" {
		return s.processOpenAIFirstToolChunk(data, choice.Delta.ToolCalls)
	}

	// Case 2: Argument streaming chunk (has tool_calls with only arguments)
	if len(choice.Delta.ToolCalls) > 0 {
		return s.processOpenAIArgumentChunk(originalLine, choice.Delta.ToolCalls)
	}

	// Case 3: Finish chunk (finish_reason present)
	if choice.FinishReason != nil && *choice.FinishReason == "tool_calls" {
		if s.totalTools > 0 && s.blockedTools == s.totalTools {
			// All blocked: rewrite finish_reason to "stop"
			return []string{s.rewriteOpenAIFinishReason(data)}
		}
		return []string{originalLine}
	}

	return []string{originalLine}
}

// processOpenAIFirstToolChunk handles the first delta that declares tool calls.
func (s *SSEInterceptor) processOpenAIFirstToolChunk(data []byte, toolCalls []struct {
	Index    int    `json:"index"`
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments,omitempty"`
	} `json:"function"`
}) []string {
	var kept []int // indices of tool calls to keep
	var blockedMessages []string

	for _, tc := range toolCalls {
		if tc.ID == "" || tc.Function.Name == "" {
			// Not a declaration chunk — keep
			kept = append(kept, tc.Index)
			continue
		}

		s.totalTools++

		entry, decision := s.lookupAndEvaluate(tc.Function.Name)
		if entry == nil {
			// Not an MCP tool — pass through
			kept = append(kept, tc.Index)
			continue
		}

		if !decision.Allowed {
			s.blockedToolIdx[tc.Index] = true
			s.blockedTools++
			s.fireEvent(tc.Function.Name, tc.ID, "block", decision.Reason, entry)
			blockedMessages = append(blockedMessages,
				fmt.Sprintf("[agentsh] Tool '%s' blocked by policy", tc.Function.Name))
		} else {
			kept = append(kept, tc.Index)
			s.fireEvent(tc.Function.Name, tc.ID, "allow", "", entry)
		}
	}

	if len(blockedMessages) == 0 {
		// Nothing blocked — pass through original
		return []string{"data: " + string(data)}
	}

	// Re-serialize the chunk with blocked tools removed
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return []string{"data: " + string(data)}
	}

	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(raw["choices"], &choices); err != nil || len(choices) == 0 {
		return []string{"data: " + string(data)}
	}

	var delta map[string]json.RawMessage
	if err := json.Unmarshal(choices[0]["delta"], &delta); err != nil {
		return []string{"data: " + string(data)}
	}

	if len(kept) == 0 {
		// ALL tools blocked: remove tool_calls, set content to blocked message
		delete(delta, "tool_calls")
		combinedMsg := strings.Join(blockedMessages, "\n")
		contentBytes, _ := json.Marshal(combinedMsg)
		delta["content"] = json.RawMessage(contentBytes)
	} else {
		// Partial block: filter tool_calls array
		var allCalls []json.RawMessage
		json.Unmarshal(delta["tool_calls"], &allCalls)

		var filteredCalls []json.RawMessage
		for _, callRaw := range allCalls {
			var tc struct{ Index int `json:"index"` }
			json.Unmarshal(callRaw, &tc)
			if !s.blockedToolIdx[tc.Index] {
				filteredCalls = append(filteredCalls, callRaw)
			}
		}
		filteredBytes, _ := json.Marshal(filteredCalls)
		delta["tool_calls"] = json.RawMessage(filteredBytes)
	}

	deltaBytes, _ := json.Marshal(delta)
	choices[0]["delta"] = json.RawMessage(deltaBytes)
	choicesBytes, _ := json.Marshal(choices)
	raw["choices"] = json.RawMessage(choicesBytes)
	out, _ := json.Marshal(raw)

	return []string{"data: " + string(out)}
}

// processOpenAIArgumentChunk filters argument-streaming chunks.
func (s *SSEInterceptor) processOpenAIArgumentChunk(originalLine string, toolCalls []struct {
	Index    int    `json:"index"`
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments,omitempty"`
	} `json:"function"`
}) []string {
	// Check if ALL tool calls in this chunk are blocked
	allBlocked := true
	for _, tc := range toolCalls {
		if !s.blockedToolIdx[tc.Index] {
			allBlocked = false
			break
		}
	}

	if allBlocked {
		return nil // suppress entire line
	}

	// Partial: need to filter. But OpenAI argument chunks typically contain
	// only one tool call entry, so if it's not blocked, pass through.
	// For mixed chunks (rare), we'd need to re-serialize.
	return []string{originalLine}
}

// rewriteOpenAIFinishReason rewrites finish_reason from "tool_calls" to "stop".
func (s *SSEInterceptor) rewriteOpenAIFinishReason(data []byte) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return "data: " + string(data)
	}

	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(raw["choices"], &choices); err != nil || len(choices) == 0 {
		return "data: " + string(data)
	}

	choices[0]["finish_reason"] = json.RawMessage(`"stop"`)

	choicesBytes, _ := json.Marshal(choices)
	raw["choices"] = json.RawMessage(choicesBytes)
	out, _ := json.Marshal(raw)

	return "data: " + string(out)
}
```

**Important:** The `processOpenAIEvent` currently uses an anonymous struct for the type assertion. The `processOpenAIFirstToolChunk` and `processOpenAIArgumentChunk` methods need a named struct type instead. Refactor: define a `openAIToolCallDelta` struct at file level and use it in the parsing + method signatures.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/ -run TestSSEInterceptor_OpenAI_SingleBlocked -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/llmproxy/sse_intercept.go internal/llmproxy/sse_intercept_test.go
git commit -m "feat(llmproxy): add OpenAI SSE interception for single blocked tool"
```

---

## Task 6: OpenAI partial block

**Files:**
- Modify: `internal/llmproxy/sse_intercept_test.go`

**Step 1: Write the failing test**

Add to `sse_intercept_test.go`:

```go
func TestSSEInterceptor_OpenAI_PartialBlock(t *testing.T) {
	// Two parallel tool calls: get_weather (allowed) and delete_all (blocked)
	input := `data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_AAA","type":"function","function":{"name":"get_weather","arguments":""}},{"index":1,"id":"call_BBB","type":"function","function":{"name":"delete_all","arguments":""}}]},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"location\": \"NYC\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{}"}}]},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n"

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})
	reg.Register("danger-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "delete_all", Hash: "sha256:def"},
	})

	// Block delete_all only
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "delete_all"})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	interceptor := NewSSEInterceptor(reg, policy, DialectOpenAI, "sess-1", "req-1",
		func(ev mcpinspect.MCPToolCallInterceptedEvent) { events = append(events, ev) }, nil)

	var output bytes.Buffer
	interceptor.Stream(strings.NewReader(input), &output)

	result := output.String()

	// get_weather should still be in the output
	if !strings.Contains(result, "get_weather") {
		t.Error("allowed tool get_weather should pass through")
	}

	// delete_all should NOT be in the output
	if strings.Contains(result, "delete_all") {
		t.Error("blocked tool delete_all should be removed")
	}

	// finish_reason stays "tool_calls" because one tool is still allowed
	if !strings.Contains(result, `"finish_reason":"tool_calls"`) {
		t.Error("finish_reason should stay tool_calls for partial block")
	}

	// Argument chunk for index 1 (blocked) should be suppressed
	// Argument chunk for index 0 (allowed) should pass through
	if !strings.Contains(result, `"location"`) {
		t.Error("argument chunk for allowed tool should pass through")
	}

	// 2 events
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}
```

**Step 2: Run test**

Run: `go test ./internal/llmproxy/ -run TestSSEInterceptor_OpenAI_PartialBlock -v`
Expected: PASS (or may need minor fixes to filtering logic)

**Step 3: Commit**

```bash
git add internal/llmproxy/sse_intercept_test.go
git commit -m "test(llmproxy): add OpenAI SSE partial block test"
```

---

## Task 7: Edge cases — malformed JSON + text-only stream

**Files:**
- Modify: `internal/llmproxy/sse_intercept_test.go`

**Step 1: Write the tests**

Add to `sse_intercept_test.go`:

```go
func TestSSEInterceptor_MalformedJSON(t *testing.T) {
	// Stream with invalid JSON in a data line
	input := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01"}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {INVALID JSON HERE}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	reg := mcpregistry.NewRegistry()
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "*"})

	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess-1", "req-1", nil, nil)

	var output bytes.Buffer
	interceptor.Stream(strings.NewReader(input), &output)

	result := output.String()

	// Malformed JSON should pass through (fail open)
	if !strings.Contains(result, `{INVALID JSON HERE}`) {
		t.Error("malformed JSON should pass through unchanged")
	}

	// Other events should also pass through
	if !strings.Contains(result, `"type":"message_stop"`) {
		t.Error("valid events should still pass through")
	}
}

func TestSSEInterceptor_TextOnlyStream(t *testing.T) {
	// Stream with no tool calls — should pass through completely
	input := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello world!"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	reg := mcpregistry.NewRegistry()
	policy := newTestPolicy(config.MCPToolRule{Server: "*", Tool: "*"})

	interceptor := NewSSEInterceptor(reg, policy, DialectAnthropic, "sess-1", "req-1", nil, nil)

	var output bytes.Buffer
	interceptor.Stream(strings.NewReader(input), &output)

	result := output.String()

	// Everything should pass through unchanged
	if !strings.Contains(result, "Hello world!") {
		t.Error("text content should pass through")
	}
	if !strings.Contains(result, `"stop_reason":"end_turn"`) {
		t.Error("stop_reason should remain end_turn")
	}
	if strings.Contains(result, "[agentsh]") {
		t.Error("no blocking should occur in text-only stream")
	}
}
```

**Step 2: Run tests**

Run: `go test ./internal/llmproxy/ -run "TestSSEInterceptor_Malformed|TestSSEInterceptor_TextOnly" -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/llmproxy/sse_intercept_test.go
git commit -m "test(llmproxy): add SSE interceptor edge case tests"
```

---

## Task 8: Wire interceptor into streaming.go

Modify `sseProxyTransport` to optionally use the `SSEInterceptor` instead of `io.Copy`.

**Files:**
- Modify: `internal/llmproxy/streaming.go:76-144`

**Step 1: Write the failing test**

Add to `internal/llmproxy/streaming_test.go`:

```go
func TestSSEProxyTransport_WithInterceptor(t *testing.T) {
	// SSE server that returns a stream with a tool_use block
	sseBody := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01AAA","name":"get_weather"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	sseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer sseServer.Close()

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})
	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
		DeniedTools:   []config.MCPToolRule{{Server: "*", Tool: "get_weather"}},
	})

	var callbackBody []byte
	rec := httptest.NewRecorder()
	transport := newSSEProxyTransport(
		http.DefaultTransport,
		rec,
		func(resp *http.Response, body []byte) {
			callbackBody = body
		},
	)
	transport.SetInterceptor(reg, policy, DialectAnthropic, "sess-1", "req-1", nil, nil)

	req, _ := http.NewRequest("POST", sseServer.URL+"/v1/messages", nil)
	_, err := transport.RoundTrip(req)

	if err != errSSEHandled {
		t.Errorf("expected errSSEHandled, got %v", err)
	}

	result := rec.Body.String()

	// Tool should be blocked in the output
	if strings.Contains(result, `"name":"get_weather"`) {
		t.Error("blocked tool should be suppressed in output")
	}
	if !strings.Contains(result, "[agentsh]") {
		t.Error("expected replacement text block")
	}

	// Callback should receive the modified body
	if !bytes.Contains(callbackBody, []byte("[agentsh]")) {
		t.Error("callback body should contain modified output")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/ -run TestSSEProxyTransport_WithInterceptor -v`
Expected: FAIL — `SetInterceptor` not defined

**Step 3: Write implementation**

Modify `internal/llmproxy/streaming.go`. Add interception fields to `sseProxyTransport` and a `SetInterceptor` method:

```go
// Add imports at top:
import (
	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

// Add fields to sseProxyTransport (after onComplete):
type sseProxyTransport struct {
	base       http.RoundTripper
	w          http.ResponseWriter
	onComplete func(resp *http.Response, body []byte)
	// Optional MCP interception fields. When registry and policy are both
	// non-nil, SSE streams are processed through an SSEInterceptor instead
	// of io.Copy, enabling real-time tool call blocking.
	registry  *mcpregistry.Registry
	policy    *mcpinspect.PolicyEvaluator
	dialect   Dialect
	sessionID string
	requestID string
	onEvent   func(mcpinspect.MCPToolCallInterceptedEvent)
	logger    *slog.Logger
}

// SetInterceptor configures MCP interception on the transport.
func (t *sseProxyTransport) SetInterceptor(
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	dialect Dialect,
	sessionID, requestID string,
	onEvent func(mcpinspect.MCPToolCallInterceptedEvent),
	logger *slog.Logger,
) {
	t.registry = registry
	t.policy = policy
	t.dialect = dialect
	t.sessionID = sessionID
	t.requestID = requestID
	t.onEvent = onEvent
	t.logger = logger
}
```

In `RoundTrip`, replace the `io.Copy` block (lines 114-116) with:

```go
		// Stream body to client — with MCP interception if configured
		var bufferedBody []byte
		if t.registry != nil && t.policy != nil {
			interceptor := NewSSEInterceptor(
				t.registry, t.policy, t.dialect,
				t.sessionID, t.requestID, t.onEvent, t.logger,
			)
			bufferedBody = interceptor.Stream(resp.Body, sw)
		} else {
			// Fast path: no MCP policy — direct io.Copy
			_, copyErr = io.Copy(sw, resp.Body)
		}
		resp.Body.Close()

		// Get buffered body for logging
		if bufferedBody == nil {
			bufferedBody = sw.Data()
		}
```

Replace the rest of the `if IsSSEResponse(resp)` block to use `bufferedBody` instead of calling `sw.Data()` again.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/ -run TestSSEProxyTransport_WithInterceptor -v`
Expected: PASS

**Step 5: Run all existing streaming tests to verify no regression**

Run: `go test ./internal/llmproxy/ -run TestSSEProxyTransport -v`
Expected: All PASS (existing tests don't set interceptor, so they use `io.Copy` path)

**Step 6: Commit**

```bash
git add internal/llmproxy/streaming.go internal/llmproxy/streaming_test.go
git commit -m "feat(llmproxy): wire SSEInterceptor into sseProxyTransport"
```

---

## Task 9: Wire into proxy.go ServeHTTP

Pass the registry, policy, dialect, and callback to the SSE transport in `ServeHTTP`. Simplify the `onComplete` callback to remove the now-redundant post-stream MCP interception.

**Files:**
- Modify: `internal/llmproxy/proxy.go:281-313`

**Step 1: Modify ServeHTTP**

In `proxy.go`, in the `ServeHTTP` method, replace the `newSSEProxyTransport` call and its `onComplete` closure (lines 289-313). The key changes:

1. After creating the transport, call `SetInterceptor` if registry and policy are available:

```go
	sseTransport := newSSEProxyTransport(
		http.DefaultTransport,
		w,
		func(resp *http.Response, body []byte) {
			// Log the response. MCP interception is now handled inline
			// by the SSEInterceptor (if configured), so this callback
			// only needs to handle logging.
			p.logResponseDirect(requestID, sessionID, dialect, resp, body, startTime)
		},
	)

	// Configure real-time MCP interception if policy enforcement is enabled.
	if reg := p.getRegistry(); reg != nil && p.policy != nil {
		sseTransport.SetInterceptor(
			reg, p.policy, dialect,
			sessionID, requestID,
			p.getEventCallback(),
			p.logger,
		)
	}
```

2. Remove the old MCP interception code from the `onComplete` closure. The old code that called `ExtractToolCallsFromSSE`, `interceptMCPToolCallsFromList`, and fired callbacks is no longer needed — the interceptor does this inline.

3. Remove the `SECURITY NOTE` comment about audit-only SSE interception — it's no longer audit-only.

**Step 2: Run all proxy tests**

Run: `go test ./internal/llmproxy/ -run TestProxy -v -count=1`
Expected: All PASS

**Step 3: Run all package tests**

Run: `go test ./internal/llmproxy/ -v -count=1`
Expected: All PASS

**Step 4: Commit**

```bash
git add internal/llmproxy/proxy.go
git commit -m "feat(llmproxy): wire SSE interceptor into ServeHTTP, remove audit-only SSE path"
```

---

## Task 10: End-to-end SSE blocking integration test

Add a full proxy integration test that verifies blocked MCP tools are actually suppressed in the SSE response the client receives.

**Files:**
- Modify: `internal/llmproxy/proxy_test.go`

**Step 1: Write the integration test**

Add to `proxy_test.go`:

```go
// TestProxy_SSEBlocking_Integration tests that the proxy blocks MCP tool calls
// in SSE streaming responses in real-time. This replaces the previous audit-only
// behavior where blocked tools were logged but not suppressed.
func TestProxy_SSEBlocking_Integration(t *testing.T) {
	// Anthropic SSE stream with a tool_use block for "get_weather"
	sseChunks := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"stop_reason\":null}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Let me check.\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01AAA\",\"name\":\"get_weather\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"location\\\": \\\"NYC\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":10}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, chunk := range sseChunks {
			w.Write([]byte(chunk))
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "test-sse-blocking",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
		MCP: config.SandboxMCPConfig{
			EnforcePolicy: true,
			ToolPolicy:    "denylist",
			DeniedTools: []config.MCPToolRule{
				{Server: "*", Tool: "get_weather"},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})
	proxy.SetRegistry(reg)

	var mu sync.Mutex
	var collected []mcpinspect.MCPToolCallInterceptedEvent
	done := make(chan struct{}, 1)
	proxy.SetEventCallback(func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		mu.Lock()
		collected = append(collected, ev)
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	time.Sleep(10 * time.Millisecond)

	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	reqBody := `{"model":"claude-sonnet-4-20250514","stream":true,"messages":[{"role":"user","content":"weather?"}]}`
	req, _ := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	result := string(respBody)

	// 1. Text block should pass through
	if !strings.Contains(result, "Let me check.") {
		t.Error("text block should pass through")
	}

	// 2. Blocked tool_use should be REPLACED, not present
	if strings.Contains(result, `"type":"tool_use"`) {
		t.Error("blocked tool_use should be suppressed in SSE output")
	}

	// 3. Replacement text block should be present
	if !strings.Contains(result, `[agentsh] Tool 'get_weather' blocked by policy`) {
		t.Error("expected replacement text block for blocked tool")
	}

	// 4. stop_reason should be end_turn (all tools blocked)
	if !strings.Contains(result, `"end_turn"`) {
		t.Error("stop_reason should be rewritten to end_turn")
	}

	// 5. Event callback should fire
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event callback")
	}

	mu.Lock()
	defer mu.Unlock()

	if len(collected) != 1 {
		t.Fatalf("expected 1 event, got %d", len(collected))
	}
	if collected[0].Action != "block" {
		t.Errorf("event action: got %q, want block", collected[0].Action)
	}
	if collected[0].ToolName != "get_weather" {
		t.Errorf("event tool: got %q, want get_weather", collected[0].ToolName)
	}
}
```

**Step 2: Run the test**

Run: `go test ./internal/llmproxy/ -run TestProxy_SSEBlocking_Integration -v -count=1`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/llmproxy/proxy_test.go
git commit -m "test(llmproxy): add end-to-end SSE blocking integration test"
```

---

## Task 11: Update existing audit-only SSE test

The existing `TestProxy_MCPInterception_SSE_Integration` in `mcp_intercept_test.go` asserts that blocked tools pass through SSE unmodified (audit-only). Now that we have real blocking, this test needs updating.

**Files:**
- Modify: `internal/llmproxy/mcp_intercept_test.go:1574-1710`

**Step 1: Update the test**

Change the test comment and assertions at lines 1574-1577 and 1685-1691:

Old comment (lines 1574-1577):
```go
// TestProxy_MCPInterception_SSE_Integration verifies that the proxy logs
// MCP tool call interception events when processing an SSE streaming response
// containing tool_use blocks. Since SSE responses are streamed directly to the
// client, interception is audit-only (logged but not blocked).
```

New comment:
```go
// TestProxy_MCPInterception_SSE_Integration verifies that the proxy blocks
// MCP tool calls in SSE streaming responses. Blocked tool_use blocks are
// replaced with text blocks containing the blocked message.
```

Old assertions (lines 1685-1691):
```go
	// The SSE stream should have been passed through to the client unmodified.
	if !strings.Contains(string(respBody), "content_block_start") {
		t.Error("expected SSE stream to contain content_block_start events")
	}
	if !strings.Contains(string(respBody), "get_weather") {
		t.Error("expected SSE stream to contain get_weather tool_use (audit-only, not blocked)")
	}
```

New assertions:
```go
	// The blocked tool_use should be replaced with a text block.
	if !strings.Contains(string(respBody), "content_block_start") {
		t.Error("expected SSE stream to contain content_block_start events")
	}
	if strings.Contains(string(respBody), `"type":"tool_use"`) {
		t.Error("blocked tool_use should be suppressed in SSE output")
	}
	if !strings.Contains(string(respBody), `[agentsh] Tool 'get_weather' blocked by policy`) {
		t.Error("expected replacement text block for blocked tool")
	}
```

**Step 2: Run the updated test**

Run: `go test ./internal/llmproxy/ -run TestProxy_MCPInterception_SSE_Integration -v -count=1`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/llmproxy/mcp_intercept_test.go
git commit -m "test(llmproxy): update SSE interception test for real blocking (was audit-only)"
```

---

## Task 12: Full build + test + cross-compile verification

**Files:** None (verification only)

**Step 1: Run all package tests**

Run: `go test ./internal/llmproxy/ -v -count=1 -race`
Expected: All PASS with no data races

**Step 2: Run all project tests**

Run: `go test ./... -count=1`
Expected: All PASS

**Step 3: Build all**

Run: `go build ./...`
Expected: Success

**Step 4: Cross-compile for Windows**

Run: `GOOS=windows go build ./...`
Expected: Success

**Step 5: Commit (if any fixups needed)**

Only if previous steps revealed issues that needed fixing.

---

## Files Summary

| File | Change |
|------|--------|
| `internal/llmproxy/sse_intercept.go` | **New:** `SSEInterceptor` type, `Stream`, Anthropic processor, OpenAI processor, helper methods |
| `internal/llmproxy/sse_intercept_test.go` | **New:** 8 unit tests covering both dialects, partial block, all blocked, allowed, unregistered, edge cases |
| `internal/llmproxy/streaming.go` | **Modify:** Add interceptor fields + `SetInterceptor` to `sseProxyTransport`, conditional interceptor in `RoundTrip` |
| `internal/llmproxy/streaming_test.go` | **Modify:** Add `TestSSEProxyTransport_WithInterceptor` |
| `internal/llmproxy/proxy.go` | **Modify:** Wire interceptor in `ServeHTTP`, simplify SSE `onComplete` to logging-only |
| `internal/llmproxy/proxy_test.go` | **Modify:** Add `TestProxy_SSEBlocking_Integration` |
| `internal/llmproxy/mcp_intercept_test.go` | **Modify:** Update `TestProxy_MCPInterception_SSE_Integration` from audit-only to real blocking assertions |

## Verification

```bash
go test ./internal/llmproxy/ -v -count=1 -race   # All tests with race detector
go test ./... -count=1                             # Full project
go build ./...                                     # Build all
GOOS=windows go build ./...                        # Cross-compile
```
