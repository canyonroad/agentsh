package llmproxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

func TestExtractToolCalls_AnthropicSingleTool(t *testing.T) {
	body := []byte(`{
		"id": "msg_01XFDUDYJgAACzvnptvVoYEL",
		"type": "message",
		"role": "assistant",
		"stop_reason": "tool_use",
		"content": [
			{"type": "text", "text": "I'll check the weather for you."},
			{
				"type": "tool_use",
				"id": "toolu_01A09q90qw90lq917835lq9",
				"name": "get_weather",
				"input": {"location": "San Francisco, CA"}
			}
		]
	}`)

	calls := ExtractToolCalls(body, DialectAnthropic)
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}

	tc := calls[0]
	if tc.ID != "toolu_01A09q90qw90lq917835lq9" {
		t.Errorf("expected ID %q, got %q", "toolu_01A09q90qw90lq917835lq9", tc.ID)
	}
	if tc.Name != "get_weather" {
		t.Errorf("expected Name %q, got %q", "get_weather", tc.Name)
	}

	var input map[string]string
	if err := json.Unmarshal(tc.Input, &input); err != nil {
		t.Fatalf("failed to unmarshal input: %v", err)
	}
	if input["location"] != "San Francisco, CA" {
		t.Errorf("expected location %q, got %q", "San Francisco, CA", input["location"])
	}
}

func TestExtractToolCalls_AnthropicParallelTools(t *testing.T) {
	body := []byte(`{
		"id": "msg_01XFDUDYJgAACzvnptvVoYEL",
		"type": "message",
		"role": "assistant",
		"stop_reason": "tool_use",
		"content": [
			{"type": "text", "text": "I'll check both locations."},
			{
				"type": "tool_use",
				"id": "toolu_01AAA",
				"name": "get_weather",
				"input": {"location": "San Francisco, CA"}
			},
			{
				"type": "tool_use",
				"id": "toolu_01BBB",
				"name": "get_weather",
				"input": {"location": "New York, NY"}
			}
		]
	}`)

	calls := ExtractToolCalls(body, DialectAnthropic)
	if len(calls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d", len(calls))
	}

	if calls[0].ID != "toolu_01AAA" {
		t.Errorf("first call: expected ID %q, got %q", "toolu_01AAA", calls[0].ID)
	}
	if calls[0].Name != "get_weather" {
		t.Errorf("first call: expected Name %q, got %q", "get_weather", calls[0].Name)
	}

	if calls[1].ID != "toolu_01BBB" {
		t.Errorf("second call: expected ID %q, got %q", "toolu_01BBB", calls[1].ID)
	}
	if calls[1].Name != "get_weather" {
		t.Errorf("second call: expected Name %q, got %q", "get_weather", calls[1].Name)
	}

	// Verify the inputs are different
	var input0, input1 map[string]string
	if err := json.Unmarshal(calls[0].Input, &input0); err != nil {
		t.Fatalf("failed to unmarshal first input: %v", err)
	}
	if err := json.Unmarshal(calls[1].Input, &input1); err != nil {
		t.Fatalf("failed to unmarshal second input: %v", err)
	}
	if input0["location"] != "San Francisco, CA" {
		t.Errorf("first call: expected location %q, got %q", "San Francisco, CA", input0["location"])
	}
	if input1["location"] != "New York, NY" {
		t.Errorf("second call: expected location %q, got %q", "New York, NY", input1["location"])
	}
}

func TestExtractToolCalls_OpenAISingleTool(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-abc123",
		"object": "chat.completion",
		"choices": [{
			"index": 0,
			"finish_reason": "tool_calls",
			"message": {
				"role": "assistant",
				"content": null,
				"tool_calls": [{
					"id": "call_KlZ3abc123",
					"type": "function",
					"function": {
						"name": "get_weather",
						"arguments": "{\"location\": \"San Francisco, CA\"}"
					}
				}]
			}
		}]
	}`)

	calls := ExtractToolCalls(body, DialectOpenAI)
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}

	tc := calls[0]
	if tc.ID != "call_KlZ3abc123" {
		t.Errorf("expected ID %q, got %q", "call_KlZ3abc123", tc.ID)
	}
	if tc.Name != "get_weather" {
		t.Errorf("expected Name %q, got %q", "get_weather", tc.Name)
	}

	var input map[string]string
	if err := json.Unmarshal(tc.Input, &input); err != nil {
		t.Fatalf("failed to unmarshal input: %v", err)
	}
	if input["location"] != "San Francisco, CA" {
		t.Errorf("expected location %q, got %q", "San Francisco, CA", input["location"])
	}
}

func TestExtractToolCalls_OpenAIParallelTools(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-abc123",
		"object": "chat.completion",
		"choices": [{
			"index": 0,
			"finish_reason": "tool_calls",
			"message": {
				"role": "assistant",
				"content": null,
				"tool_calls": [
					{
						"id": "call_AAA",
						"type": "function",
						"function": {
							"name": "get_weather",
							"arguments": "{\"location\": \"San Francisco, CA\"}"
						}
					},
					{
						"id": "call_BBB",
						"type": "function",
						"function": {
							"name": "get_time",
							"arguments": "{\"timezone\": \"America/Los_Angeles\"}"
						}
					}
				]
			}
		}]
	}`)

	calls := ExtractToolCalls(body, DialectOpenAI)
	if len(calls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d", len(calls))
	}

	if calls[0].ID != "call_AAA" {
		t.Errorf("first call: expected ID %q, got %q", "call_AAA", calls[0].ID)
	}
	if calls[0].Name != "get_weather" {
		t.Errorf("first call: expected Name %q, got %q", "get_weather", calls[0].Name)
	}

	if calls[1].ID != "call_BBB" {
		t.Errorf("second call: expected ID %q, got %q", "call_BBB", calls[1].ID)
	}
	if calls[1].Name != "get_time" {
		t.Errorf("second call: expected Name %q, got %q", "get_time", calls[1].Name)
	}
}

func TestExtractToolCalls_NonToolResponseReturnsNil(t *testing.T) {
	tests := []struct {
		name    string
		dialect Dialect
		body    string
	}{
		{
			name:    "Anthropic text-only response",
			dialect: DialectAnthropic,
			body: `{
				"id": "msg_01XFDUDYJgAACzvnptvVoYEL",
				"type": "message",
				"role": "assistant",
				"stop_reason": "end_turn",
				"content": [
					{"type": "text", "text": "Hello! How can I help you today?"}
				]
			}`,
		},
		{
			name:    "OpenAI text-only response",
			dialect: DialectOpenAI,
			body: `{
				"id": "chatcmpl-abc123",
				"object": "chat.completion",
				"choices": [{
					"index": 0,
					"finish_reason": "stop",
					"message": {
						"role": "assistant",
						"content": "Hello! How can I help you today?"
					}
				}]
			}`,
		},
		{
			name:    "Anthropic stop_reason is not tool_use",
			dialect: DialectAnthropic,
			body: `{
				"stop_reason": "max_tokens",
				"content": [
					{"type": "text", "text": "I was saying..."}
				]
			}`,
		},
		{
			name:    "OpenAI finish_reason is not tool_calls",
			dialect: DialectOpenAI,
			body: `{
				"choices": [{
					"finish_reason": "stop",
					"message": {
						"role": "assistant",
						"content": "The weather is nice."
					}
				}]
			}`,
		},
		{
			name:    "Unknown dialect",
			dialect: DialectUnknown,
			body:    `{"some": "data"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := ExtractToolCalls([]byte(tt.body), tt.dialect)
			if calls != nil {
				t.Errorf("expected nil, got %v", calls)
			}
		})
	}
}

func TestExtractToolCalls_MalformedJSONReturnsNil(t *testing.T) {
	tests := []struct {
		name    string
		dialect Dialect
		body    string
	}{
		{
			name:    "Anthropic malformed JSON",
			dialect: DialectAnthropic,
			body:    `{not valid json`,
		},
		{
			name:    "OpenAI malformed JSON",
			dialect: DialectOpenAI,
			body:    `{not valid json`,
		},
		{
			name:    "Anthropic empty body",
			dialect: DialectAnthropic,
			body:    ``,
		},
		{
			name:    "OpenAI empty body",
			dialect: DialectOpenAI,
			body:    ``,
		},
		{
			name:    "Anthropic null body",
			dialect: DialectAnthropic,
			body:    `null`,
		},
		{
			name:    "OpenAI null body",
			dialect: DialectOpenAI,
			body:    `null`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := ExtractToolCalls([]byte(tt.body), tt.dialect)
			if calls != nil {
				t.Errorf("expected nil, got %v", calls)
			}
		})
	}
}

func TestExtractToolCalls_OpenAIArgumentsConversion(t *testing.T) {
	// OpenAI sends arguments as a JSON string. Verify it is correctly
	// stored as json.RawMessage and can be parsed back.
	body := []byte(`{
		"choices": [{
			"finish_reason": "tool_calls",
			"message": {
				"tool_calls": [{
					"id": "call_test123",
					"type": "function",
					"function": {
						"name": "create_file",
						"arguments": "{\"path\": \"/tmp/test.txt\", \"content\": \"hello world\", \"overwrite\": true}"
					}
				}]
			}
		}]
	}`)

	calls := ExtractToolCalls(body, DialectOpenAI)
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}

	tc := calls[0]

	// Verify Input is valid JSON
	if !json.Valid(tc.Input) {
		t.Fatalf("Input is not valid JSON: %s", string(tc.Input))
	}

	// Parse the arguments and verify all fields
	var args struct {
		Path      string `json:"path"`
		Content   string `json:"content"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := json.Unmarshal(tc.Input, &args); err != nil {
		t.Fatalf("failed to unmarshal arguments: %v", err)
	}

	if args.Path != "/tmp/test.txt" {
		t.Errorf("expected path %q, got %q", "/tmp/test.txt", args.Path)
	}
	if args.Content != "hello world" {
		t.Errorf("expected content %q, got %q", "hello world", args.Content)
	}
	if !args.Overwrite {
		t.Error("expected overwrite to be true")
	}
}

func TestExtractToolCalls_AnthropicMixedContentBlocks(t *testing.T) {
	// Verify that non-tool_use content blocks are skipped
	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "text", "text": "Let me help with that."},
			{
				"type": "tool_use",
				"id": "toolu_01CCC",
				"name": "read_file",
				"input": {"path": "/etc/hosts"}
			},
			{"type": "text", "text": "And also..."},
			{
				"type": "tool_use",
				"id": "toolu_01DDD",
				"name": "write_file",
				"input": {"path": "/tmp/out.txt", "content": "data"}
			}
		]
	}`)

	calls := ExtractToolCalls(body, DialectAnthropic)
	if len(calls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d", len(calls))
	}

	if calls[0].Name != "read_file" {
		t.Errorf("first call: expected Name %q, got %q", "read_file", calls[0].Name)
	}
	if calls[1].Name != "write_file" {
		t.Errorf("second call: expected Name %q, got %q", "write_file", calls[1].Name)
	}
}

func TestExtractToolCalls_OpenAIEmptyToolCallsArray(t *testing.T) {
	// finish_reason is tool_calls but tool_calls array is empty
	body := []byte(`{
		"choices": [{
			"finish_reason": "tool_calls",
			"message": {
				"tool_calls": []
			}
		}]
	}`)

	calls := ExtractToolCalls(body, DialectOpenAI)
	if calls != nil {
		t.Errorf("expected nil for empty tool_calls array, got %v", calls)
	}
}

func TestExtractToolCalls_AnthropicEmptyContentArray(t *testing.T) {
	// stop_reason is tool_use but content array has no tool_use blocks
	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "text", "text": "Just some text."}
		]
	}`)

	calls := ExtractToolCalls(body, DialectAnthropic)
	if calls != nil {
		t.Errorf("expected nil when no tool_use blocks found, got %v", calls)
	}
}

func TestExtractToolCalls_OpenAIMultipleChoices(t *testing.T) {
	// Only the choice with finish_reason "tool_calls" should yield tool calls.
	body := []byte(`{
		"choices": [
			{
				"index": 0,
				"finish_reason": "stop",
				"message": {
					"role": "assistant",
					"content": "Hello"
				}
			},
			{
				"index": 1,
				"finish_reason": "tool_calls",
				"message": {
					"tool_calls": [{
						"id": "call_from_choice_1",
						"type": "function",
						"function": {
							"name": "search",
							"arguments": "{\"query\": \"test\"}"
						}
					}]
				}
			}
		]
	}`)

	calls := ExtractToolCalls(body, DialectOpenAI)
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}
	if calls[0].ID != "call_from_choice_1" {
		t.Errorf("expected ID %q, got %q", "call_from_choice_1", calls[0].ID)
	}
}

func TestExtractToolCalls_OpenAIInvalidArgumentsSkipped(t *testing.T) {
	// OpenAI arguments must be valid JSON. Invalid arguments should be skipped.
	body := []byte(`{
		"choices": [{
			"finish_reason": "tool_calls",
			"message": {
				"tool_calls": [
					{
						"id": "call_valid",
						"type": "function",
						"function": {
							"name": "good_tool",
							"arguments": "{\"key\": \"value\"}"
						}
					},
					{
						"id": "call_invalid",
						"type": "function",
						"function": {
							"name": "bad_tool",
							"arguments": "not valid json {{"
						}
					},
					{
						"id": "call_empty",
						"type": "function",
						"function": {
							"name": "empty_tool",
							"arguments": ""
						}
					}
				]
			}
		}]
	}`)

	calls := ExtractToolCalls(body, DialectOpenAI)
	if len(calls) != 1 {
		t.Fatalf("expected 1 valid tool call (invalid ones skipped), got %d", len(calls))
	}
	if calls[0].Name != "good_tool" {
		t.Errorf("expected Name %q, got %q", "good_tool", calls[0].Name)
	}
}

func TestExtractToolCalls_AnthropicComplexInput(t *testing.T) {
	// Verify nested JSON objects in input are preserved
	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [{
			"type": "tool_use",
			"id": "toolu_complex",
			"name": "api_call",
			"input": {
				"method": "POST",
				"url": "https://api.example.com/data",
				"headers": {"Content-Type": "application/json"},
				"body": {"key": "value", "nested": {"deep": true}}
			}
		}]
	}`)

	calls := ExtractToolCalls(body, DialectAnthropic)
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}

	// Verify the complex input is preserved as valid JSON
	if !json.Valid(calls[0].Input) {
		t.Fatalf("Input is not valid JSON: %s", string(calls[0].Input))
	}

	var input map[string]any
	if err := json.Unmarshal(calls[0].Input, &input); err != nil {
		t.Fatalf("failed to unmarshal complex input: %v", err)
	}

	if input["method"] != "POST" {
		t.Errorf("expected method %q, got %v", "POST", input["method"])
	}

	headers, ok := input["headers"].(map[string]any)
	if !ok {
		t.Fatal("expected headers to be a map")
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type header, got %v", headers["Content-Type"])
	}
}

// --- interceptMCPToolCalls tests ---

// newTestRegistry creates a registry with the given tools registered under serverID.
func newTestRegistry(serverID, serverType string, tools []mcpregistry.ToolInfo) *mcpregistry.Registry {
	reg := mcpregistry.NewRegistry()
	reg.Register(serverID, serverType, "", tools)
	return reg
}

// newBlockingPolicy creates a policy that blocks the specified tool via allowlist
// (the tool won't match the allowlist, so it will be blocked).
func newBlockingPolicy() *mcpinspect.PolicyEvaluator {
	return mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "allowlist",
		AllowedTools:  []config.MCPToolRule{}, // empty allowlist = block everything
	})
}

// newAllowingPolicy creates a policy that allows everything.
func newAllowingPolicy() *mcpinspect.PolicyEvaluator {
	return mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "allowlist",
		AllowedTools: []config.MCPToolRule{
			{Server: "*", Tool: "*"},
		},
	})
}

func TestInterceptMCPToolCalls_NilRegistryReturnsEmpty(t *testing.T) {
	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "NYC"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, nil, newAllowingPolicy(), "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
	if result.HasBlocked {
		t.Error("expected HasBlocked to be false")
	}
	if result.RewrittenBody != nil {
		t.Error("expected RewrittenBody to be nil")
	}
}

func TestInterceptMCPToolCalls_NilPolicyReturnsEmpty(t *testing.T) {
	reg := newTestRegistry("my-server", "stdio", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "NYC"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, reg, nil, "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
	if result.HasBlocked {
		t.Error("expected HasBlocked to be false")
	}
	if result.RewrittenBody != nil {
		t.Error("expected RewrittenBody to be nil")
	}
}

func TestInterceptMCPToolCalls_UnknownToolSkipped(t *testing.T) {
	// Registry has no tools registered, so get_weather is unknown.
	reg := mcpregistry.NewRegistry()
	policy := newAllowingPolicy()

	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "NYC"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, reg, policy, "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// Unknown tools (not in registry) should not emit events.
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for unknown tool, got %d", len(result.Events))
	}
	if result.HasBlocked {
		t.Error("expected HasBlocked to be false")
	}
	if result.RewrittenBody != nil {
		t.Error("expected RewrittenBody to be nil")
	}
}

func TestInterceptMCPToolCalls_AllowedToolPassesThrough(t *testing.T) {
	reg := newTestRegistry("my-server", "stdio", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})
	policy := newAllowingPolicy()

	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "text", "text": "Let me check the weather."},
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "NYC"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, reg, policy, "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}

	evt := result.Events[0]
	if evt.Type != "mcp_tool_call_intercepted" {
		t.Errorf("expected event type %q, got %q", "mcp_tool_call_intercepted", evt.Type)
	}
	if evt.Action != "allow" {
		t.Errorf("expected action %q, got %q", "allow", evt.Action)
	}
	if evt.ToolName != "get_weather" {
		t.Errorf("expected tool name %q, got %q", "get_weather", evt.ToolName)
	}
	if evt.ToolCallID != "toolu_01" {
		t.Errorf("expected tool call ID %q, got %q", "toolu_01", evt.ToolCallID)
	}
	if evt.ServerID != "my-server" {
		t.Errorf("expected server ID %q, got %q", "my-server", evt.ServerID)
	}
	if evt.SessionID != "sess_1" {
		t.Errorf("expected session ID %q, got %q", "sess_1", evt.SessionID)
	}
	if evt.RequestID != "req_1" {
		t.Errorf("expected request ID %q, got %q", "req_1", evt.RequestID)
	}
	if evt.Dialect != "anthropic" {
		t.Errorf("expected dialect %q, got %q", "anthropic", evt.Dialect)
	}

	if result.HasBlocked {
		t.Error("expected HasBlocked to be false")
	}
	if result.RewrittenBody != nil {
		t.Error("expected RewrittenBody to be nil for allowed tool")
	}
}

func TestInterceptMCPToolCalls_BlockedToolRewritten(t *testing.T) {
	reg := newTestRegistry("my-server", "stdio", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})
	policy := newBlockingPolicy()

	body := []byte(`{
		"id": "msg_01XFDUDYJgAACzvnptvVoYEL",
		"type": "message",
		"role": "assistant",
		"stop_reason": "tool_use",
		"content": [
			{"type": "text", "text": "Let me check the weather."},
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "NYC"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, reg, policy, "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Should have 1 event with action=block
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	evt := result.Events[0]
	if evt.Action != "block" {
		t.Errorf("expected action %q, got %q", "block", evt.Action)
	}
	if evt.ToolName != "get_weather" {
		t.Errorf("expected tool name %q, got %q", "get_weather", evt.ToolName)
	}

	if !result.HasBlocked {
		t.Error("expected HasBlocked to be true")
	}
	if result.RewrittenBody == nil {
		t.Fatal("expected RewrittenBody to be non-nil")
	}

	// Parse the rewritten body and verify:
	// 1. tool_use block replaced with text block
	// 2. stop_reason changed to "end_turn" (all tool_use blocks blocked)
	var rewritten map[string]json.RawMessage
	if err := json.Unmarshal(result.RewrittenBody, &rewritten); err != nil {
		t.Fatalf("failed to unmarshal rewritten body: %v", err)
	}

	// Check stop_reason
	var stopReason string
	if err := json.Unmarshal(rewritten["stop_reason"], &stopReason); err != nil {
		t.Fatalf("failed to unmarshal stop_reason: %v", err)
	}
	if stopReason != "end_turn" {
		t.Errorf("expected stop_reason %q, got %q", "end_turn", stopReason)
	}

	// Check content blocks
	var content []map[string]json.RawMessage
	if err := json.Unmarshal(rewritten["content"], &content); err != nil {
		t.Fatalf("failed to unmarshal content: %v", err)
	}

	// Should have 2 blocks (original text + replacement text for blocked tool)
	if len(content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(content))
	}

	// First block should be original text
	var firstType string
	json.Unmarshal(content[0]["type"], &firstType)
	if firstType != "text" {
		t.Errorf("expected first block type %q, got %q", "text", firstType)
	}

	// Second block should be replacement text (not tool_use)
	var secondType string
	json.Unmarshal(content[1]["type"], &secondType)
	if secondType != "text" {
		t.Errorf("expected second block type %q, got %q (should be text, not tool_use)", "text", secondType)
	}

	var secondText string
	json.Unmarshal(content[1]["text"], &secondText)
	if !strings.Contains(secondText, "get_weather") {
		t.Errorf("expected replacement text to mention tool name, got %q", secondText)
	}
	if !strings.Contains(secondText, "blocked") {
		t.Errorf("expected replacement text to mention 'blocked', got %q", secondText)
	}
}

func TestInterceptMCPToolCalls_FailClosedBlocksViaAllowlist(t *testing.T) {
	// Tool IS in the registry but the allowlist has a specific hash that won't match.
	// With fail_closed=true and an allowlist, tools not matching get blocked.
	reg := newTestRegistry("my-server", "stdio", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		FailClosed:    true,
		ToolPolicy:    "allowlist",
		AllowedTools: []config.MCPToolRule{
			// Only allow a different tool on the same server
			{Server: "my-server", Tool: "some_other_tool"},
		},
	})

	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "NYC"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, reg, policy, "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	if result.Events[0].Action != "block" {
		t.Errorf("expected action %q, got %q", "block", result.Events[0].Action)
	}
	if !result.HasBlocked {
		t.Error("expected HasBlocked to be true")
	}
	if result.RewrittenBody == nil {
		t.Error("expected RewrittenBody to be non-nil")
	}
}

func TestInterceptMCPToolCalls_PartialBlockAnthropic(t *testing.T) {
	// Two tool calls: one allowed, one blocked.
	// stop_reason should remain "tool_use" because some tool_use blocks remain.
	reg := newTestRegistry("my-server", "stdio", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
		{Name: "read_file", Hash: "def456"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "allowlist",
		AllowedTools: []config.MCPToolRule{
			{Server: "my-server", Tool: "get_weather"}, // allow get_weather
			// read_file not allowed -> blocked
		},
	})

	body := []byte(`{
		"id": "msg_123",
		"type": "message",
		"role": "assistant",
		"stop_reason": "tool_use",
		"content": [
			{"type": "text", "text": "Let me do both."},
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "NYC"}},
			{"type": "tool_use", "id": "toolu_02", "name": "read_file", "input": {"path": "/etc/passwd"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, reg, policy, "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Should have 2 events
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(result.Events))
	}

	// Verify actions
	var allowCount, blockCount int
	for _, evt := range result.Events {
		switch evt.Action {
		case "allow":
			allowCount++
		case "block":
			blockCount++
		}
	}
	if allowCount != 1 || blockCount != 1 {
		t.Errorf("expected 1 allow and 1 block, got %d allow and %d block", allowCount, blockCount)
	}

	if !result.HasBlocked {
		t.Error("expected HasBlocked to be true")
	}
	if result.RewrittenBody == nil {
		t.Fatal("expected RewrittenBody to be non-nil")
	}

	// Parse rewritten body
	var rewritten map[string]json.RawMessage
	if err := json.Unmarshal(result.RewrittenBody, &rewritten); err != nil {
		t.Fatalf("failed to unmarshal rewritten body: %v", err)
	}

	// stop_reason should remain "tool_use" because get_weather is still allowed
	var stopReason string
	if err := json.Unmarshal(rewritten["stop_reason"], &stopReason); err != nil {
		t.Fatalf("failed to unmarshal stop_reason: %v", err)
	}
	if stopReason != "tool_use" {
		t.Errorf("expected stop_reason %q for partial block, got %q", "tool_use", stopReason)
	}

	// Content should have 3 blocks: text, tool_use (allowed), text (blocked replacement)
	var content []map[string]json.RawMessage
	if err := json.Unmarshal(rewritten["content"], &content); err != nil {
		t.Fatalf("failed to unmarshal content: %v", err)
	}
	if len(content) != 3 {
		t.Fatalf("expected 3 content blocks, got %d", len(content))
	}

	// The first remaining tool_use should be get_weather
	var secondType string
	json.Unmarshal(content[1]["type"], &secondType)
	if secondType != "tool_use" {
		t.Errorf("expected second block to be tool_use, got %q", secondType)
	}
	var secondName string
	json.Unmarshal(content[1]["name"], &secondName)
	if secondName != "get_weather" {
		t.Errorf("expected second block name %q, got %q", "get_weather", secondName)
	}

	// Third block should be text replacement for blocked read_file
	var thirdType string
	json.Unmarshal(content[2]["type"], &thirdType)
	if thirdType != "text" {
		t.Errorf("expected third block to be text (blocked replacement), got %q", thirdType)
	}
}

func TestInterceptMCPToolCalls_OpenAIBlockedToolRewritten(t *testing.T) {
	reg := newTestRegistry("my-server", "stdio", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})
	policy := newBlockingPolicy()

	body := []byte(`{
		"id": "chatcmpl-abc123",
		"object": "chat.completion",
		"choices": [{
			"index": 0,
			"finish_reason": "tool_calls",
			"message": {
				"role": "assistant",
				"content": null,
				"tool_calls": [{
					"id": "call_KlZ3abc123",
					"type": "function",
					"function": {
						"name": "get_weather",
						"arguments": "{\"location\": \"San Francisco, CA\"}"
					}
				}]
			}
		}]
	}`)

	result := interceptMCPToolCalls(body, DialectOpenAI, reg, policy, "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	if result.Events[0].Action != "block" {
		t.Errorf("expected action %q, got %q", "block", result.Events[0].Action)
	}
	if !result.HasBlocked {
		t.Error("expected HasBlocked to be true")
	}
	if result.RewrittenBody == nil {
		t.Fatal("expected RewrittenBody to be non-nil")
	}

	// Parse rewritten body
	var rewritten struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   string          `json:"content"`
				ToolCalls json.RawMessage `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(result.RewrittenBody, &rewritten); err != nil {
		t.Fatalf("failed to unmarshal rewritten body: %v", err)
	}

	if len(rewritten.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(rewritten.Choices))
	}

	choice := rewritten.Choices[0]
	// All tool calls blocked -> finish_reason should be "stop"
	if choice.FinishReason != "stop" {
		t.Errorf("expected finish_reason %q, got %q", "stop", choice.FinishReason)
	}
	// Content should mention the blocked tool
	if !strings.Contains(choice.Message.Content, "get_weather") {
		t.Errorf("expected content to mention blocked tool, got %q", choice.Message.Content)
	}
	if !strings.Contains(choice.Message.Content, "blocked") {
		t.Errorf("expected content to mention 'blocked', got %q", choice.Message.Content)
	}
	// tool_calls should be empty or null
	if choice.Message.ToolCalls != nil && string(choice.Message.ToolCalls) != "[]" && string(choice.Message.ToolCalls) != "null" {
		t.Errorf("expected tool_calls to be empty/null, got %s", string(choice.Message.ToolCalls))
	}
}

func TestInterceptMCPToolCalls_OpenAIPartialBlock(t *testing.T) {
	reg := newTestRegistry("my-server", "stdio", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
		{Name: "read_file", Hash: "def456"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "allowlist",
		AllowedTools: []config.MCPToolRule{
			{Server: "my-server", Tool: "get_weather"}, // allow get_weather only
		},
	})

	body := []byte(`{
		"id": "chatcmpl-abc123",
		"object": "chat.completion",
		"choices": [{
			"index": 0,
			"finish_reason": "tool_calls",
			"message": {
				"role": "assistant",
				"content": null,
				"tool_calls": [
					{
						"id": "call_AAA",
						"type": "function",
						"function": {
							"name": "get_weather",
							"arguments": "{\"location\": \"NYC\"}"
						}
					},
					{
						"id": "call_BBB",
						"type": "function",
						"function": {
							"name": "read_file",
							"arguments": "{\"path\": \"/etc/passwd\"}"
						}
					}
				]
			}
		}]
	}`)

	result := interceptMCPToolCalls(body, DialectOpenAI, reg, policy, "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(result.Events))
	}

	if !result.HasBlocked {
		t.Error("expected HasBlocked to be true")
	}
	if result.RewrittenBody == nil {
		t.Fatal("expected RewrittenBody to be non-nil")
	}

	// Parse rewritten body
	var rewritten struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   *string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name string `json:"name"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(result.RewrittenBody, &rewritten); err != nil {
		t.Fatalf("failed to unmarshal rewritten body: %v", err)
	}

	choice := rewritten.Choices[0]
	// Partial block -> finish_reason should remain "tool_calls"
	if choice.FinishReason != "tool_calls" {
		t.Errorf("expected finish_reason %q for partial block, got %q", "tool_calls", choice.FinishReason)
	}

	// Only the allowed tool call should remain
	if len(choice.Message.ToolCalls) != 1 {
		t.Fatalf("expected 1 remaining tool call, got %d", len(choice.Message.ToolCalls))
	}
	if choice.Message.ToolCalls[0].Function.Name != "get_weather" {
		t.Errorf("expected remaining tool to be %q, got %q", "get_weather", choice.Message.ToolCalls[0].Function.Name)
	}
}

func TestInterceptMCPToolCalls_MixedMCPAndNonMCP(t *testing.T) {
	// One tool is in the registry (MCP), one is not (non-MCP).
	// Only the MCP tool should generate an event.
	reg := newTestRegistry("my-server", "stdio", []mcpregistry.ToolInfo{
		{Name: "mcp_tool", Hash: "abc123"},
		// "native_tool" is NOT registered
	})
	policy := newAllowingPolicy()

	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "mcp_tool", "input": {"key": "value"}},
			{"type": "tool_use", "id": "toolu_02", "name": "native_tool", "input": {"key": "value"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, reg, policy, "req_1", "sess_1")
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Only 1 event (for the MCP tool), native_tool is skipped
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	if result.Events[0].ToolName != "mcp_tool" {
		t.Errorf("expected event for %q, got %q", "mcp_tool", result.Events[0].ToolName)
	}
	if result.HasBlocked {
		t.Error("expected no blocking")
	}
}
