package llmproxy

import (
	"encoding/json"
	"testing"
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
