package llmproxy

import (
	"testing"
)

func TestExtractToolCallsFromSSE_Anthropic(t *testing.T) {
	// Full Anthropic SSE stream with text + tool_use content blocks.
	sseBody := []byte("event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me check the weather."}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01A09q90qw90lq917835lq9","name":"get_weather"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"San"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":" Francisco\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":1}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n")

	calls := ExtractToolCallsFromSSE(sseBody, DialectAnthropic)
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
	if tc.Input != nil {
		t.Errorf("expected Input to be nil, got %s", string(tc.Input))
	}
}

func TestExtractToolCallsFromSSE_OpenAI(t *testing.T) {
	// Full OpenAI SSE stream with tool call deltas.
	sseBody := []byte("data: " + `{"id":"chatcmpl-abc123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_abc123","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"chatcmpl-abc123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"lo"}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"chatcmpl-abc123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"cation\": \"NYC\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"chatcmpl-abc123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n")

	calls := ExtractToolCallsFromSSE(sseBody, DialectOpenAI)
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}

	tc := calls[0]
	if tc.ID != "call_abc123" {
		t.Errorf("expected ID %q, got %q", "call_abc123", tc.ID)
	}
	if tc.Name != "get_weather" {
		t.Errorf("expected Name %q, got %q", "get_weather", tc.Name)
	}
	if tc.Input != nil {
		t.Errorf("expected Input to be nil, got %s", string(tc.Input))
	}
}

func TestExtractToolCallsFromSSE_NoToolCalls(t *testing.T) {
	// Anthropic SSE stream with only text content.
	sseBody := []byte("event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello! How can I help you today?"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n")

	calls := ExtractToolCallsFromSSE(sseBody, DialectAnthropic)
	if len(calls) != 0 {
		t.Fatalf("expected 0 tool calls, got %d", len(calls))
	}
}

func TestExtractToolCallsFromSSE_MultipleTools(t *testing.T) {
	// Anthropic SSE stream with 2 tool_use content blocks.
	sseBody := []byte("event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I'll check both."}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01AAA","name":"get_weather"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"NYC\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":1}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_01BBB","name":"get_time"}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"timezone\": \"America/New_York\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":2}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n")

	calls := ExtractToolCallsFromSSE(sseBody, DialectAnthropic)
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
	if calls[1].Name != "get_time" {
		t.Errorf("second call: expected Name %q, got %q", "get_time", calls[1].Name)
	}
}

func TestExtractToolCallsFromSSE_OpenAIMultipleTools(t *testing.T) {
	// OpenAI SSE stream with 2 parallel tool calls.
	// The first chunk for each tool call contains both id and function.name.
	sseBody := []byte("data: " + `{"id":"chatcmpl-abc123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_AAA","type":"function","function":{"name":"get_weather","arguments":""}},{"index":1,"id":"call_BBB","type":"function","function":{"name":"get_time","arguments":""}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"chatcmpl-abc123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"location\": \"NYC\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"chatcmpl-abc123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"timezone\": \"EST\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"chatcmpl-abc123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n")

	calls := ExtractToolCallsFromSSE(sseBody, DialectOpenAI)
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
