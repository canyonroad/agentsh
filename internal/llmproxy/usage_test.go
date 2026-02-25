// internal/llmproxy/usage_test.go
package llmproxy

import (
	"testing"
)

func TestExtractUsage_Anthropic(t *testing.T) {
	// Anthropic format: {"usage": {"input_tokens": 150, "output_tokens": 892}}
	body := []byte(`{
		"id": "msg_123",
		"type": "message",
		"role": "assistant",
		"content": [{"type": "text", "text": "Hello!"}],
		"usage": {"input_tokens": 150, "output_tokens": 892}
	}`)

	usage := ExtractUsage(body, DialectAnthropic)

	if usage.InputTokens != 150 {
		t.Errorf("expected InputTokens=150, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 892 {
		t.Errorf("expected OutputTokens=892, got %d", usage.OutputTokens)
	}
}

func TestExtractUsage_OpenAI(t *testing.T) {
	// OpenAI format: {"usage": {"prompt_tokens": 150, "completion_tokens": 892, "total_tokens": 1042}}
	body := []byte(`{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"choices": [{"message": {"role": "assistant", "content": "Hello!"}}],
		"usage": {"prompt_tokens": 150, "completion_tokens": 892, "total_tokens": 1042}
	}`)

	usage := ExtractUsage(body, DialectOpenAI)

	if usage.InputTokens != 150 {
		t.Errorf("expected InputTokens=150, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 892 {
		t.Errorf("expected OutputTokens=892, got %d", usage.OutputTokens)
	}
}

func TestExtractUsage_ChatGPT(t *testing.T) {
	// ChatGPT uses same format as OpenAI (and same dialect now)
	body := []byte(`{
		"id": "chatcmpl-123",
		"usage": {"prompt_tokens": 200, "completion_tokens": 500, "total_tokens": 700}
	}`)

	usage := ExtractUsage(body, DialectOpenAI)

	if usage.InputTokens != 200 {
		t.Errorf("expected InputTokens=200, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 500 {
		t.Errorf("expected OutputTokens=500, got %d", usage.OutputTokens)
	}
}

func TestExtractUsage_NoUsage(t *testing.T) {
	// Response without usage field
	body := []byte(`{
		"id": "msg_123",
		"type": "message",
		"content": [{"type": "text", "text": "Hello!"}]
	}`)

	usage := ExtractUsage(body, DialectAnthropic)

	if usage.InputTokens != 0 {
		t.Errorf("expected InputTokens=0, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 0 {
		t.Errorf("expected OutputTokens=0, got %d", usage.OutputTokens)
	}
}

func TestExtractUsage_InvalidJSON(t *testing.T) {
	// Invalid JSON should return zero usage
	body := []byte(`{not valid json`)

	usage := ExtractUsage(body, DialectAnthropic)

	if usage.InputTokens != 0 {
		t.Errorf("expected InputTokens=0, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 0 {
		t.Errorf("expected OutputTokens=0, got %d", usage.OutputTokens)
	}
}

func TestExtractUsage_EmptyBody(t *testing.T) {
	// Empty body should return zero usage
	usage := ExtractUsage([]byte{}, DialectOpenAI)

	if usage.InputTokens != 0 {
		t.Errorf("expected InputTokens=0, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 0 {
		t.Errorf("expected OutputTokens=0, got %d", usage.OutputTokens)
	}
}

func TestExtractUsage_NilBody(t *testing.T) {
	// Nil body should return zero usage
	usage := ExtractUsage(nil, DialectOpenAI)

	if usage.InputTokens != 0 {
		t.Errorf("expected InputTokens=0, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 0 {
		t.Errorf("expected OutputTokens=0, got %d", usage.OutputTokens)
	}
}

func TestExtractUsage_UnknownDialect(t *testing.T) {
	// Unknown dialect should return zero usage
	body := []byte(`{"usage": {"input_tokens": 100, "output_tokens": 200}}`)

	usage := ExtractUsage(body, DialectUnknown)

	if usage.InputTokens != 0 {
		t.Errorf("expected InputTokens=0, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 0 {
		t.Errorf("expected OutputTokens=0, got %d", usage.OutputTokens)
	}
}

func TestExtractSSEUsage_Anthropic(t *testing.T) {
	body := []byte(
		"event: message_start\n" +
			`data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":null,"usage":{"input_tokens":150,"output_tokens":0}}}` + "\n\n" +
			"event: content_block_delta\n" +
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n" +
			"event: message_delta\n" +
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}` + "\n\n" +
			"event: message_stop\n" +
			`data: {"type":"message_stop"}` + "\n\n",
	)

	usage := ExtractSSEUsage(body, DialectAnthropic)
	if usage.InputTokens != 150 {
		t.Errorf("InputTokens = %d, want 150", usage.InputTokens)
	}
	if usage.OutputTokens != 42 {
		t.Errorf("OutputTokens = %d, want 42", usage.OutputTokens)
	}
}

func TestExtractSSEUsage_AnthropicEmpty(t *testing.T) {
	usage := ExtractSSEUsage(nil, DialectAnthropic)
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		t.Errorf("expected zero usage for nil body, got %+v", usage)
	}
}

func TestExtractSSEUsage_OpenAI(t *testing.T) {
	body := []byte(
		`data: {"id":"chatcmpl-1","choices":[{"delta":{"content":"Hi"}}]}` + "\n\n" +
			`data: {"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":100,"completion_tokens":25}}` + "\n\n" +
			"data: [DONE]\n\n",
	)

	usage := ExtractSSEUsage(body, DialectOpenAI)
	if usage.InputTokens != 100 {
		t.Errorf("InputTokens = %d, want 100", usage.InputTokens)
	}
	if usage.OutputTokens != 25 {
		t.Errorf("OutputTokens = %d, want 25", usage.OutputTokens)
	}
}

func TestExtractSSEUsage_PlainJSON(t *testing.T) {
	// Non-SSE JSON body should return zero from ExtractSSEUsage
	body := []byte(`{"usage":{"input_tokens":50,"output_tokens":10}}`)
	usage := ExtractSSEUsage(body, DialectAnthropic)
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		t.Errorf("expected zero from ExtractSSEUsage on non-SSE body, got %+v", usage)
	}
}
