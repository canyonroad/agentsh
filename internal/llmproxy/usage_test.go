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
	// ChatGPT uses same format as OpenAI
	body := []byte(`{
		"id": "chatcmpl-123",
		"usage": {"prompt_tokens": 200, "completion_tokens": 500, "total_tokens": 700}
	}`)

	usage := ExtractUsage(body, DialectChatGPT)

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
