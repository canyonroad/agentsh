// internal/llmproxy/dialect_test.go
package llmproxy

import (
	"net/http"
	"testing"
)

func TestDialectDetector_Anthropic(t *testing.T) {
	d := NewDialectDetector(nil)

	// x-api-key header -> Anthropic
	req, _ := http.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("x-api-key", "sk-ant-xxx")

	got := d.Detect(req)
	if got != DialectAnthropic {
		t.Errorf("expected Anthropic, got %s", got)
	}
}

func TestDialectDetector_AnthropicVersion(t *testing.T) {
	d := NewDialectDetector(nil)

	// anthropic-version header -> Anthropic
	req, _ := http.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("anthropic-version", "2024-01-01")
	req.Header.Set("Authorization", "Bearer xxx")

	got := d.Detect(req)
	if got != DialectAnthropic {
		t.Errorf("expected Anthropic, got %s", got)
	}
}

func TestDialectDetector_OpenAI_APIKey(t *testing.T) {
	d := NewDialectDetector(nil)

	// Bearer sk-xxx -> OpenAI API
	req, _ := http.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-proj-abc123")

	got := d.Detect(req)
	if got != DialectOpenAI {
		t.Errorf("expected OpenAI, got %s", got)
	}
}

func TestDialectDetector_ChatGPT_OAuth(t *testing.T) {
	d := NewDialectDetector(nil)

	// Bearer without sk- prefix -> ChatGPT
	req, _ := http.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

	got := d.Detect(req)
	if got != DialectChatGPT {
		t.Errorf("expected ChatGPT, got %s", got)
	}
}

func TestDialectDetector_NoAuth(t *testing.T) {
	d := NewDialectDetector(nil)

	req, _ := http.NewRequest("POST", "/v1/messages", nil)
	// No auth headers

	got := d.Detect(req)
	if got != DialectUnknown {
		t.Errorf("expected Unknown, got %s", got)
	}
}
