// internal/llmproxy/usage.go
package llmproxy

import (
	"encoding/json"
)

// Usage represents normalized token usage from LLM responses.
// Different providers use different field names, but we normalize to
// input_tokens and output_tokens for consistent logging and cost attribution.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// anthropicUsage represents the usage format in Anthropic API responses.
// Anthropic uses "input_tokens" and "output_tokens".
type anthropicUsage struct {
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// openAIUsage represents the usage format in OpenAI API responses.
// OpenAI uses "prompt_tokens" and "completion_tokens".
type openAIUsage struct {
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// ExtractUsage extracts token usage from an LLM response body.
// It normalizes the provider-specific field names to the standard
// InputTokens and OutputTokens fields.
//
// For Anthropic responses:
//
//	{"usage": {"input_tokens": 150, "output_tokens": 892}}
//
// For OpenAI/ChatGPT responses:
//
//	{"usage": {"prompt_tokens": 150, "completion_tokens": 892, "total_tokens": 1042}}
//
// Returns zero Usage if the body is empty, invalid JSON, or the dialect is unknown.
func ExtractUsage(body []byte, dialect Dialect) Usage {
	if len(body) == 0 {
		return Usage{}
	}

	switch dialect {
	case DialectAnthropic:
		return extractAnthropicUsage(body)
	case DialectOpenAI:
		return extractOpenAIUsage(body)
	default:
		return Usage{}
	}
}

// extractAnthropicUsage parses usage from Anthropic API responses.
func extractAnthropicUsage(body []byte) Usage {
	var resp anthropicUsage
	if err := json.Unmarshal(body, &resp); err != nil {
		return Usage{}
	}
	return Usage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
	}
}

// extractOpenAIUsage parses usage from OpenAI/ChatGPT API responses.
func extractOpenAIUsage(body []byte) Usage {
	var resp openAIUsage
	if err := json.Unmarshal(body, &resp); err != nil {
		return Usage{}
	}
	return Usage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}
}
