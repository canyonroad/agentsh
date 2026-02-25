// internal/llmproxy/usage.go
package llmproxy

import (
	"bytes"
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

// sseEvent is a minimal structure for extracting usage from SSE event data lines.
// Anthropic SSE streams embed usage in message_start (input_tokens) and
// message_delta (output_tokens) events.
type sseEvent struct {
	Type    string `json:"type"`
	Message struct {
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// openAISSEChunk represents the final chunk in an OpenAI SSE stream that
// contains aggregated usage.
type openAISSEChunk struct {
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// ExtractSSEUsage extracts token usage from an SSE event stream body.
// It scans each "data:" line for usage information and sums the totals.
func ExtractSSEUsage(body []byte, dialect Dialect) Usage {
	if len(body) == 0 {
		return Usage{}
	}

	switch dialect {
	case DialectAnthropic:
		return extractAnthropicSSEUsage(body)
	case DialectOpenAI:
		return extractOpenAISSEUsage(body)
	default:
		return Usage{}
	}
}

// extractAnthropicSSEUsage scans SSE lines for Anthropic usage events.
// input_tokens comes from message_start, output_tokens from message_delta.
func extractAnthropicSSEUsage(body []byte) Usage {
	var total Usage
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data: ")) {
			continue
		}
		data := line[6:] // strip "data: "
		var ev sseEvent
		if err := json.Unmarshal(data, &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "message_start":
			total.InputTokens += ev.Message.Usage.InputTokens
			total.OutputTokens += ev.Message.Usage.OutputTokens
		case "message_delta":
			total.InputTokens += ev.Usage.InputTokens
			total.OutputTokens += ev.Usage.OutputTokens
		}
	}
	return total
}

// extractOpenAISSEUsage scans SSE lines for OpenAI usage in the final chunk.
func extractOpenAISSEUsage(body []byte) Usage {
	var total Usage
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data: ")) {
			continue
		}
		data := line[6:]
		if bytes.Equal(data, []byte("[DONE]")) {
			continue
		}
		var chunk openAISSEChunk
		if err := json.Unmarshal(data, &chunk); err != nil {
			continue
		}
		if chunk.Usage.PromptTokens > 0 || chunk.Usage.CompletionTokens > 0 {
			total.InputTokens = chunk.Usage.PromptTokens
			total.OutputTokens = chunk.Usage.CompletionTokens
		}
	}
	return total
}
