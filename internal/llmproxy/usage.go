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
	InputTokens  int  `json:"input_tokens"`
	OutputTokens int  `json:"output_tokens"`
	HasUsage     bool `json:"-"` // true when the response contained a parseable usage field
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
	// Detect presence: if both tokens are zero, check whether the "usage"
	// object contains expected token fields (not just the "usage" key).
	hasUsage := resp.Usage.InputTokens > 0 || resp.Usage.OutputTokens > 0
	if !hasUsage {
		hasUsage = usageHasTokenFields(body, DialectAnthropic)
	}
	return Usage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		HasUsage:     hasUsage,
	}
}

// extractOpenAIUsage parses usage from OpenAI/ChatGPT API responses.
func extractOpenAIUsage(body []byte) Usage {
	var resp openAIUsage
	if err := json.Unmarshal(body, &resp); err != nil {
		return Usage{}
	}
	hasUsage := resp.Usage.PromptTokens > 0 || resp.Usage.CompletionTokens > 0
	if !hasUsage {
		hasUsage = usageHasTokenFields(body, DialectOpenAI)
	}
	return Usage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
		HasUsage:     hasUsage,
	}
}

// usageHasTokenFields checks whether the "usage" object in body contains
// all expected token fields with valid numeric values for the given dialect.
// Requires both fields (e.g. input_tokens AND output_tokens for Anthropic)
// with numeric values to prevent partial, null, or malformed usage objects
// from suppressing fallback charges.
func usageHasTokenFields(body []byte, dialect Dialect) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	usageRaw, ok := raw["usage"]
	if !ok {
		return false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(usageRaw, &fields); err != nil {
		return false
	}
	switch dialect {
	case DialectAnthropic:
		return isJSONNumber(fields["input_tokens"]) && isJSONNumber(fields["output_tokens"])
	case DialectOpenAI:
		return isJSONNumber(fields["prompt_tokens"]) && isJSONNumber(fields["completion_tokens"])
	default:
		return false
	}
}

// isJSONNumber returns true if raw is a valid JSON number (not null, string, etc.).
func isJSONNumber(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	// JSON numbers start with a digit or '-'.
	return raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9')
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
// It scans each "data:" line for usage information.
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

// extractSSEDataPayload extracts the JSON payload from an SSE data line.
// Handles both "data: {...}" (with space) and "data:{...}" (without space).
// Returns nil if the line is not a data line.
func extractSSEDataPayload(line []byte) []byte {
	line = bytes.TrimSpace(line)
	if bytes.HasPrefix(line, []byte("data: ")) {
		return line[6:]
	}
	if bytes.HasPrefix(line, []byte("data:")) {
		return line[5:]
	}
	return nil
}

// parseSSEEvents splits an SSE body into individual event data payloads.
// Per the SSE spec, an event's data may span multiple "data:" lines; these
// are concatenated (with newlines) until a blank line terminates the event.
// Returns only events that had at least one data line.
func parseSSEEvents(body []byte) [][]byte {
	var events [][]byte
	var dataBuf []byte
	hasData := false

	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			// Blank line = event boundary.
			if hasData {
				events = append(events, dataBuf)
				dataBuf = nil
				hasData = false
			}
			continue
		}
		if payload := extractSSEDataPayload(line); payload != nil {
			if hasData {
				dataBuf = append(dataBuf, '\n')
			}
			dataBuf = append(dataBuf, payload...)
			hasData = true
		}
		// Other fields (event:, id:, retry:, comments) are ignored.
	}
	// Flush trailing event if body doesn't end with a blank line.
	if hasData {
		events = append(events, dataBuf)
	}
	return events
}

// extractAnthropicSSEUsage scans SSE events for Anthropic usage.
// input_tokens comes from message_start. output_tokens comes from
// message_delta — Anthropic delta usage is cumulative, so we take the
// latest (highest) value rather than summing.
func extractAnthropicSSEUsage(body []byte) Usage {
	var total Usage
	for _, data := range parseSSEEvents(body) {
		var ev sseEvent
		if err := json.Unmarshal(data, &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "message_start":
			total.InputTokens += ev.Message.Usage.InputTokens
			total.OutputTokens += ev.Message.Usage.OutputTokens
			total.HasUsage = true
		case "message_delta":
			// Delta usage is cumulative — take the latest value.
			if ev.Usage.OutputTokens > total.OutputTokens {
				total.OutputTokens = ev.Usage.OutputTokens
			}
			if ev.Usage.InputTokens > total.InputTokens {
				total.InputTokens = ev.Usage.InputTokens
			}
			total.HasUsage = true
		}
	}
	return total
}

// extractOpenAISSEUsage scans SSE events for OpenAI usage in the final chunk.
func extractOpenAISSEUsage(body []byte) Usage {
	var total Usage
	for _, data := range parseSSEEvents(body) {
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
			total.HasUsage = true
		} else if !total.HasUsage && usageHasTokenFields(data, DialectOpenAI) {
			// Usage object present with zero tokens — still counts as HasUsage.
			total.HasUsage = true
		}
	}
	return total
}
