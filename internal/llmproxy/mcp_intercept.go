package llmproxy

import "encoding/json"

// ToolCall represents a tool invocation extracted from an LLM response.
type ToolCall struct {
	ID    string          // "toolu_..." or "call_..."
	Name  string          // tool name
	Input json.RawMessage // arguments
}

// ExtractToolCalls parses tool call blocks from an LLM response body.
// It returns nil if no tool calls are found or the body is malformed.
func ExtractToolCalls(body []byte, dialect Dialect) []ToolCall {
	switch dialect {
	case DialectAnthropic:
		return extractAnthropicToolCalls(body)
	case DialectOpenAI:
		return extractOpenAIToolCalls(body)
	}
	return nil
}

// extractAnthropicToolCalls parses content blocks where type == "tool_use".
// It checks stop_reason == "tool_use" first and extracts id, name, input
// from each tool_use content block.
//
// Anthropic response format:
//
//	{
//	  "stop_reason": "tool_use",
//	  "content": [
//	    {"type": "text", "text": "..."},
//	    {"type": "tool_use", "id": "toolu_01A09q90qw90lq917835lq9", "name": "get_weather", "input": {"location": "San Francisco, CA"}}
//	  ]
//	}
func extractAnthropicToolCalls(body []byte) []ToolCall {
	var resp struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}
	if resp.StopReason != "tool_use" {
		return nil
	}
	var calls []ToolCall
	for _, block := range resp.Content {
		if block.Type == "tool_use" {
			calls = append(calls, ToolCall{
				ID:    block.ID,
				Name:  block.Name,
				Input: block.Input,
			})
		}
	}
	return calls
}

// extractOpenAIToolCalls parses choices[].message.tool_calls[] where
// finish_reason == "tool_calls". It extracts id, function.name, and
// function.arguments from each tool call entry. Note that OpenAI sends
// arguments as a JSON string, which is converted to json.RawMessage.
//
// OpenAI response format:
//
//	{
//	  "choices": [{
//	    "finish_reason": "tool_calls",
//	    "message": {
//	      "tool_calls": [{
//	        "id": "call_KlZ3...",
//	        "type": "function",
//	        "function": {"name": "get_weather", "arguments": "{\"location\": \"San Francisco, CA\"}"}
//	      }]
//	    }
//	  }]
//	}
func extractOpenAIToolCalls(body []byte) []ToolCall {
	var resp struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"` // JSON string
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}
	var calls []ToolCall
	for _, choice := range resp.Choices {
		if choice.FinishReason != "tool_calls" {
			continue
		}
		for _, tc := range choice.Message.ToolCalls {
			calls = append(calls, ToolCall{
				ID:    tc.ID,
				Name:  tc.Function.Name,
				Input: json.RawMessage(tc.Function.Arguments),
			})
		}
	}
	return calls
}
