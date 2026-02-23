package llmproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// ExtractToolCallsFromSSE parses tool calls from a buffered SSE response body.
// It dispatches to dialect-specific extractors based on the dialect parameter.
// Returns nil if no tool calls are found.
//
// For SSE extraction, ToolCall.Input will be nil because we do not accumulate
// streamed argument deltas -- we only need the tool name and ID for policy
// evaluation.
func ExtractToolCallsFromSSE(sseBody []byte, dialect Dialect) []ToolCall {
	switch dialect {
	case DialectAnthropic:
		return extractAnthropicSSEToolCalls(sseBody)
	case DialectOpenAI:
		return extractOpenAISSEToolCalls(sseBody)
	}
	return nil
}

// extractAnthropicSSEToolCalls scans SSE data lines for content_block_start
// events where content_block.type == "tool_use". It extracts content_block.id
// and content_block.name from each such event.
//
// Example SSE data line:
//
//	data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01","name":"get_weather"}}
func extractAnthropicSSEToolCalls(sseBody []byte) []ToolCall {
	var calls []ToolCall

	scanner := bufio.NewScanner(bytes.NewReader(sseBody))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]

		var evt struct {
			Type         string `json:"type"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}
		if evt.Type == "content_block_start" && evt.ContentBlock.Type == "tool_use" {
			calls = append(calls, ToolCall{
				ID:   evt.ContentBlock.ID,
				Name: evt.ContentBlock.Name,
			})
		}
	}

	return calls
}

// extractOpenAISSEToolCalls scans SSE data lines for
// choices[].delta.tool_calls[] entries that contain both an id and a
// function.name (the first delta chunk for each tool call). It deduplicates
// by tool call ID to avoid counting subsequent argument-streaming chunks.
//
// Example SSE data line:
//
//	data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}
func extractOpenAISSEToolCalls(sseBody []byte) []ToolCall {
	var calls []ToolCall
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(sseBody))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			continue
		}

		var chunk struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						ID       string `json:"id"`
						Function struct {
							Name string `json:"name"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}

		for _, choice := range chunk.Choices {
			for _, tc := range choice.Delta.ToolCalls {
				if tc.ID != "" && tc.Function.Name != "" && !seen[tc.ID] {
					seen[tc.ID] = true
					calls = append(calls, ToolCall{
						ID:   tc.ID,
						Name: tc.Function.Name,
					})
				}
			}
		}
	}

	return calls
}
