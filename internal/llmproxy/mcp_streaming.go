package llmproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// sseMaxLineSize is the maximum size of a single SSE line. The default
// bufio.Scanner limit is 64KB which could truncate very large SSE data
// lines (e.g., tool calls with large arguments). We use 256KB.
const sseMaxLineSize = 256 * 1024

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

// extractSSEData extracts the JSON payload from an SSE data line.
// Handles both "data: {...}" (with space) and "data:{...}" (without space)
// per the SSE specification. Returns empty string for non-data lines.
func extractSSEData(line string) (string, bool) {
	if strings.HasPrefix(line, "data: ") {
		return line[len("data: "):], true
	}
	if strings.HasPrefix(line, "data:") {
		return line[len("data:"):], true
	}
	return "", false
}

// newSSEScanner creates a bufio.Scanner with an increased buffer size
// for parsing SSE bodies that may contain large data lines.
func newSSEScanner(data []byte) *bufio.Scanner {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, sseMaxLineSize), sseMaxLineSize)
	return scanner
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

	scanner := newSSEScanner(sseBody)
	for scanner.Scan() {
		data, ok := extractSSEData(scanner.Text())
		if !ok {
			continue
		}

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

	scanner := newSSEScanner(sseBody)
	for scanner.Scan() {
		data, ok := extractSSEData(scanner.Text())
		if !ok {
			continue
		}
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
