package llmproxy

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

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
			var input json.RawMessage
			if args := []byte(tc.Function.Arguments); json.Valid(args) {
				input = args
			}
			// Always extract the tool call even with invalid args — policy
			// evaluation is based on tool name, not arguments.
			calls = append(calls, ToolCall{
				ID:    tc.ID,
				Name:  tc.Function.Name,
				Input: input,
			})
		}
	}
	return calls
}

// InterceptResult holds the outcome of MCP tool call interception.
type InterceptResult struct {
	Events        []mcpinspect.MCPToolCallInterceptedEvent
	HasBlocked    bool
	RewrittenBody []byte // Non-nil only if tool calls were blocked
}

// interceptMCPToolCalls extracts tool calls from an LLM response body,
// looks them up in the registry, evaluates policy, and returns events plus
// an optional rewritten body for blocked tools. When an analyzer is provided
// and non-nil, cross-server rules are checked before regular policy evaluation,
// and tool calls are recorded in the analyzer after each decision.
func interceptMCPToolCalls(
	body []byte,
	dialect Dialect,
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	requestID, sessionID string,
	optAnalyzer ...*mcpinspect.SessionAnalyzer,
) *InterceptResult {
	var analyzer *mcpinspect.SessionAnalyzer
	if len(optAnalyzer) > 0 {
		analyzer = optAnalyzer[0]
	}

	result := &InterceptResult{}

	if registry == nil || policy == nil {
		return result
	}

	calls := ExtractToolCalls(body, dialect)
	if len(calls) == 0 {
		return result
	}

	now := time.Now()
	blockedNames := make(map[string]bool) // tool names that were blocked

	for _, call := range calls {
		entry := registry.Lookup(call.Name)
		if entry == nil {
			// Not an MCP tool (not in registry) — skip, no event.
			continue
		}

		// Cross-server check (before regular policy).
		var decision mcpinspect.PolicyDecision
		var crossServerBlocked bool
		if analyzer != nil {
			if block := analyzer.Check(entry.ServerID, call.Name, requestID); block != nil {
				decision = mcpinspect.PolicyDecision{Allowed: false, Reason: block.Reason}
				crossServerBlocked = true
			}
		}
		if !crossServerBlocked {
			decision = policy.Evaluate(entry.ServerID, call.Name, entry.ToolHash)
		}

		action := "allow"
		var reason string
		if !decision.Allowed {
			action = "block"
			reason = decision.Reason
			result.HasBlocked = true
			blockedNames[call.Name] = true
		}

		// Record in analyzer for cross-server pattern detection.
		if analyzer != nil {
			analyzer.Record(mcpinspect.ToolCallRecord{
				Timestamp: now,
				ServerID:  entry.ServerID,
				ToolName:  call.Name,
				RequestID: requestID,
				Action:    action,
				Category:  analyzer.Classify(call.Name),
			})
		}

		result.Events = append(result.Events, mcpinspect.MCPToolCallInterceptedEvent{
			Type:       "mcp_tool_call_intercepted",
			Timestamp:  now,
			SessionID:  sessionID,
			RequestID:  requestID,
			Dialect:    string(dialect),
			ToolName:   call.Name,
			ToolCallID: call.ID,
			Input:      call.Input,
			ServerID:   entry.ServerID,
			ServerType: entry.ServerType,
			ServerAddr: entry.ServerAddr,
			ToolHash:   entry.ToolHash,
			Action: action,
			Reason: reason,
		})
	}

	if result.HasBlocked {
		switch dialect {
		case DialectAnthropic:
			result.RewrittenBody = rewriteAnthropicResponse(body, blockedNames)
		case DialectOpenAI:
			result.RewrittenBody = rewriteOpenAIResponse(body, blockedNames)
		}
	}

	return result
}

// rewriteAnthropicResponse replaces blocked tool_use content blocks with text
// blocks saying the tool was blocked. If ALL tool_use blocks are blocked, the
// stop_reason is changed to "end_turn". If only some are blocked, stop_reason
// remains "tool_use".
func rewriteAnthropicResponse(body []byte, blockedNames map[string]bool) []byte {
	// Parse preserving unknown fields.
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}

	// Parse content array.
	var content []json.RawMessage
	if err := json.Unmarshal(resp["content"], &content); err != nil {
		return nil
	}

	var newContent []json.RawMessage
	remainingToolUse := 0

	for _, block := range content {
		var info struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(block, &info); err != nil {
			// Keep blocks we can't parse.
			newContent = append(newContent, block)
			continue
		}

		if info.Type == "tool_use" && blockedNames[info.Name] {
			// Replace with a text block.
			replacement := map[string]string{
				"type": "text",
				"text": fmt.Sprintf("[agentsh] Tool '%s' blocked by policy", info.Name),
			}
			raw, err := json.Marshal(replacement)
			if err != nil {
				newContent = append(newContent, block)
				continue
			}
			newContent = append(newContent, json.RawMessage(raw))
		} else {
			if info.Type == "tool_use" {
				remainingToolUse++
			}
			newContent = append(newContent, block)
		}
	}

	// Update content.
	contentRaw, err := json.Marshal(newContent)
	if err != nil {
		return nil
	}
	resp["content"] = json.RawMessage(contentRaw)

	// Update stop_reason: "end_turn" if all tool_use blocks were blocked.
	if remainingToolUse == 0 {
		resp["stop_reason"] = json.RawMessage(`"end_turn"`)
	}

	out, err := json.Marshal(resp)
	if err != nil {
		return nil
	}
	return out
}

// rewriteOpenAIResponse removes blocked tool calls from
// choices[].message.tool_calls[]. If all tool calls are removed, sets
// message.content to a blocked message string and changes finish_reason
// to "stop".
func rewriteOpenAIResponse(body []byte, blockedNames map[string]bool) []byte {
	// Parse top-level preserving unknown fields.
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}

	// Parse choices.
	var choices []json.RawMessage
	if err := json.Unmarshal(resp["choices"], &choices); err != nil {
		return nil
	}

	var newChoices []json.RawMessage
	for _, choiceRaw := range choices {
		var choice map[string]json.RawMessage
		if err := json.Unmarshal(choiceRaw, &choice); err != nil {
			newChoices = append(newChoices, choiceRaw)
			continue
		}

		// Parse message.
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(choice["message"], &msg); err != nil {
			newChoices = append(newChoices, choiceRaw)
			continue
		}

		// Parse tool_calls from message.
		var toolCalls []json.RawMessage
		if msg["tool_calls"] != nil {
			if err := json.Unmarshal(msg["tool_calls"], &toolCalls); err != nil {
				newChoices = append(newChoices, choiceRaw)
				continue
			}
		}

		// Filter out blocked tool calls.
		var kept []json.RawMessage
		var blockedMessages []string
		for _, tcRaw := range toolCalls {
			var tc struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			}
			if err := json.Unmarshal(tcRaw, &tc); err != nil {
				kept = append(kept, tcRaw)
				continue
			}
			if blockedNames[tc.Function.Name] {
				blockedMessages = append(blockedMessages, fmt.Sprintf("[agentsh] Tool '%s' blocked by policy", tc.Function.Name))
			} else {
				kept = append(kept, tcRaw)
			}
		}

		if len(kept) == 0 && len(blockedMessages) > 0 {
			// All tool calls blocked: set content to blocked message and
			// change finish_reason to "stop".
			combinedMsg := blockedMessages[0]
			if len(blockedMessages) > 1 {
				combinedMsg = ""
				for _, m := range blockedMessages {
					if combinedMsg != "" {
						combinedMsg += "\n"
					}
					combinedMsg += m
				}
			}
			contentRaw, _ := json.Marshal(combinedMsg)
			msg["content"] = json.RawMessage(contentRaw)
			// Remove tool_calls.
			delete(msg, "tool_calls")
			choice["finish_reason"] = json.RawMessage(`"stop"`)
		} else if len(kept) < len(toolCalls) {
			// Partial block: keep remaining tool calls.
			keptRaw, _ := json.Marshal(kept)
			msg["tool_calls"] = json.RawMessage(keptRaw)
		}
		// else: no blocking needed, keep as is.

		msgRaw, _ := json.Marshal(msg)
		choice["message"] = json.RawMessage(msgRaw)

		choiceResult, _ := json.Marshal(choice)
		newChoices = append(newChoices, json.RawMessage(choiceResult))
	}

	choicesRaw, err := json.Marshal(newChoices)
	if err != nil {
		return nil
	}
	resp["choices"] = json.RawMessage(choicesRaw)

	out, err := json.Marshal(resp)
	if err != nil {
		return nil
	}
	return out
}

// interceptMCPToolCallsFromList performs interception on pre-extracted tool calls.
// Used by the SSE path where tool calls are extracted from SSE chunks rather
// than from a JSON body.
func interceptMCPToolCallsFromList(
	calls []ToolCall,
	dialect Dialect,
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	requestID, sessionID string,
) *InterceptResult {
	result := &InterceptResult{}

	for _, call := range calls {
		entry := registry.Lookup(call.Name)
		if entry == nil {
			continue
		}

		decision := policy.Evaluate(entry.ServerID, call.Name, entry.ToolHash)

		event := mcpinspect.MCPToolCallInterceptedEvent{
			Type:       "mcp_tool_call_intercepted",
			Timestamp:  time.Now(),
			SessionID:  sessionID,
			RequestID:  requestID,
			Dialect:    string(dialect),
			ToolName:   call.Name,
			ToolCallID: call.ID,
			Input:      call.Input,
			ServerID:   entry.ServerID,
			ServerType: entry.ServerType,
			ServerAddr: entry.ServerAddr,
			ToolHash:   entry.ToolHash,
		}

		if decision.Allowed {
			event.Action = "allow"
		} else {
			event.Action = "block"
			event.Reason = decision.Reason
			result.HasBlocked = true
		}
		result.Events = append(result.Events, event)
	}

	return result
}

// getRegistry returns the MCP tool registry in a thread-safe manner.
func (p *Proxy) getRegistry() *mcpregistry.Registry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.registry
}
