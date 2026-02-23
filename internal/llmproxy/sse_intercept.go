package llmproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

// SSEInterceptor processes an SSE stream line-by-line, evaluating MCP tool
// calls against a policy and suppressing/replacing blocked tool_use events
// mid-stream. It replaces the previous io.Copy approach where SSE interception
// was audit-only.
type SSEInterceptor struct {
	registry  *mcpregistry.Registry
	policy    *mcpinspect.PolicyEvaluator
	dialect   Dialect
	sessionID string
	requestID string
	onEvent   func(mcpinspect.MCPToolCallInterceptedEvent)
	logger    *slog.Logger

	// Anthropic state
	blockedIndices map[int]bool
	totalToolUse   int
	blockedToolUse int

	// Internal buffer for the complete output (returned to caller for logging).
	buf bytes.Buffer
}

// NewSSEInterceptor creates a new SSE stream interceptor.
func NewSSEInterceptor(
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	dialect Dialect,
	sessionID, requestID string,
	onEvent func(mcpinspect.MCPToolCallInterceptedEvent),
	logger *slog.Logger,
) *SSEInterceptor {
	return &SSEInterceptor{
		registry:       registry,
		policy:         policy,
		dialect:        dialect,
		sessionID:      sessionID,
		requestID:      requestID,
		onEvent:        onEvent,
		logger:         logger,
		blockedIndices: make(map[int]bool),
	}
}

// Stream reads SSE lines from upstream, evaluates tool calls against policy,
// and writes (possibly modified) output to client. Returns the buffered output
// for logging/auditing.
func (s *SSEInterceptor) Stream(upstream io.Reader, client io.Writer) []byte {
	scanner := bufio.NewScanner(upstream)
	scanner.Buffer(make([]byte, 0, sseMaxLineSize), sseMaxLineSize)

	// pendingEvent buffers an "event: ..." line until we see the paired
	// "data: ..." line and decide whether to emit or suppress the pair.
	var pendingEvent string
	hasPending := false
	// suppressNextEmpty drops the blank line that terminates a suppressed
	// SSE event (the "\n\n" separator between events).
	suppressNextEmpty := false

	for scanner.Scan() {
		line := scanner.Text()

		var outputLines []string

		switch s.dialect {
		case DialectAnthropic:
			// If we just suppressed an event, also suppress its trailing blank line.
			if suppressNextEmpty && line == "" {
				suppressNextEmpty = false
				continue
			}
			suppressNextEmpty = false

			data, ok := extractSSEData(line)
			if ok {
				outputLines = s.processAnthropicEvent(line, data)
				if outputLines == nil {
					// Suppressed — also drop the buffered event: line
					// and the following blank separator.
					hasPending = false
					suppressNextEmpty = true
					continue
				}
				// Emit the buffered event: line unless the processor
				// returned a multi-line replacement that includes its
				// own event: prefixes (e.g. emitAnthropicTextBlock).
				if hasPending {
					hasOwnEvents := false
					for _, ol := range outputLines {
						if strings.HasPrefix(ol, "event:") {
							hasOwnEvents = true
							break
						}
					}
					if !hasOwnEvents {
						s.writeLine(client, pendingEvent)
					}
					hasPending = false
				}
			} else if strings.HasPrefix(line, "event:") {
				// Buffer this event: line until we process the paired data: line.
				pendingEvent = line
				hasPending = true
				continue
			} else {
				// Empty lines and other non-event/non-data lines.
				// Flush any pending event first.
				if hasPending {
					s.writeLine(client, pendingEvent)
					hasPending = false
				}
				outputLines = []string{line}
			}
		case DialectOpenAI:
			outputLines = s.processOpenAIEvent(line)
		default:
			outputLines = []string{line}
		}

		for _, outLine := range outputLines {
			s.writeLine(client, outLine)
		}
	}

	// Flush any trailing pending event.
	if hasPending {
		s.writeLine(client, pendingEvent)
	}

	if err := scanner.Err(); err != nil {
		s.logger.Warn("sse interceptor scanner error",
			"error", err,
			"request_id", s.requestID,
			"session_id", s.sessionID,
		)
	}

	return s.buf.Bytes()
}

// processAnthropicEvent implements the Anthropic SSE state machine.
// It returns zero or more lines to write to the client.
func (s *SSEInterceptor) processAnthropicEvent(originalLine, data string) []string {
	// Parse the event type.
	var evt struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
	}
	if err := json.Unmarshal([]byte(data), &evt); err != nil {
		// Can't parse — pass through.
		return []string{originalLine}
	}

	switch evt.Type {
	case "content_block_start":
		return s.handleContentBlockStart(originalLine, data, evt.Index)

	case "content_block_delta":
		if s.blockedIndices[evt.Index] {
			return nil // suppress
		}
		return []string{originalLine}

	case "content_block_stop":
		if s.blockedIndices[evt.Index] {
			return nil // suppress (we emitted our own stop in the replacement)
		}
		return []string{originalLine}

	case "message_delta":
		return s.handleMessageDelta(originalLine, data)

	default:
		// message_start, message_stop, ping, etc. — pass through.
		return []string{originalLine}
	}
}

// handleContentBlockStart handles a content_block_start event. If the block
// is a tool_use, it looks up the tool in the registry and evaluates policy.
func (s *SSEInterceptor) handleContentBlockStart(originalLine, data string, index int) []string {
	var block struct {
		Type         string `json:"type"`
		Index        int    `json:"index"`
		ContentBlock struct {
			Type string `json:"type"`
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"content_block"`
	}
	if err := json.Unmarshal([]byte(data), &block); err != nil {
		return []string{originalLine}
	}

	if block.ContentBlock.Type != "tool_use" {
		// Not a tool_use block — pass through (text blocks, etc.).
		return []string{originalLine}
	}

	s.totalToolUse++

	toolName := block.ContentBlock.Name
	toolCallID := block.ContentBlock.ID

	entry, decision := s.lookupAndEvaluate(toolName)
	if entry == nil {
		// Not in registry (not an MCP tool) — pass through silently.
		return []string{originalLine}
	}

	if decision.Allowed {
		// Allowed — pass through, fire event.
		s.fireEvent(toolName, toolCallID, "allow", "", entry)
		return []string{originalLine}
	}

	// Blocked — suppress original and emit replacement text block.
	s.blockedToolUse++
	s.blockedIndices[index] = true
	s.fireEvent(toolName, toolCallID, "block", decision.Reason, entry)

	return s.emitAnthropicTextBlock(index, toolName)
}

// handleMessageDelta handles the message_delta event. If all tool_use blocks
// were blocked, it rewrites the stop_reason to "end_turn".
func (s *SSEInterceptor) handleMessageDelta(originalLine, data string) []string {
	if s.totalToolUse > 0 && s.blockedToolUse == s.totalToolUse {
		// All tool_use blocked — rewrite stop_reason.
		rewritten := s.rewriteAnthropicStopReason(data)
		return []string{"data: " + rewritten}
	}
	return []string{originalLine}
}

// emitAnthropicTextBlock generates a replacement text block for a blocked tool.
// It produces 3 SSE data lines: content_block_start, content_block_delta, content_block_stop.
func (s *SSEInterceptor) emitAnthropicTextBlock(index int, toolName string) []string {
	msg := fmt.Sprintf("[agentsh] Tool '%s' blocked by policy", toolName)

	startData := fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`, index)
	deltaData := fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%s}}`, index, mustMarshalString(msg))
	stopData := fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, index)

	return []string{
		"event: content_block_start",
		"data: " + startData,
		"",
		"event: content_block_delta",
		"data: " + deltaData,
		"",
		"event: content_block_stop",
		"data: " + stopData,
		"",
	}
}

// rewriteAnthropicStopReason parses a message_delta data payload, changes
// stop_reason to "end_turn", and re-serializes it. Preserves other fields
// like usage.
func (s *SSEInterceptor) rewriteAnthropicStopReason(data string) string {
	// Use map to preserve unknown fields.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &obj); err != nil {
		return data
	}

	// Parse the delta sub-object.
	var delta map[string]json.RawMessage
	if err := json.Unmarshal(obj["delta"], &delta); err != nil {
		return data
	}

	// Rewrite stop_reason.
	delta["stop_reason"] = json.RawMessage(`"end_turn"`)

	deltaBytes, err := json.Marshal(delta)
	if err != nil {
		return data
	}
	obj["delta"] = json.RawMessage(deltaBytes)

	result, err := json.Marshal(obj)
	if err != nil {
		return data
	}
	return string(result)
}

// lookupAndEvaluate looks up a tool in the registry and evaluates policy.
// Returns nil entry if the tool is not registered (not an MCP tool).
func (s *SSEInterceptor) lookupAndEvaluate(toolName string) (*mcpregistry.ToolEntry, *mcpinspect.PolicyDecision) {
	if s.registry == nil || s.policy == nil {
		return nil, nil
	}

	entry := s.registry.Lookup(toolName)
	if entry == nil {
		return nil, nil
	}

	decision := s.policy.Evaluate(entry.ServerID, toolName, entry.ToolHash)
	return entry, &decision
}

// fireEvent fires the onEvent callback with the given parameters.
func (s *SSEInterceptor) fireEvent(toolName, toolCallID, action, reason string, entry *mcpregistry.ToolEntry) {
	if s.onEvent == nil {
		return
	}

	s.onEvent(mcpinspect.MCPToolCallInterceptedEvent{
		Type:       "mcp_tool_call_intercepted",
		Timestamp:  time.Now(),
		SessionID:  s.sessionID,
		RequestID:  s.requestID,
		Dialect:    string(s.dialect),
		ToolName:   toolName,
		ToolCallID: toolCallID,
		ServerID:   entry.ServerID,
		ServerType: entry.ServerType,
		ServerAddr: entry.ServerAddr,
		ToolHash:   entry.ToolHash,
		Action:     action,
		Reason:     reason,
	})
}

// writeLine writes a line to both the client writer and the internal buffer,
// followed by a newline. Flushes the client if it supports http.Flusher.
func (s *SSEInterceptor) writeLine(client io.Writer, line string) {
	lineBytes := []byte(line + "\n")

	// Write to client.
	client.Write(lineBytes) //nolint:errcheck

	// Flush if possible for immediate streaming.
	if f, ok := client.(http.Flusher); ok {
		f.Flush()
	}

	// Buffer for return value.
	s.buf.Write(lineBytes)
}

// processOpenAIEvent is a stub for OpenAI SSE processing.
// Currently passes all lines through unchanged.
func (s *SSEInterceptor) processOpenAIEvent(originalLine string) []string {
	return []string{originalLine}
}

// mustMarshalString JSON-encodes a string value (with proper escaping).
func mustMarshalString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
