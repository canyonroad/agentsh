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

	"github.com/agentsh/agentsh/internal/config"
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
	analyzer  *mcpinspect.SessionAnalyzer
	dialect   Dialect
	sessionID string
	requestID string
	onEvent   func(mcpinspect.MCPToolCallInterceptedEvent)
	logger    *slog.Logger
	rateLimiter   *mcpinspect.RateLimiterRegistry
	versionPinCfg *config.MCPVersionPinningConfig

	// Anthropic state
	blockedIndices map[int]bool
	totalToolUse   int
	blockedToolUse int

	// OpenAI state — tracked per choice index for n>1 support.
	openAIChoices map[int]*openAIChoiceTracking

	// Internal buffer for the complete output (returned to caller for logging).
	buf bytes.Buffer

	// clientErr tracks the first write error to the client, used to abort early.
	clientErr error
}

// openAIChoiceTracking tracks per-choice blocking state for OpenAI dialect.
// Each choice (from the n parameter) has its own set of tool calls.
type openAIChoiceTracking struct {
	blocked  map[int]bool // tool_calls[].index → blocked
	total    int          // all tool calls seen (MCP + non-MCP)
	nblocked int          // how many were blocked
}

// NewSSEInterceptor creates a new SSE stream interceptor. The analyzer
// parameter enables cross-server pattern detection; pass nil to disable.
func NewSSEInterceptor(
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	dialect Dialect,
	sessionID, requestID string,
	onEvent func(mcpinspect.MCPToolCallInterceptedEvent),
	logger *slog.Logger,
	analyzer *mcpinspect.SessionAnalyzer,
	rateLimiter *mcpinspect.RateLimiterRegistry,
	versionPinCfg *config.MCPVersionPinningConfig,
) *SSEInterceptor {
	return &SSEInterceptor{
		registry:       registry,
		policy:         policy,
		analyzer:       analyzer,
		dialect:        dialect,
		sessionID:      sessionID,
		requestID:      requestID,
		onEvent:        onEvent,
		logger:         logger,
		rateLimiter:    rateLimiter,
		versionPinCfg:  versionPinCfg,
		blockedIndices: make(map[int]bool),
		openAIChoices:  make(map[int]*openAIChoiceTracking),
	}
}

// getChoiceTracking returns the per-choice state for the given choice index,
// creating it if needed.
func (s *SSEInterceptor) getChoiceTracking(choiceIdx int) *openAIChoiceTracking {
	st := s.openAIChoices[choiceIdx]
	if st == nil {
		st = &openAIChoiceTracking{blocked: make(map[int]bool)}
		s.openAIChoices[choiceIdx] = st
	}
	return st
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
		// Abort early if client disconnected.
		if s.clientErr != nil {
			break
		}

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
	if hasPending && s.clientErr == nil {
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

	entry, decision, crossServerDec := s.lookupAndEvaluate(toolName, toolCallID)
	if entry == nil {
		// Not in registry (not an MCP tool) — pass through silently.
		return []string{originalLine}
	}

	if decision.Allowed {
		// Allowed — pass through, fire event.
		s.fireEvent(toolName, toolCallID, "allow", decision.Reason, entry)
		return []string{originalLine}
	}

	// Blocked — suppress original and emit replacement text block.
	s.blockedToolUse++
	s.blockedIndices[index] = true
	s.fireEvent(toolName, toolCallID, "block", decision.Reason, entry, crossServerDec)

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
// When a SessionAnalyzer is configured, cross-server rules are checked before
// regular policy evaluation. The third return value carries the cross-server
// decision details when the block was caused by a cross-server rule.
func (s *SSEInterceptor) lookupAndEvaluate(toolName, toolCallID string) (*mcpregistry.ToolEntry, *mcpinspect.PolicyDecision, *mcpinspect.CrossServerDecision) {
	if s.registry == nil {
		return nil, nil, nil
	}

	entry := s.registry.Lookup(toolName)
	if entry == nil {
		return nil, nil, nil
	}

	// Cross-server check + record (atomic to eliminate TOCTOU race).
	if s.analyzer != nil {
		if block, _ := s.analyzer.CheckAndRecord(entry.ServerID, toolName, toolCallID, s.requestID); block != nil {
			return entry, &mcpinspect.PolicyDecision{Allowed: false, Reason: block.Reason}, block
		}
	}

	// Rate limit check.
	if s.rateLimiter != nil {
		if !s.rateLimiter.Allow(entry.ServerID, toolName) {
			dec := mcpinspect.PolicyDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("rate limit exceeded for server %q", entry.ServerID),
			}
			if s.analyzer != nil {
				s.analyzer.MarkBlocked(entry.ServerID, toolName, toolCallID, s.requestID)
			}
			return entry, &dec, nil
		}
	}

	// Version pin check.
	var alertReason string
	if s.versionPinCfg != nil && s.versionPinCfg.Enabled {
		if pinnedHash, pinned := s.registry.PinnedHash(toolName); pinned && entry.ToolHash != pinnedHash {
			switch s.versionPinCfg.OnChange {
			case "block":
				dec := mcpinspect.PolicyDecision{
					Allowed: false,
					Reason: fmt.Sprintf("tool %q hash changed (pinned: %s, current: %s)",
						toolName, pinnedHash, entry.ToolHash),
				}
				if s.analyzer != nil {
					s.analyzer.MarkBlocked(entry.ServerID, toolName, toolCallID, s.requestID)
				}
				return entry, &dec, nil
			case "alert":
				// Store alert reason but continue to policy evaluation.
				alertReason = fmt.Sprintf("tool %q hash changed (pinned: %s, current: %s) [alert only]",
					toolName, pinnedHash, entry.ToolHash)
			}
		}
	}

	// Policy evaluation (only if policy is present).
	var decision mcpinspect.PolicyDecision
	if s.policy != nil {
		decision = s.policy.Evaluate(entry.ServerID, toolName, entry.ToolHash)
	} else {
		decision = mcpinspect.PolicyDecision{Allowed: true}
	}

	// If policy blocks a call that cross-server allowed, update the window
	// so the "allow" record becomes "block" (prevents false positives).
	if !decision.Allowed && s.analyzer != nil {
		s.analyzer.MarkBlocked(entry.ServerID, toolName, toolCallID, s.requestID)
	}

	// Preserve version pin alert reason when policy allows the call.
	if decision.Allowed && alertReason != "" {
		decision.Reason = alertReason
	}

	return entry, &decision, nil
}

// fireEvent fires the onEvent callback with the given parameters.
// When a cross-server decision is provided, its metadata is included in the event.
func (s *SSEInterceptor) fireEvent(toolName, toolCallID, action, reason string, entry *mcpregistry.ToolEntry, crossServerDec ...*mcpinspect.CrossServerDecision) {
	if s.onEvent == nil {
		return
	}

	ev := mcpinspect.MCPToolCallInterceptedEvent{
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
	}

	if len(crossServerDec) > 0 && crossServerDec[0] != nil {
		dec := crossServerDec[0]
		ev.CrossServerRule = dec.Rule
		ev.CrossServerSeverity = dec.Severity
		ev.CrossServerRelated = dec.Related
	}

	s.onEvent(ev)
}

// writeLine writes a line to both the client writer and the internal buffer,
// followed by a newline. Flushes the client if it supports http.Flusher.
// On the first write error, sets s.clientErr so the scan loop can abort.
func (s *SSEInterceptor) writeLine(client io.Writer, line string) {
	lineBytes := []byte(line + "\n")

	// Always buffer (for return value / logging) regardless of client state.
	s.buf.Write(lineBytes)

	// Skip writing to client if a previous write already failed.
	if s.clientErr != nil {
		return
	}

	// Write to client.
	if _, err := client.Write(lineBytes); err != nil {
		s.clientErr = err
		s.logger.Debug("sse interceptor client write error",
			"error", err,
			"request_id", s.requestID,
		)
		return
	}

	// Flush if possible for immediate streaming.
	if f, ok := client.(http.Flusher); ok {
		f.Flush()
	}
}

// processOpenAIEvent implements the OpenAI SSE state machine.
// OpenAI SSE lines are bare "data: ..." lines (no "event:" prefix).
// Tool calls are embedded as arrays inside choices[].delta.tool_calls[].
// All choices in each chunk are processed (supports n>1).
func (s *SSEInterceptor) processOpenAIEvent(originalLine string) []string {
	data, ok := extractSSEData(originalLine)
	if !ok {
		// Empty lines, comments, etc. — pass through.
		return []string{originalLine}
	}

	// data: [DONE] — always pass through.
	if data == "[DONE]" {
		return []string{originalLine}
	}

	// Parse the chunk.
	var chunk openAIChunk
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		// Unparseable — pass through.
		return []string{originalLine}
	}

	if len(chunk.Choices) == 0 {
		return []string{originalLine}
	}

	// Process ALL choices (supports n>1).
	modified := false
	for i := range chunk.Choices {
		choice := &chunk.Choices[i]

		// Check for finish_reason.
		if choice.FinishReason != nil {
			if s.rewriteOpenAIFinish(choice) {
				modified = true
			}
			continue
		}

		// Check if this chunk has tool_calls.
		if len(choice.Delta.ToolCalls) == 0 {
			continue
		}

		// Determine whether this is a first-chunk (has id+name) or argument-streaming chunk.
		isFirstChunk := false
		for _, tc := range choice.Delta.ToolCalls {
			if tc.ID != "" {
				isFirstChunk = true
				break
			}
		}

		if isFirstChunk {
			if s.handleOpenAIFirstToolChunk(choice) {
				modified = true
			}
		} else {
			if s.handleOpenAIArgChunk(choice) {
				modified = true
			}
		}
	}

	if !modified {
		return []string{originalLine}
	}

	// Check if all choices ended up with empty deltas (all tool_calls suppressed).
	// If so, suppress the entire line to avoid emitting useless empty chunks.
	allEmpty := true
	for _, c := range chunk.Choices {
		if len(c.Delta.ToolCalls) > 0 || len(c.Delta.Content) > 0 || c.Delta.Role != "" || c.FinishReason != nil {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return nil // suppress entire line
	}

	return []string{s.safeDataJSON(&chunk, originalLine)}
}

// openAIChunk is the minimal structure we need to parse and rewrite OpenAI SSE chunks.
type openAIChunk struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Choices []openAIChunkChoice `json:"choices"`
	// Preserve other fields via raw message.
}

type openAIChunkChoice struct {
	Index        int                    `json:"index"`
	Delta        openAIChunkDelta       `json:"delta"`
	FinishReason *string                `json:"finish_reason"`
}

type openAIChunkDelta struct {
	Role      string                `json:"role,omitempty"`
	Content   json.RawMessage       `json:"content,omitempty"`
	ToolCalls []openAIChunkToolCall `json:"tool_calls,omitempty"`
}

type openAIChunkToolCall struct {
	Index    int                        `json:"index"`
	ID       string                     `json:"id,omitempty"`
	Type     string                     `json:"type,omitempty"`
	Function openAIChunkToolCallFunction `json:"function"`
}

type openAIChunkToolCallFunction struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments"`
}

// handleOpenAIFirstToolChunk processes the first chunk that introduces tool calls
// (entries have id + function.name). It evaluates each tool call against policy.
// Returns true if the chunk was modified.
func (s *SSEInterceptor) handleOpenAIFirstToolChunk(choice *openAIChunkChoice) bool {
	st := s.getChoiceTracking(choice.Index)
	toolCalls := choice.Delta.ToolCalls

	var allowed []openAIChunkToolCall
	var blockedMessages []string

	for _, tc := range toolCalls {
		toolName := tc.Function.Name
		toolCallID := tc.ID

		// Count ALL tool calls toward total (MCP and non-MCP) so that
		// finish_reason is only rewritten when truly all tools are blocked.
		st.total++

		entry, decision, crossServerDec := s.lookupAndEvaluate(toolName, toolCallID)
		if entry == nil {
			// Not in registry — pass through silently (not an MCP tool).
			allowed = append(allowed, tc)
			continue
		}

		if decision.Allowed {
			s.fireEvent(toolName, toolCallID, "allow", decision.Reason, entry)
			allowed = append(allowed, tc)
		} else {
			st.nblocked++
			st.blocked[tc.Index] = true
			s.fireEvent(toolName, toolCallID, "block", decision.Reason, entry, crossServerDec)
			blockedMessages = append(blockedMessages, fmt.Sprintf("[agentsh] Tool '%s' blocked by policy", toolName))
		}
	}

	if len(blockedMessages) == 0 {
		// Nothing blocked — no modification.
		return false
	}

	// ALL blocked: remove tool_calls, set content to combined blocked message.
	if len(allowed) == 0 {
		choice.Delta.ToolCalls = nil
		msg := strings.Join(blockedMessages, "\n")
		choice.Delta.Content = json.RawMessage(mustMarshalString(msg))
		return true
	}

	// Partial block: filter tool_calls to keep only allowed entries.
	choice.Delta.ToolCalls = allowed
	return true
}

// handleOpenAIArgChunk processes argument-streaming chunks (no id, just function.arguments).
// Filters entries whose tool_calls index is blocked for this choice.
// Returns true if the chunk was modified.
func (s *SSEInterceptor) handleOpenAIArgChunk(choice *openAIChunkChoice) bool {
	st := s.openAIChoices[choice.Index]
	if st == nil || len(st.blocked) == 0 {
		// No tools blocked for this choice — pass through.
		return false
	}

	var kept []openAIChunkToolCall
	for _, tc := range choice.Delta.ToolCalls {
		if !st.blocked[tc.Index] {
			kept = append(kept, tc)
		}
	}

	if len(kept) == len(choice.Delta.ToolCalls) {
		// Nothing filtered — pass through.
		return false
	}

	// Some or all filtered — update the choice.
	choice.Delta.ToolCalls = kept
	return true
}

// rewriteOpenAIFinish rewrites finish_reason from "tool_calls" to "stop"
// when all tool calls in this choice were blocked.
// Returns true if the chunk was modified.
func (s *SSEInterceptor) rewriteOpenAIFinish(choice *openAIChunkChoice) bool {
	st := s.openAIChoices[choice.Index]
	if st == nil {
		return false
	}

	if st.total > 0 && st.nblocked == st.total && choice.FinishReason != nil && *choice.FinishReason == "tool_calls" {
		stop := "stop"
		choice.FinishReason = &stop
		return true
	}

	return false
}

// safeDataJSON marshals a value to a "data: <json>" SSE line.
// On marshal error, logs a warning and returns the fallback line unchanged.
func (s *SSEInterceptor) safeDataJSON(v interface{}, fallbackLine string) string {
	b, err := json.Marshal(v)
	if err != nil {
		s.logger.Warn("sse interceptor JSON marshal error",
			"error", err,
			"request_id", s.requestID,
		)
		return fallbackLine
	}
	return "data: " + string(b)
}

// mustMarshalString JSON-encodes a string value (with proper escaping).
func mustMarshalString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
