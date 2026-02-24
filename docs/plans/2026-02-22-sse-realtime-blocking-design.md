# Real-Time SSE Stream Blocking for MCP Tool Calls

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the audit-only SSE interception with real-time inline blocking that suppresses blocked MCP tool calls mid-stream and emits replacement text blocks, matching non-SSE behavior.

**Architecture:** A stateful per-line SSE interceptor sits between the upstream LLM response and the client writer. It parses each `data:` line, evaluates policy on tool_use declarations, and either passes events through or replaces them with synthetic text blocks. When no policy is configured, the existing `io.Copy` fast path is preserved.

**Tech Stack:** Go, `bufio.Scanner`, `encoding/json`, existing `mcpregistry.Registry` + `mcpinspect.PolicyEvaluator`

---

## Background

PR #100 added MCP tool call interception to the LLM proxy. For non-SSE (buffered) responses, blocked tool calls are rewritten before reaching the client. For SSE (streaming) responses, interception is **audit-only** — the `onComplete` callback fires after `io.Copy` has already forwarded the entire stream to the client.

This means a client using `stream=true` receives blocked tool calls verbatim. The agent can then attempt to execute them, bypassing the policy.

## Approach: Inline Chunk Suppression (Approach 3)

Replace `io.Copy(streamingResponseWriter, resp.Body)` with a line-by-line SSE scanner that can suppress/replace individual events mid-stream.

**Why not terminate-and-rewrite (Approach 1):** Cutting the stream produces a protocol error — the harness receives an incomplete SSE body with open content blocks and no `message_stop`. Most SDKs treat this as a connection error.

**Why not append-error (Approach 2):** The agent still receives the tool_use and can execute it. Doesn't solve the security problem.

**Why Approach 3 works:** Each suppressed tool_use block is replaced with a text block identical to what the non-SSE path produces. The stream stays well-formed — every `content_block_start` gets a matching `content_block_stop`, `message_delta` has a valid `stop_reason`, and `message_stop` closes cleanly. The harness sees a perfectly normal response.

## Decisions

- **Partial block:** When a turn has multiple tool calls and only some are blocked, suppress only the blocked ones. Allowed tools pass through. Matches non-SSE behavior.
- **Immediate events:** MCP intercept events fire to the event store/broker immediately when a blocked tool is detected mid-stream, not batched at end.
- **Fail open:** Malformed JSON or scanner errors cause pass-through, not blocking.

## SSEInterceptor Type

New file: `internal/llmproxy/sse_intercept.go`

```go
type SSEInterceptor struct {
    registry    *mcpregistry.Registry
    policy      *mcpinspect.PolicyEvaluator
    dialect     Dialect
    sessionID   string
    requestID   string
    onEvent     func(mcpinspect.MCPToolCallInterceptedEvent)
    logger      *slog.Logger

    // Anthropic state
    blockedIndices map[int]bool
    totalToolUse   int
    blockedToolUse int

    // OpenAI state
    blockedToolIdx map[int]bool
    totalTools     int
    blockedTools   int

    // Shared
    blockedNames []string
    buf          bytes.Buffer // buffered copy of what was sent to client
}
```

### Public method

```go
func (s *SSEInterceptor) Stream(upstream io.Reader, client io.Writer) []byte
```

- Reads upstream line-by-line with `bufio.Scanner` (256KB buffer)
- For each line: if it starts with `data: ` and is not `data: [DONE]`, dispatches to dialect-specific processor
- Non-data lines (`event:`, empty lines, comments) pass through verbatim
- Returns full buffered output for logging

### Internal methods

- `processAnthropicEvent(data []byte) [][]byte` — returns lines to emit (0 = suppress, 1 = pass/rewrite, 3 = replacement text block)
- `processOpenAIEvent(data []byte) [][]byte` — same contract
- `emitAnthropicTextBlock(index int, name string) [][]byte` — generates 3 synthetic SSE events for a replacement text block
- `lookupAndEvaluate(toolName string) (serverID, toolHash, action, reason)` — registry lookup + policy eval

## Anthropic Dialect: State Machine

| SSE Event | Action |
|-----------|--------|
| `content_block_start` with `type: tool_use` | Lookup name in registry + evaluate policy. **Blocked:** add index to `blockedIndices`, emit replacement text block (3 events: start + delta + stop), fire event callback. **Allowed:** pass through, fire event callback. **Unregistered:** pass through silently. |
| `content_block_start` with `type: text` | Pass through unchanged |
| `content_block_delta` | If index in `blockedIndices`: suppress. Otherwise pass through. |
| `content_block_stop` | If index in `blockedIndices`: suppress. Otherwise pass through. |
| `message_delta` | If `blockedToolUse == totalToolUse` (all blocked): rewrite `stop_reason` from `"tool_use"` to `"end_turn"`. Otherwise pass through. |
| Everything else | Pass through unchanged |

Replacement text block (3 events emitted at the original index):

```
data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}
data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"[agentsh] Tool 'get_weather' blocked by policy"}}
data: {"type":"content_block_stop","index":1}
```

## OpenAI Dialect: Array Filtering

| Chunk Type | Action |
|-----------|--------|
| First tool chunk (has `id` + `function.name`) | Evaluate each tool. Remove blocked entries from `tool_calls[]`. If ALL blocked: remove `tool_calls`, set `content` to blocked message, emit. If partial: emit with filtered array. Fire event callbacks. |
| Argument chunk (`function.arguments` only) | Filter entries whose `index` is in `blockedToolIdx`. If all filtered: suppress line. Otherwise emit with filtered array. |
| Finish chunk (`finish_reason: "tool_calls"`) | If all blocked: rewrite to `"stop"`. Otherwise pass through. |
| `data: [DONE]`, content deltas, role | Pass through |

Re-serialization is required for chunks containing mixed blocked/allowed tool calls. For chunks with no blocked tools, raw bytes pass through.

## Integration: proxy.go + streaming.go

### Changes to `sseProxyTransport`

Add optional fields:

```go
type sseProxyTransport struct {
    base       http.RoundTripper
    w          http.ResponseWriter
    onComplete func(*http.Response, []byte)
    // New fields for real-time interception
    registry   *mcpregistry.Registry
    policy     *mcpinspect.PolicyEvaluator
    dialect    Dialect
    sessionID  string
    requestID  string
    onEvent    func(mcpinspect.MCPToolCallInterceptedEvent)
    logger     *slog.Logger
}
```

In `RoundTrip`, after detecting SSE:

```go
if t.registry != nil && t.policy != nil {
    interceptor := NewSSEInterceptor(t.registry, t.policy, t.dialect, ...)
    buffered := interceptor.Stream(resp.Body, sw)
    // onComplete for logging only (interception already done)
    if t.onComplete != nil {
        t.onComplete(logResp, buffered)
    }
} else {
    // Existing io.Copy fast path
    io.Copy(sw, resp.Body)
    ...
}
```

### Changes to `proxy.go` `ServeHTTP`

Pass registry, policy, dialect, IDs, and event callback into `newSSEProxyTransport`. The `onComplete` callback simplifies — no longer needs to do MCP extraction (interceptor already did it). It just calls `logResponseDirect`.

### What stays the same

- `streamingResponseWriter` — still does write-through + buffering + flush
- `errSSEHandled` sentinel
- Non-SSE `ModifyResponse` path — completely unchanged
- `interceptMCPToolCalls` / `rewriteAnthropicResponse` / `rewriteOpenAIResponse` — still used for non-SSE
- `mcp_streaming.go` extraction functions — remain available but unused in policy-enabled SSE path

## Edge Cases

- **Malformed JSON:** Pass through unmodified, log warning. Fail open.
- **Unregistered tools:** Not in MCP registry = not an MCP tool. Pass through, no event.
- **Scanner buffer overflow (>256KB line):** Fall back to `io.Copy` for remainder. Log warning.
- **Upstream drops mid-stream:** Scanner loop ends, return buffered data. Same as today.
- **Content block indices:** Replacement uses same index as suppressed block. No renumbering needed.
- **No race condition:** Synchronous pipeline — read one line, decide, write. Upstream blocked on read, client blocked on write.

## Performance

- **Fast path preserved:** No policy configured = `io.Copy`, zero overhead.
- **Cheap pre-filter:** Check for `"tool_use"` or `"tool_calls"` substring before JSON parsing. Text deltas skip parsing entirely.
- **One parse per relevant line:** Same work the current post-stream extraction does, just done inline.

## Testing

### Unit tests (`sse_intercept_test.go`)

1. Anthropic: single blocked tool — verify suppression + replacement text block + `stop_reason` rewrite + event callback
2. Anthropic: single allowed tool — verify pass-through + event callback
3. Anthropic: partial block (2 tools, 1 blocked) — verify selective suppression, `stop_reason` stays `"tool_use"`
4. Anthropic: all tools blocked — both replaced, `stop_reason` → `"end_turn"`
5. OpenAI: single blocked tool — `tool_calls` removed, content set, `finish_reason` → `"stop"`
6. OpenAI: partial block — filtered array, blocked index argument deltas suppressed
7. Unregistered tool (both dialects) — pass through, no events
8. Malformed JSON — pass through without panic
9. No policy — verify `io.Copy` path still works

### Integration test (`proxy_test.go`)

10. End-to-end SSE blocking: full proxy with mock upstream returning SSE stream with blocked MCP tool. Verify client receives replacement text block. Verify event callback fired.

## Files

| File | Change |
|------|--------|
| `internal/llmproxy/sse_intercept.go` | New: `SSEInterceptor` type, `Stream`, Anthropic + OpenAI processors |
| `internal/llmproxy/sse_intercept_test.go` | New: unit tests (cases 1-9) |
| `internal/llmproxy/streaming.go` | Add optional interception fields to `sseProxyTransport`, conditional interceptor in `RoundTrip` |
| `internal/llmproxy/proxy.go` | Pass interception params to `newSSEProxyTransport`, simplify `onComplete` |
| `internal/llmproxy/proxy_test.go` | Add end-to-end SSE blocking integration test |
