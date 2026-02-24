# MCP Wiring & Streaming Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the existing MCP building blocks (ExtractToolCalls, Registry, PolicyEvaluator) into the LLM proxy runtime, add SSE streaming tool call extraction, and enable response rewriting to block denied tool calls.

**Architecture:** The proxy already buffers response bodies in both paths (non-SSE via `logResponse`, SSE via `streamingResponseWriter`). For non-SSE, we intercept in `ModifyResponse` before the body reaches the agent — this lets us rewrite blocked tool calls. For SSE, we add a chunk-level scanner that extracts tool names from early SSE events (`content_block_start` for Anthropic, first `tool_calls` delta for OpenAI), performs policy checks, and can terminate the stream for blocked tools. Both paths emit `mcp_tool_call_intercepted` events. The registry and policy evaluator are injected into the proxy at construction time.

**Tech Stack:** Go stdlib (`encoding/json`, `net/http`, `bufio`), existing packages (`mcpregistry`, `mcpinspect`, `llmproxy`, `config`, `session`)

---

### Task 1: Add MCP fields to proxy Config and Proxy struct

Add the registry, policy evaluator, and MCP config to the proxy so downstream tasks can use them.

**Files:**
- Modify: `internal/llmproxy/proxy.go:24-36` (Config struct)
- Modify: `internal/llmproxy/proxy.go:39-52` (Proxy struct)
- Modify: `internal/llmproxy/proxy.go:55-107` (New function)

**Step 1: Write the failing test**

Create a test that constructs a proxy with MCP config and verifies the fields are accessible.

```go
// internal/llmproxy/mcp_intercept_test.go (append)

func TestProxyWithMCPConfig(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
	}

	cfg := Config{
		SessionID: "test-mcp",
		Proxy:     config.ProxyConfig{Mode: "embedded", Port: 0},
		DLP:       config.DLPConfig{Mode: "disabled"},
		MCP:       mcpCfg,
	}

	storageDir := t.TempDir()
	proxy, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Registry should be nil when not provided via SetRegistry
	if proxy.registry != nil {
		t.Error("expected nil registry before SetRegistry")
	}

	proxy.SetRegistry(registry)
	if proxy.registry != registry {
		t.Error("expected registry to be set")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/ -run TestProxyWithMCPConfig -v`
Expected: FAIL — `Config` has no `MCP` field, `Proxy` has no `registry` field, no `SetRegistry` method.

**Step 3: Write minimal implementation**

In `internal/llmproxy/proxy.go`:

1. Add to `Config` struct:
```go
// MCP is the MCP policy configuration.
MCP config.SandboxMCPConfig
```

2. Add fields to `Proxy` struct:
```go
registry *mcpregistry.Registry
policy   *mcpinspect.PolicyEvaluator
```

3. In `New()`, after creating the other components, create the policy evaluator:
```go
var policyEval *mcpinspect.PolicyEvaluator
if cfg.MCP.EnforcePolicy {
    policyEval = mcpinspect.NewPolicyEvaluator(cfg.MCP)
}
```

4. Set it in the returned struct:
```go
return &Proxy{
    // ... existing fields ...
    policy: policyEval,
}, nil
```

5. Add `SetRegistry` method:
```go
// SetRegistry sets the MCP tool registry for tool call interception.
// The registry is set after construction because it's shared across
// multiple components (proxy, shim, session) and may be populated
// after the proxy starts.
func (p *Proxy) SetRegistry(r *mcpregistry.Registry) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.registry = r
}
```

Add imports for `mcpregistry` and `mcpinspect`.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/ -run TestProxyWithMCPConfig -v`
Expected: PASS

**Step 5: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: Build succeeds.

**Step 6: Commit**

```bash
git add internal/llmproxy/proxy.go internal/llmproxy/mcp_intercept_test.go
git commit -m "feat(llmproxy): add MCP config, registry, and policy fields to proxy"
```

---

### Task 2: Wire non-streaming MCP interception into ModifyResponse

This is the core wiring. When the proxy receives a non-SSE LLM response containing tool calls, look them up in the registry, evaluate policy, and emit events. Blocked tool calls are rewritten.

**Files:**
- Modify: `internal/llmproxy/mcp_intercept.go` (add `interceptMCPToolCalls` and `rewriteBlockedToolCalls`)
- Modify: `internal/llmproxy/proxy.go:256-259` (ModifyResponse callback)

**Step 1: Write the failing test for interception logic**

```go
// internal/llmproxy/mcp_intercept_test.go (append)

func TestInterceptMCPToolCalls_BlockedToolRewritten(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	registry.Register("weather-server", "http", "mcp.example.com:443", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
		DeniedTools: []config.MCPToolRule{
			{Server: "*", Tool: "get_weather"},
		},
	}
	policyEval := mcpinspect.NewPolicyEvaluator(mcpCfg)

	body := []byte(`{
		"id": "msg_01",
		"type": "message",
		"role": "assistant",
		"stop_reason": "tool_use",
		"content": [
			{"type": "text", "text": "Let me check the weather."},
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "SF"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, registry, policyEval, "req_test", "sess_test")

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.HasBlocked {
		t.Error("expected HasBlocked to be true")
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	if result.Events[0].Action != "block" {
		t.Errorf("expected action 'block', got %q", result.Events[0].Action)
	}

	// The rewritten body should have the tool_use block replaced
	if result.RewrittenBody == nil {
		t.Fatal("expected rewritten body")
	}

	// Verify the rewritten body is valid JSON with stop_reason changed
	var rewritten struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
		} `json:"content"`
	}
	if err := json.Unmarshal(result.RewrittenBody, &rewritten); err != nil {
		t.Fatalf("unmarshal rewritten body: %v", err)
	}
	if rewritten.StopReason != "end_turn" {
		t.Errorf("expected stop_reason 'end_turn', got %q", rewritten.StopReason)
	}
	// Should have the original text block + a replacement text block
	if len(rewritten.Content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(rewritten.Content))
	}
	if rewritten.Content[1].Type != "text" {
		t.Errorf("expected replaced block type 'text', got %q", rewritten.Content[1].Type)
	}
}

func TestInterceptMCPToolCalls_AllowedToolPassesThrough(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	registry.Register("weather-server", "http", "mcp.example.com:443", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
		DeniedTools:   []config.MCPToolRule{
			{Server: "*", Tool: "dangerous_tool"},
		},
	}
	policyEval := mcpinspect.NewPolicyEvaluator(mcpCfg)

	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "SF"}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, registry, policyEval, "req_test", "sess_test")

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.HasBlocked {
		t.Error("expected HasBlocked to be false for allowed tool")
	}
	if result.RewrittenBody != nil {
		t.Error("expected nil RewrittenBody for allowed tool")
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	if result.Events[0].Action != "allow" {
		t.Errorf("expected action 'allow', got %q", result.Events[0].Action)
	}
}

func TestInterceptMCPToolCalls_UnknownToolSkipped(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	// Registry is empty — no MCP tools registered

	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
	}
	policyEval := mcpinspect.NewPolicyEvaluator(mcpCfg)

	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "native_tool", "input": {}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, registry, policyEval, "req_test", "sess_test")

	// Tool not in registry, fail_closed=false (default) → skip it
	if result.HasBlocked {
		t.Error("expected no blocking for unknown tool with fail_closed=false")
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for unknown tool, got %d", len(result.Events))
	}
}

func TestInterceptMCPToolCalls_FailClosedBlocksUnknown(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	// Registry is empty

	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		FailClosed:    true,
		ToolPolicy:    "denylist",
	}
	policyEval := mcpinspect.NewPolicyEvaluator(mcpCfg)

	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "unknown_tool", "input": {}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, registry, policyEval, "req_test", "sess_test")

	if !result.HasBlocked {
		t.Error("expected blocking for unknown tool with fail_closed=true")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/ -run TestInterceptMCPToolCalls -v`
Expected: FAIL — `interceptMCPToolCalls` doesn't exist.

**Step 3: Write minimal implementation**

In `internal/llmproxy/mcp_intercept.go`, add:

```go
// InterceptResult holds the outcome of MCP tool call interception.
type InterceptResult struct {
	Events        []mcpinspect.MCPToolCallInterceptedEvent
	HasBlocked    bool
	RewrittenBody []byte // Non-nil only if tool calls were blocked (Anthropic)
}

// interceptMCPToolCalls extracts tool calls from an LLM response, checks each
// against the registry and policy, and returns interception events. If any tool
// is blocked, RewrittenBody contains the modified response with blocked tool_use
// blocks replaced by text blocks.
func interceptMCPToolCalls(
	body []byte,
	dialect Dialect,
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	requestID, sessionID string,
) *InterceptResult {
	if registry == nil || policy == nil {
		return &InterceptResult{}
	}

	calls := ExtractToolCalls(body, dialect)
	if len(calls) == 0 {
		return &InterceptResult{}
	}

	result := &InterceptResult{}
	var blockedNames []string

	for _, call := range calls {
		entry := registry.Lookup(call.Name)
		if entry == nil {
			// Not an MCP tool — skip unless fail_closed would catch it
			// (fail_closed is handled by the policy evaluator itself, but
			// we need a server ID for evaluation. No entry = no server ID,
			// so we can't evaluate. For fail_closed on unknown tools, we
			// treat "no registry entry" as "unknown MCP tool" only when
			// fail_closed is set.)
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
			blockedNames = append(blockedNames, call.Name)
		}
		result.Events = append(result.Events, event)
	}

	// Rewrite response if any tools were blocked
	if result.HasBlocked && dialect == DialectAnthropic {
		result.RewrittenBody = rewriteAnthropicResponse(body, blockedNames)
	} else if result.HasBlocked && dialect == DialectOpenAI {
		result.RewrittenBody = rewriteOpenAIResponse(body, blockedNames)
	}

	return result
}

// rewriteAnthropicResponse replaces blocked tool_use content blocks with text
// blocks and changes stop_reason to "end_turn".
func rewriteAnthropicResponse(body []byte, blockedNames []string) []byte {
	blocked := make(map[string]bool, len(blockedNames))
	for _, name := range blockedNames {
		blocked[name] = true
	}

	// Parse into generic structure to preserve all fields
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil
	}

	// Parse content array
	var content []json.RawMessage
	if err := json.Unmarshal(msg["content"], &content); err != nil {
		return nil
	}

	// Rebuild content array, replacing blocked tool_use blocks
	var newContent []json.RawMessage
	anyBlocked := false
	for _, block := range content {
		var blockInfo struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(block, &blockInfo); err != nil {
			newContent = append(newContent, block)
			continue
		}
		if blockInfo.Type == "tool_use" && blocked[blockInfo.Name] {
			// Replace with text block
			replacement := map[string]string{
				"type": "text",
				"text": fmt.Sprintf("[agentsh] Tool '%s' blocked by policy", blockInfo.Name),
			}
			b, _ := json.Marshal(replacement)
			newContent = append(newContent, b)
			anyBlocked = true
		} else {
			newContent = append(newContent, block)
		}
	}

	if !anyBlocked {
		return nil
	}

	// Replace content and stop_reason
	contentBytes, _ := json.Marshal(newContent)
	msg["content"] = contentBytes
	msg["stop_reason"] = json.RawMessage(`"end_turn"`)

	result, err := json.Marshal(msg)
	if err != nil {
		return nil
	}
	return result
}

// rewriteOpenAIResponse replaces blocked tool calls in OpenAI format.
// It removes blocked tool_calls entries and changes finish_reason to "stop".
func rewriteOpenAIResponse(body []byte, blockedNames []string) []byte {
	blocked := make(map[string]bool, len(blockedNames))
	for _, name := range blockedNames {
		blocked[name] = true
	}

	var msg map[string]json.RawMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil
	}

	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(msg["choices"], &choices); err != nil {
		return nil
	}

	for i, choice := range choices {
		var message map[string]json.RawMessage
		if err := json.Unmarshal(choice["message"], &message); err != nil {
			continue
		}

		var toolCalls []map[string]json.RawMessage
		if err := json.Unmarshal(message["tool_calls"], &toolCalls); err != nil {
			continue
		}

		var filtered []map[string]json.RawMessage
		for _, tc := range toolCalls {
			var fn struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(tc["function"], &fn); err != nil {
				filtered = append(filtered, tc)
				continue
			}
			if !blocked[fn.Name] {
				filtered = append(filtered, tc)
			}
		}

		if len(filtered) == 0 {
			// All tool calls blocked — add a text content and change finish_reason
			message["content"] = json.RawMessage(`"[agentsh] Tool calls blocked by policy"`)
			delete(message, "tool_calls")
			choices[i]["finish_reason"] = json.RawMessage(`"stop"`)
		} else {
			b, _ := json.Marshal(filtered)
			message["tool_calls"] = b
		}

		b, _ := json.Marshal(message)
		choices[i]["message"] = b
	}

	choicesBytes, _ := json.Marshal(choices)
	msg["choices"] = choicesBytes
	result, _ := json.Marshal(msg)
	return result
}
```

Add imports: `"fmt"`, `"time"`, `"github.com/agentsh/agentsh/internal/mcpinspect"`, `"github.com/agentsh/agentsh/internal/mcpregistry"`.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/ -run TestInterceptMCPToolCalls -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/llmproxy/mcp_intercept.go internal/llmproxy/mcp_intercept_test.go
git commit -m "feat(llmproxy): add MCP tool call interception and response rewriting"
```

---

### Task 3: Wire interception into the proxy ModifyResponse and SSE callback

Connect `interceptMCPToolCalls` to the actual proxy request flow — both the non-SSE `ModifyResponse` path and the SSE `onComplete` callback.

**Files:**
- Modify: `internal/llmproxy/proxy.go:239-259` (ServeHTTP, the ModifyResponse and onComplete callbacks)

**Step 1: Write the failing integration test**

```go
// internal/llmproxy/mcp_intercept_test.go (append)

func TestProxy_MCPInterception_Integration(t *testing.T) {
	// Create upstream that returns an Anthropic tool_use response
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "msg_01",
			"type": "message",
			"role": "assistant",
			"stop_reason": "tool_use",
			"content": [
				{"type": "text", "text": "Let me check."},
				{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "SF"}}
			],
			"usage": {"input_tokens": 10, "output_tokens": 20}
		}`))
	}))
	defer upstream.Close()

	registry := mcpregistry.NewRegistry()
	registry.Register("weather-server", "http", "mcp.example.com:443", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	cfg := Config{
		SessionID: "test-mcp-integration",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
		MCP: config.SandboxMCPConfig{
			EnforcePolicy: true,
			ToolPolicy:    "denylist",
			DeniedTools: []config.MCPToolRule{
				{Server: "*", Tool: "get_weather"},
			},
		},
	}

	storageDir := t.TempDir()
	proxy, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxy.SetRegistry(registry)

	if err := proxy.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Stop(context.Background())

	// Make a request through the proxy
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/v1/messages", proxy.Addr()), strings.NewReader(`{"model":"claude-3","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// The response should have the tool_use block replaced
	var result struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, body)
	}

	if result.StopReason != "end_turn" {
		t.Errorf("expected stop_reason 'end_turn', got %q", result.StopReason)
	}

	foundBlock := false
	for _, block := range result.Content {
		if strings.Contains(block.Text, "blocked by policy") {
			foundBlock = true
			break
		}
	}
	if !foundBlock {
		t.Errorf("expected blocked message in content, got: %s", body)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/ -run TestProxy_MCPInterception_Integration -v`
Expected: FAIL — the proxy doesn't call `interceptMCPToolCalls` yet; response passes through unchanged.

**Step 3: Write minimal implementation**

In `internal/llmproxy/proxy.go`, modify the `ModifyResponse` callback (around line 256):

```go
ModifyResponse: func(resp *http.Response) error {
    // Read body for both logging and MCP interception
    var respBody []byte
    if resp.Body != nil {
        body, err := io.ReadAll(resp.Body)
        if err != nil {
            p.logger.Error("read response body", "error", err, "request_id", requestID)
            return nil
        }
        respBody = body
    }

    // MCP tool call interception (non-SSE only; SSE handled in onComplete)
    if p.registry != nil && p.policy != nil && resp.StatusCode == http.StatusOK {
        result := interceptMCPToolCalls(respBody, dialect, p.registry, p.policy, requestID, sessionID)
        for _, ev := range result.Events {
            p.logger.Info("mcp tool call intercepted",
                "tool", ev.ToolName, "action", ev.Action,
                "server", ev.ServerID, "request_id", requestID)
        }
        if result.HasBlocked && result.RewrittenBody != nil {
            respBody = result.RewrittenBody
        }
    }

    // Put body back for client
    resp.Body = io.NopCloser(bytes.NewReader(respBody))
    resp.ContentLength = int64(len(respBody))

    // Log response
    p.logResponseDirect(requestID, sessionID, dialect, resp, respBody, startTime)
    return nil
},
```

Note: This replaces the existing `logResponse` call with inline body reading + `logResponseDirect`, since we need access to the body before putting it back. The existing `logResponse` method already reads the body the same way — we're just doing it earlier so we can inspect it.

Also modify the SSE `onComplete` callback (around line 242) to do the same interception (audit-only, no rewriting since the stream is already sent):

```go
func(resp *http.Response, body []byte) {
    // MCP tool call interception for SSE (audit only — stream already sent)
    if p.registry != nil && p.policy != nil {
        result := interceptMCPToolCalls(body, dialect, p.registry, p.policy, requestID, sessionID)
        for _, ev := range result.Events {
            p.logger.Info("mcp tool call intercepted (sse)",
                "tool", ev.ToolName, "action", ev.Action,
                "server", ev.ServerID, "request_id", requestID)
        }
    }
    p.logResponseDirect(requestID, sessionID, dialect, resp, body, startTime)
},
```

Wait — the SSE body is raw SSE wire format (`event: ...\ndata: ...\n\n`), not clean JSON. `ExtractToolCalls` expects a JSON body. We need SSE-specific extraction for the `onComplete` path. For now, let's only wire the non-SSE path and log a note for SSE. The SSE extraction is Task 4.

Revised SSE callback (keep existing behavior, add TODO):

```go
func(resp *http.Response, body []byte) {
    // SSE MCP interception is handled by the streaming scanner (Task 4).
    // The onComplete callback fires after the stream is fully sent to
    // the client, so it cannot block. We log here for completeness.
    p.logResponseDirect(requestID, sessionID, dialect, resp, body, startTime)
},
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/ -run TestProxy_MCPInterception_Integration -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `go test ./internal/llmproxy/ -v`
Expected: All tests pass (existing tests should not be affected since they don't set MCP config).

**Step 6: Commit**

```bash
git add internal/llmproxy/proxy.go internal/llmproxy/mcp_intercept.go internal/llmproxy/mcp_intercept_test.go
git commit -m "feat(llmproxy): wire MCP interception into proxy ModifyResponse path"
```

---

### Task 4: SSE streaming tool call extraction

Add SSE chunk-level parsing to extract tool names from streaming responses. Both Anthropic and OpenAI send the tool name early in the stream. This creates the extraction functions that the streaming scanner (Task 5) will use.

**Files:**
- Create: `internal/llmproxy/mcp_streaming.go`
- Create: `internal/llmproxy/mcp_streaming_test.go`

**Step 1: Write the failing test**

```go
// internal/llmproxy/mcp_streaming_test.go

package llmproxy

import (
	"testing"
)

func TestExtractToolCallsFromSSE_Anthropic(t *testing.T) {
	// Anthropic SSE stream with a tool_use content block
	sseBody := []byte(
		"event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"role\":\"assistant\"}}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Let me check.\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"get_weather\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"loc\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":1}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":25}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n",
	)

	calls := ExtractToolCallsFromSSE(sseBody, DialectAnthropic)
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].Name != "get_weather" {
		t.Errorf("expected name 'get_weather', got %q", calls[0].Name)
	}
	if calls[0].ID != "toolu_01" {
		t.Errorf("expected ID 'toolu_01', got %q", calls[0].ID)
	}
}

func TestExtractToolCallsFromSSE_OpenAI(t *testing.T) {
	// OpenAI SSE stream with tool_calls delta chunks
	sseBody := []byte(
		"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"index\":0,\"id\":\"call_abc\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"lo\"}}]},\"finish_reason\":null}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n" +
		"data: [DONE]\n\n",
	)

	calls := ExtractToolCallsFromSSE(sseBody, DialectOpenAI)
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].Name != "get_weather" {
		t.Errorf("expected name 'get_weather', got %q", calls[0].Name)
	}
	if calls[0].ID != "call_abc" {
		t.Errorf("expected ID 'call_abc', got %q", calls[0].ID)
	}
}

func TestExtractToolCallsFromSSE_NoToolCalls(t *testing.T) {
	sseBody := []byte(
		"event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\"}}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello!\"}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n",
	)

	calls := ExtractToolCallsFromSSE(sseBody, DialectAnthropic)
	if len(calls) != 0 {
		t.Errorf("expected 0 calls, got %d", len(calls))
	}
}

func TestExtractToolCallsFromSSE_MultipleTools(t *testing.T) {
	sseBody := []byte(
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"get_weather\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_02\",\"name\":\"get_time\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":1}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n",
	)

	calls := ExtractToolCallsFromSSE(sseBody, DialectAnthropic)
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
	if calls[0].Name != "get_weather" {
		t.Errorf("expected first call 'get_weather', got %q", calls[0].Name)
	}
	if calls[1].Name != "get_time" {
		t.Errorf("expected second call 'get_time', got %q", calls[1].Name)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/ -run TestExtractToolCallsFromSSE -v`
Expected: FAIL — `ExtractToolCallsFromSSE` doesn't exist.

**Step 3: Write minimal implementation**

```go
// internal/llmproxy/mcp_streaming.go

package llmproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// ExtractToolCallsFromSSE parses tool calls from a buffered SSE response body.
// This is used for the post-stream audit path where the full SSE body has been
// captured. For real-time chunk scanning, see the streaming scanner in Task 5.
func ExtractToolCallsFromSSE(sseBody []byte, dialect Dialect) []ToolCall {
	switch dialect {
	case DialectAnthropic:
		return extractAnthropicSSEToolCalls(sseBody)
	case DialectOpenAI:
		return extractOpenAISSEToolCalls(sseBody)
	}
	return nil
}

// extractAnthropicSSEToolCalls scans for content_block_start events with
// type=tool_use. The tool name and ID are in the content_block_start event;
// arguments are streamed in subsequent deltas (we don't capture full args here).
func extractAnthropicSSEToolCalls(sseBody []byte) []ToolCall {
	var calls []ToolCall

	scanner := bufio.NewScanner(bytes.NewReader(sseBody))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]

		var event struct {
			Type         string `json:"type"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
		if event.Type == "content_block_start" && event.ContentBlock.Type == "tool_use" {
			calls = append(calls, ToolCall{
				ID:   event.ContentBlock.ID,
				Name: event.ContentBlock.Name,
			})
		}
	}
	return calls
}

// extractOpenAISSEToolCalls scans for delta chunks containing tool_calls with
// a function name. The first delta for each tool_call index contains the name.
func extractOpenAISSEToolCalls(sseBody []byte) []ToolCall {
	var calls []ToolCall
	seen := make(map[string]bool) // track by ID to deduplicate

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
				if tc.Function.Name != "" && tc.ID != "" && !seen[tc.ID] {
					calls = append(calls, ToolCall{
						ID:   tc.ID,
						Name: tc.Function.Name,
					})
					seen[tc.ID] = true
				}
			}
		}
	}
	return calls
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/ -run TestExtractToolCallsFromSSE -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/llmproxy/mcp_streaming.go internal/llmproxy/mcp_streaming_test.go
git commit -m "feat(llmproxy): add SSE tool call extraction for Anthropic and OpenAI"
```

---

### Task 5: Wire SSE extraction into the onComplete callback

Now that we have `ExtractToolCallsFromSSE`, wire it into the SSE onComplete callback for audit-only interception of streaming responses.

**Files:**
- Modify: `internal/llmproxy/proxy.go` (SSE onComplete callback)

**Step 1: Write the failing integration test**

```go
// internal/llmproxy/mcp_intercept_test.go (append)

func TestProxy_MCPInterception_SSE_Integration(t *testing.T) {
	// Create upstream that returns an Anthropic SSE stream with tool_use
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)
		events := []string{
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"role\":\"assistant\"}}\n\n",
			"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"get_weather\"}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"location\\\":\\\"SF\\\"\"}}\n\n",
			"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":15}}\n\n",
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		}
		for _, event := range events {
			w.Write([]byte(event))
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	registry := mcpregistry.NewRegistry()
	registry.Register("weather-server", "http", "mcp.example.com:443", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	// Use a log handler that captures log output
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := Config{
		SessionID: "test-mcp-sse",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
		MCP: config.SandboxMCPConfig{
			EnforcePolicy: true,
			ToolPolicy:    "denylist",
			DeniedTools: []config.MCPToolRule{
				{Server: "*", Tool: "get_weather"},
			},
		},
	}

	storageDir := t.TempDir()
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxy.SetRegistry(registry)

	if err := proxy.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Stop(context.Background())

	// Make a streaming request through the proxy
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/v1/messages", proxy.Addr()), strings.NewReader(`{"model":"claude-3","messages":[],"stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// Read the streamed body (it passes through — SSE interception is audit-only)
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("expected non-empty SSE body")
	}

	// Check that the interception was logged
	// Give a moment for async logging
	time.Sleep(50 * time.Millisecond)
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "mcp tool call intercepted") {
		t.Errorf("expected interception log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "get_weather") {
		t.Errorf("expected tool name in log, got: %s", logOutput)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/ -run TestProxy_MCPInterception_SSE_Integration -v`
Expected: FAIL — SSE callback doesn't call interception.

**Step 3: Write minimal implementation**

Modify the SSE `onComplete` callback in `proxy.go` `ServeHTTP`:

```go
func(resp *http.Response, body []byte) {
    // MCP tool call interception for SSE (audit-only — stream already sent to client)
    if p.registry != nil && p.policy != nil {
        calls := ExtractToolCallsFromSSE(body, dialect)
        if len(calls) > 0 {
            result := interceptMCPToolCallsFromList(calls, dialect, p.registry, p.policy, requestID, sessionID)
            for _, ev := range result.Events {
                p.logger.Info("mcp tool call intercepted (sse)",
                    "tool", ev.ToolName, "action", ev.Action,
                    "server", ev.ServerID, "request_id", requestID)
            }
        }
    }
    p.logResponseDirect(requestID, sessionID, dialect, resp, body, startTime)
},
```

This requires a new helper `interceptMCPToolCallsFromList` in `mcp_intercept.go` that takes a `[]ToolCall` directly (instead of re-parsing from body):

```go
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
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/ -run TestProxy_MCPInterception_SSE_Integration -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `go test ./internal/llmproxy/ -v`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add internal/llmproxy/proxy.go internal/llmproxy/mcp_intercept.go internal/llmproxy/mcp_intercept_test.go
git commit -m "feat(llmproxy): wire SSE tool call extraction into proxy onComplete callback"
```

---

### Task 6: Wire `mcp-only` proxy mode into session startup

Currently `createSessionCore` only starts the proxy for `mode: "embedded"`. Add `"mcp-only"` handling: start the proxy, force DLP disabled, force body storage on.

**Files:**
- Modify: `internal/api/core.go:617-620` (add `mcp-only` mode)
- Modify: `internal/session/llmproxy.go` (accept MCP config)

**Step 1: Write the failing test**

```go
// internal/session/llmproxy_test.go (create or append)

package session

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestStartLLMProxy_MCPOnlyMode(t *testing.T) {
	sess := NewSession("test-mcp-only", "/tmp/workspace")

	proxyCfg := config.ProxyConfig{
		Mode: "mcp-only",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: "https://api.anthropic.com",
			OpenAI:    "https://api.openai.com",
		},
	}
	dlpCfg := config.DLPConfig{Mode: "redact"} // Should be overridden to "disabled"
	storageCfg := config.LLMStorageConfig{StoreBodies: false} // Should be overridden to true
	mcpCfg := config.SandboxMCPConfig{EnforcePolicy: true}

	storageDir := t.TempDir()

	proxyURL, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, mcpCfg, storageDir, nil)
	if err != nil {
		t.Fatalf("StartLLMProxy: %v", err)
	}
	defer closeFn()

	if proxyURL == "" {
		t.Error("expected non-empty proxy URL")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/session/ -run TestStartLLMProxy_MCPOnlyMode -v`
Expected: FAIL — `StartLLMProxy` doesn't accept `mcpCfg` parameter.

**Step 3: Write minimal implementation**

1. Modify `StartLLMProxy` signature to accept MCP config:

```go
func StartLLMProxy(
	sess *Session,
	proxyCfg config.ProxyConfig,
	dlpCfg config.DLPConfig,
	storageCfg config.LLMStorageConfig,
	mcpCfg config.SandboxMCPConfig,
	storagePath string,
	logger *slog.Logger,
) (string, func() error, error) {
```

2. Add MCP-only overrides at the start of the function:

```go
// In mcp-only mode, force DLP disabled and body storage on.
if proxyCfg.IsMCPOnly() {
    dlpCfg.Mode = "disabled"
    storageCfg.StoreBodies = true
}
```

3. Pass MCP config to the proxy:

```go
cfg := llmproxy.Config{
    SessionID: sess.ID,
    Proxy:     proxyCfg,
    DLP:       dlpCfg,
    Storage:   storageCfg,
    MCP:       mcpCfg,
}
```

4. Update the call site in `internal/api/core.go` (line ~618):

```go
// Start embedded LLM proxy if configured
if a.cfg.Proxy.Mode == "embedded" || a.cfg.Proxy.IsMCPOnly() {
    a.startLLMProxy(ctx, s)
}
```

5. Update `startLLMProxy` in `internal/api/app.go` to pass `a.cfg.Sandbox.MCP`:

```go
proxyURL, closeFn, err := session.StartLLMProxy(
    s,
    a.cfg.Proxy,
    a.cfg.DLP,
    a.cfg.LLMStorage,
    a.cfg.Sandbox.MCP,
    storagePath,
    slog.Default(),
)
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/session/ -run TestStartLLMProxy_MCPOnlyMode -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `go test ./...`
Expected: All tests pass. (The call site change in `core.go` and `app.go` may need existing test updates if they create sessions.)

**Step 6: Commit**

```bash
git add internal/session/llmproxy.go internal/api/core.go internal/api/app.go
git commit -m "feat: wire mcp-only proxy mode into session startup"
```

---

### Task 7: Pass registry from session to proxy at startup

The registry needs to be created during session startup and injected into the proxy. This connects the registry to the session lifecycle.

**Files:**
- Modify: `internal/session/manager.go` (add MCPRegistry field to Session)
- Modify: `internal/session/llmproxy.go` (create registry and inject into proxy)
- Modify: `internal/api/app.go` (startLLMProxy)

**Step 1: Write the failing test**

```go
// internal/session/llmproxy_test.go (append)

func TestStartLLMProxy_CreatesRegistry(t *testing.T) {
	sess := NewSession("test-registry", "/tmp/workspace")

	proxyCfg := config.ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: "https://api.anthropic.com",
			OpenAI:    "https://api.openai.com",
		},
	}
	mcpCfg := config.SandboxMCPConfig{EnforcePolicy: true}

	storageDir := t.TempDir()

	_, closeFn, err := StartLLMProxy(sess, proxyCfg, config.DefaultDLPConfig(), config.DefaultLLMStorageConfig(), mcpCfg, storageDir, nil)
	if err != nil {
		t.Fatalf("StartLLMProxy: %v", err)
	}
	defer closeFn()

	// Session should have a registry when MCP policy is enforced
	if sess.MCPRegistry() == nil {
		t.Error("expected MCPRegistry to be set on session")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/session/ -run TestStartLLMProxy_CreatesRegistry -v`
Expected: FAIL — `MCPRegistry()` method doesn't exist.

**Step 3: Write minimal implementation**

1. Add to `Session` struct in `manager.go`:
```go
mcpRegistry interface{} // *mcpregistry.Registry — stored as interface to avoid import cycle
```

2. Add getter/setter:
```go
// SetMCPRegistry stores the MCP tool registry for this session.
func (s *Session) SetMCPRegistry(r interface{}) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.mcpRegistry = r
}

// MCPRegistry returns the MCP tool registry for this session.
func (s *Session) MCPRegistry() interface{} {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.mcpRegistry
}
```

3. In `StartLLMProxy` (after creating the proxy), create the registry and inject it:

```go
// Create MCP registry and inject into proxy if MCP policy is configured
if mcpCfg.EnforcePolicy {
    registry := mcpregistry.NewRegistry()
    proxy.SetRegistry(registry)
    sess.SetMCPRegistry(registry)
}
```

Add `mcpregistry` import to `session/llmproxy.go`.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/session/ -run TestStartLLMProxy_CreatesRegistry -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `go test ./...`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add internal/session/manager.go internal/session/llmproxy.go
git commit -m "feat(session): create MCP registry at session startup and inject into proxy"
```

---

### Task 8: OpenAI response rewriting tests

Ensure the OpenAI response rewriting path works correctly (Task 2 implemented it but we tested Anthropic primarily).

**Files:**
- Modify: `internal/llmproxy/mcp_intercept_test.go` (add OpenAI-specific rewriting tests)

**Step 1: Write the test**

```go
// internal/llmproxy/mcp_intercept_test.go (append)

func TestInterceptMCPToolCalls_OpenAI_BlockedToolRewritten(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	registry.Register("tools-server", "http", "mcp.example.com:443", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
		DeniedTools: []config.MCPToolRule{
			{Server: "*", Tool: "get_weather"},
		},
	}
	policyEval := mcpinspect.NewPolicyEvaluator(mcpCfg)

	body := []byte(`{
		"id": "chatcmpl-123",
		"choices": [{
			"index": 0,
			"finish_reason": "tool_calls",
			"message": {
				"role": "assistant",
				"content": null,
				"tool_calls": [{
					"id": "call_abc",
					"type": "function",
					"function": {"name": "get_weather", "arguments": "{\"location\": \"SF\"}"}
				}]
			}
		}]
	}`)

	result := interceptMCPToolCalls(body, DialectOpenAI, registry, policyEval, "req_test", "sess_test")

	if !result.HasBlocked {
		t.Fatal("expected HasBlocked")
	}
	if result.RewrittenBody == nil {
		t.Fatal("expected rewritten body")
	}

	var rewritten struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(result.RewrittenBody, &rewritten); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rewritten.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(rewritten.Choices))
	}
	if rewritten.Choices[0].FinishReason != "stop" {
		t.Errorf("expected finish_reason 'stop', got %q", rewritten.Choices[0].FinishReason)
	}
	if !strings.Contains(rewritten.Choices[0].Message.Content, "blocked by policy") {
		t.Errorf("expected blocked message, got %q", rewritten.Choices[0].Message.Content)
	}
}

func TestInterceptMCPToolCalls_PartialBlock(t *testing.T) {
	// Two tools, only one blocked — the other should pass through
	registry := mcpregistry.NewRegistry()
	registry.Register("server-a", "http", "a.example.com:443", []mcpregistry.ToolInfo{
		{Name: "safe_tool", Hash: "aaa"},
		{Name: "dangerous_tool", Hash: "bbb"},
	})

	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
		DeniedTools:   []config.MCPToolRule{
			{Server: "*", Tool: "dangerous_tool"},
		},
	}
	policyEval := mcpinspect.NewPolicyEvaluator(mcpCfg)

	body := []byte(`{
		"stop_reason": "tool_use",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "safe_tool", "input": {}},
			{"type": "tool_use", "id": "toolu_02", "name": "dangerous_tool", "input": {}}
		]
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, registry, policyEval, "req_test", "sess_test")

	if !result.HasBlocked {
		t.Error("expected HasBlocked for partial block")
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(result.Events))
	}

	// First event should be allow, second block
	if result.Events[0].Action != "allow" {
		t.Errorf("expected first event 'allow', got %q", result.Events[0].Action)
	}
	if result.Events[1].Action != "block" {
		t.Errorf("expected second event 'block', got %q", result.Events[1].Action)
	}

	// Rewritten body should keep safe_tool but replace dangerous_tool
	if result.RewrittenBody == nil {
		t.Fatal("expected rewritten body")
	}
	var rewritten struct {
		Content []struct {
			Type string `json:"type"`
			Name string `json:"name,omitempty"`
			Text string `json:"text,omitempty"`
		} `json:"content"`
	}
	if err := json.Unmarshal(result.RewrittenBody, &rewritten); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rewritten.Content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(rewritten.Content))
	}
	if rewritten.Content[0].Type != "tool_use" || rewritten.Content[0].Name != "safe_tool" {
		t.Errorf("expected safe_tool to pass through, got: %+v", rewritten.Content[0])
	}
	if rewritten.Content[1].Type != "text" || !strings.Contains(rewritten.Content[1].Text, "blocked") {
		t.Errorf("expected blocked text for dangerous_tool, got: %+v", rewritten.Content[1])
	}
}
```

**Step 2: Run tests**

Run: `go test ./internal/llmproxy/ -run "TestInterceptMCPToolCalls_OpenAI_BlockedToolRewritten|TestInterceptMCPToolCalls_PartialBlock" -v`
Expected: PASS (implementation from Task 2 should handle these).

**Step 3: Fix any failures**

If partial-block rewriting needs adjustment (e.g., the Anthropic rewriter changes `stop_reason` even when some tool calls are still allowed), fix the logic: only change `stop_reason` to `end_turn` when **all** tool_use blocks are blocked. If some remain, keep `stop_reason: "tool_use"`.

**Step 4: Commit**

```bash
git add internal/llmproxy/mcp_intercept_test.go
git commit -m "test(llmproxy): add OpenAI rewriting and partial-block interception tests"
```

---

### Task 9: Verify cross-compilation and run full test suite

Final verification that everything compiles and tests pass across platforms.

**Step 1: Run full test suite**

Run: `go test ./...`
Expected: All tests pass.

**Step 2: Verify Windows cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: Build succeeds.

**Step 3: Verify Darwin cross-compilation**

Run: `GOOS=darwin go build ./...`
Expected: Build succeeds.

**Step 4: Commit any final fixes**

If any cross-compilation issues arise, fix them and commit.

---

## Summary

| Task | What it does | Files |
|------|-------------|-------|
| 1 | Add MCP fields to proxy Config/Proxy struct | `proxy.go`, `mcp_intercept_test.go` |
| 2 | Core interception logic + response rewriting | `mcp_intercept.go`, `mcp_intercept_test.go` |
| 3 | Wire interception into ModifyResponse | `proxy.go`, `mcp_intercept_test.go` |
| 4 | SSE streaming tool call extraction | `mcp_streaming.go`, `mcp_streaming_test.go` |
| 5 | Wire SSE extraction into onComplete callback | `proxy.go`, `mcp_intercept.go`, `mcp_intercept_test.go` |
| 6 | Wire `mcp-only` mode into session startup | `core.go`, `app.go`, `session/llmproxy.go` |
| 7 | Create registry at session startup | `manager.go`, `session/llmproxy.go` |
| 8 | OpenAI + partial-block rewriting tests | `mcp_intercept_test.go` |
| 9 | Final cross-compilation and test verification | — |

**What this plan does NOT cover (future work):**
- **Real-time SSE stream termination**: Stopping an SSE stream mid-flight when a blocked tool is detected. This requires replacing `io.Copy` with a chunk-level scanner that can abort. The current design does audit-only for SSE (the tool call is logged as blocked but the stream has already been sent).
- **Event persistence**: Writing `MCPToolCallInterceptedEvent` to the event store (SQLite/JSONL). Currently events are only logged via `slog`. Persisting to the event store requires passing a store reference into the proxy.
- **Phase 7 (Network Monitor)**: Publishing server addresses from the registry to the network monitor.
