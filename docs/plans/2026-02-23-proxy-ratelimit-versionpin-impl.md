# Proxy Rate Limiting & Version Pinning Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the existing `RateLimiterRegistry` and version pinning into the LLM proxy's tool call evaluation path so both non-SSE and SSE interception enforce rate limits and detect tool hash changes.

**Architecture:** Extend `mcpregistry.Registry` with a `pinnedHashes` map to remember first-seen tool hashes. Add `*mcpinspect.RateLimiterRegistry` to the proxy struct. Insert both checks into the evaluation pipeline between cross-server detection and policy evaluation: cross-server → rate limit → version pin → policy.

**Tech Stack:** Go, existing `mcpinspect.RateLimiterRegistry`, existing `mcpregistry.Registry`, existing `config.SandboxMCPConfig`

---

### Task 1: Add pinned hash tracking to mcpregistry.Registry

**Files:**
- Modify: `internal/mcpregistry/registry.go`
- Modify: `internal/mcpregistry/registry_test.go`

**Context:** The `Registry` struct currently maps tool names to `ToolEntry` (with `ToolHash`), but when a tool re-registers with a new hash the old one is lost. We need to remember the first-seen hash per tool name so the proxy can detect version changes.

**Step 1: Write the failing tests**

Add these tests to `internal/mcpregistry/registry_test.go`:

```go
func TestPinnedHash_FirstRegistration(t *testing.T) {
	r := NewRegistry()
	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	hash, pinned := r.PinnedHash("get_weather")
	if !pinned {
		t.Fatal("expected tool to be pinned after first registration")
	}
	if hash != "abc123" {
		t.Errorf("PinnedHash = %q, want %q", hash, "abc123")
	}
}

func TestPinnedHash_HashChangePreservesPinned(t *testing.T) {
	r := NewRegistry()
	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "get_weather", Hash: "hash-v1"},
	})

	// Re-register with a different hash (different server or updated tool).
	r.Register("server-2", "http", "host:443", []ToolInfo{
		{Name: "get_weather", Hash: "hash-v2"},
	})

	hash, pinned := r.PinnedHash("get_weather")
	if !pinned {
		t.Fatal("expected tool to still be pinned")
	}
	if hash != "hash-v1" {
		t.Errorf("PinnedHash = %q, want %q (original)", hash, "hash-v1")
	}

	// Current entry should have the new hash.
	entry := r.Lookup("get_weather")
	if entry.ToolHash != "hash-v2" {
		t.Errorf("Lookup ToolHash = %q, want %q (current)", entry.ToolHash, "hash-v2")
	}
}

func TestPinnedHash_RemoveDoesNotClearPin(t *testing.T) {
	r := NewRegistry()
	r.Register("server-1", "stdio", "", []ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
	})

	r.Remove("server-1")

	// Pinned hash should survive server removal.
	hash, pinned := r.PinnedHash("get_weather")
	if !pinned {
		t.Fatal("pinned hash should survive Remove")
	}
	if hash != "abc123" {
		t.Errorf("PinnedHash = %q, want %q", hash, "abc123")
	}
}

func TestPinnedHash_UnknownTool(t *testing.T) {
	r := NewRegistry()
	_, pinned := r.PinnedHash("nonexistent")
	if pinned {
		t.Error("PinnedHash should return false for unknown tool")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/mcpregistry/ -run TestPinnedHash -v`
Expected: FAIL — `PinnedHash` method does not exist.

**Step 3: Implement pinned hash tracking**

In `internal/mcpregistry/registry.go`:

1. Add `pinnedHashes map[string]string` field to `Registry` struct (after `addrs` field, line 49):

```go
pinnedHashes map[string]string // toolName -> first-seen hash (for version pinning)
```

2. Initialize it in `NewRegistry()` (line 61, alongside other map inits):

```go
pinnedHashes: make(map[string]string),
```

3. In `Register()`, inside the `for _, t := range tools` loop (after the `r.tools[t.Name] = &ToolEntry{...}` block, around line 113), pin the hash on first sight:

```go
if _, alreadyPinned := r.pinnedHashes[t.Name]; !alreadyPinned {
	r.pinnedHashes[t.Name] = t.Hash
}
```

4. Add the `PinnedHash` method after `ServerAddrs()`:

```go
// PinnedHash returns the first-seen hash for a tool name and whether it was
// pinned. The pinned hash never changes once set, even if the tool is removed
// and re-registered with a different hash. Used by the proxy for version
// pinning enforcement.
func (r *Registry) PinnedHash(toolName string) (hash string, pinned bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hash, pinned = r.pinnedHashes[toolName]
	return
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/mcpregistry/ -v`
Expected: ALL PASS (new tests + existing tests).

**Step 5: Commit**

```bash
git add internal/mcpregistry/registry.go internal/mcpregistry/registry_test.go
git commit -m "feat(mcpregistry): add pinned hash tracking for version pinning"
```

---

### Task 2: Wire rate limiter into the proxy struct and non-SSE path

**Files:**
- Modify: `internal/llmproxy/proxy.go`
- Modify: `internal/llmproxy/mcp_intercept.go`
- Modify: `internal/llmproxy/mcp_intercept_test.go` (or relevant test file)

**Context:** The proxy has `policy *mcpinspect.PolicyEvaluator` created in `New()`. We follow the same pattern for `rateLimiter`. The `interceptMCPToolCalls` function currently takes `(body, dialect, registry, policy, requestID, sessionID, optAnalyzer...)`. We add `rateLimiter` and `versionPinCfg` parameters.

**Evaluation order inside `interceptMCPToolCalls` for each tool call:**
1. Registry lookup (existing)
2. Cross-server check (existing)
3. **Rate limit check (NEW)** — if cross-server didn't block
4. **Version pin check (NEW)** — if rate limit didn't block
5. Policy evaluation (existing) — if nothing above blocked

**Step 1: Write the failing tests**

Add to `internal/llmproxy/mcp_intercept_test.go` (or the appropriate test file — find where `TestIntercept` tests live):

```go
func TestInterceptRateLimitBlocks(t *testing.T) {
	// Create a rate limiter with 0 RPM (blocks everything).
	rlCfg := config.MCPRateLimitsConfig{
		Enabled:      true,
		DefaultRPM:   0,
		DefaultBurst: 0,
	}
	rateLimiter := mcpinspect.NewRateLimiterRegistry(rlCfg)

	registry := mcpregistry.NewRegistry()
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "h1"},
	})

	// Policy that would allow everything.
	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	// Anthropic response with a tool_use block.
	body := []byte(`{
		"id": "msg_1",
		"type": "message",
		"role": "assistant",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {}}
		],
		"stop_reason": "tool_use"
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, registry, policy,
		"req-1", "sess-1", nil, rateLimiter, nil)

	if !result.HasBlocked {
		t.Fatal("expected rate limit to block the tool call")
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	if result.Events[0].Action != "block" {
		t.Errorf("event Action = %q, want %q", result.Events[0].Action, "block")
	}
	if !strings.Contains(result.Events[0].Reason, "rate limit") {
		t.Errorf("event Reason = %q, want to contain 'rate limit'", result.Events[0].Reason)
	}
}

func TestInterceptVersionPinBlock(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	// First registration pins hash "hash-v1".
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v1"},
	})
	// Re-register with changed hash.
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v2"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	vpCfg := &config.MCPVersionPinningConfig{
		Enabled:  true,
		OnChange: "block",
	}

	body := []byte(`{
		"id": "msg_1",
		"type": "message",
		"role": "assistant",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {}}
		],
		"stop_reason": "tool_use"
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, registry, policy,
		"req-1", "sess-1", nil, nil, vpCfg)

	if !result.HasBlocked {
		t.Fatal("expected version pin to block the tool call")
	}
	if !strings.Contains(result.Events[0].Reason, "hash changed") {
		t.Errorf("event Reason = %q, want to contain 'hash changed'", result.Events[0].Reason)
	}
}

func TestInterceptVersionPinAlert(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v1"},
	})
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v2"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	vpCfg := &config.MCPVersionPinningConfig{
		Enabled:  true,
		OnChange: "alert",
	}

	body := []byte(`{
		"id": "msg_1",
		"type": "message",
		"role": "assistant",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {}}
		],
		"stop_reason": "tool_use"
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, registry, policy,
		"req-1", "sess-1", nil, nil, vpCfg)

	// Alert mode should NOT block.
	if result.HasBlocked {
		t.Fatal("expected alert mode to allow the tool call")
	}
	// But should emit an event with the alert reason.
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}
	if !strings.Contains(result.Events[0].Reason, "hash changed") {
		t.Errorf("event Reason = %q, want to contain 'hash changed'", result.Events[0].Reason)
	}
}

func TestInterceptVersionPinDisabled(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v1"},
	})
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v2"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	// Version pinning disabled — hash change should be ignored.
	vpCfg := &config.MCPVersionPinningConfig{
		Enabled:  false,
		OnChange: "block",
	}

	body := []byte(`{
		"id": "msg_1",
		"type": "message",
		"role": "assistant",
		"content": [
			{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {}}
		],
		"stop_reason": "tool_use"
	}`)

	result := interceptMCPToolCalls(body, DialectAnthropic, registry, policy,
		"req-1", "sess-1", nil, nil, vpCfg)

	if result.HasBlocked {
		t.Fatal("expected disabled version pinning to allow the tool call")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/llmproxy/ -run "TestInterceptRateLimit|TestInterceptVersionPin" -v`
Expected: FAIL — wrong number of arguments to `interceptMCPToolCalls`.

**Step 3: Update `interceptMCPToolCalls` signature**

In `internal/llmproxy/mcp_intercept.go`, change the function signature from:

```go
func interceptMCPToolCalls(
	body []byte,
	dialect Dialect,
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	requestID, sessionID string,
	optAnalyzer ...*mcpinspect.SessionAnalyzer,
) *InterceptResult {
```

to:

```go
func interceptMCPToolCalls(
	body []byte,
	dialect Dialect,
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	requestID, sessionID string,
	analyzer *mcpinspect.SessionAnalyzer,
	rateLimiter *mcpinspect.RateLimiterRegistry,
	versionPinCfg *config.MCPVersionPinningConfig,
) *InterceptResult {
```

Note: we change `optAnalyzer ...` to explicit `analyzer *mcpinspect.SessionAnalyzer` to make room for the new params. This means updating all call sites.

**Step 4: Add rate limit + version pin checks to the per-tool loop**

Inside the `for _, call := range calls` loop, after the cross-server check block and before the policy evaluation, insert:

```go
// Rate limit check (only if cross-server didn't block).
if crossServerDec == nil && rateLimiter != nil {
	if !rateLimiter.Allow(entry.ServerID, call.Name) {
		decision = mcpinspect.PolicyDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("rate limit exceeded for server %q", entry.ServerID),
		}
	}
}

// Version pin check (only if nothing above blocked).
if decision.Allowed && crossServerDec == nil && versionPinCfg != nil && versionPinCfg.Enabled {
	if pinnedHash, pinned := registry.PinnedHash(call.Name); pinned && entry.ToolHash != pinnedHash {
		switch versionPinCfg.OnChange {
		case "block":
			decision = mcpinspect.PolicyDecision{
				Allowed: false,
				Reason: fmt.Sprintf("tool %q hash changed (pinned: %s, current: %s)",
					call.Name, pinnedHash, entry.ToolHash),
			}
		case "alert":
			// Allow but set a reason for the event.
			reason = fmt.Sprintf("tool %q hash changed (pinned: %s, current: %s) [alert only]",
				call.Name, pinnedHash, entry.ToolHash)
		}
	}
}

// Policy evaluation (only if nothing above blocked).
if crossServerDec == nil && decision == (mcpinspect.PolicyDecision{}) {
	decision = policy.Evaluate(entry.ServerID, call.Name, entry.ToolHash)
}
```

Note: This replaces the existing `if crossServerDec == nil { decision = policy.Evaluate(...) }` block. The `decision == (mcpinspect.PolicyDecision{})` zero-value check determines if any prior check already set a decision.

Also update the `MarkBlocked` call to cover rate limit and version pin blocks:

```go
if !decision.Allowed && crossServerDec == nil && analyzer != nil {
	analyzer.MarkBlocked(entry.ServerID, call.Name, call.ID, requestID)
}
```

This existing line already handles it — any non-cross-server block marks the analyzer window.

**Step 5: Update all call sites**

1. In `proxy.go` (around line 345), change:
```go
result := interceptMCPToolCalls(respBody, dialect, reg, p.policy, requestID, sessionID, p.getSessionAnalyzer())
```
to:
```go
result := interceptMCPToolCalls(respBody, dialect, reg, p.policy, requestID, sessionID,
	p.getSessionAnalyzer(), p.rateLimiter, p.versionPinCfg())
```

2. Add the `rateLimiter` field to `Proxy` struct and the `versionPinCfg` helper:

In `proxy.go`, add field after `sessionAnalyzer`:
```go
rateLimiter *mcpinspect.RateLimiterRegistry
```

In `New()`, after `policy: newPolicyEvaluator(cfg.MCP)`:
```go
rateLimiter: newRateLimiter(cfg.MCP),
```

Add helper functions:
```go
func newRateLimiter(mcpCfg config.SandboxMCPConfig) *mcpinspect.RateLimiterRegistry {
	if !mcpCfg.RateLimits.Enabled {
		return nil
	}
	return mcpinspect.NewRateLimiterRegistry(mcpCfg.RateLimits)
}

func (p *Proxy) versionPinCfg() *config.MCPVersionPinningConfig {
	if !p.cfg.MCP.VersionPinning.Enabled {
		return nil
	}
	return &p.cfg.MCP.VersionPinning
}
```

3. Update any existing test call sites that call `interceptMCPToolCalls` — they'll need the new `nil, nil` params appended (for rateLimiter and versionPinCfg when not being tested).

**Step 6: Run tests**

Run: `go test ./internal/llmproxy/ -v`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add internal/llmproxy/proxy.go internal/llmproxy/mcp_intercept.go internal/llmproxy/mcp_intercept_test.go
git commit -m "feat(llmproxy): wire rate limiter and version pinning into non-SSE path"
```

---

### Task 3: Wire rate limiter and version pinning into SSE path

**Files:**
- Modify: `internal/llmproxy/sse_intercept.go`
- Modify: `internal/llmproxy/streaming.go`
- Modify: `internal/llmproxy/proxy.go` (SSE transport setup)
- Modify: SSE test files

**Context:** The `SSEInterceptor` has a `lookupAndEvaluate` method that mirrors the non-SSE evaluation logic. We add rate limiting and version pinning there too. The `sseProxyTransport` and its `SetInterceptor` method need to pass through the new dependencies.

**Step 1: Write the failing tests**

Add to the SSE test file (find where `TestSSEInterceptor` tests live):

```go
func TestSSEInterceptor_RateLimitBlocks(t *testing.T) {
	rlCfg := config.MCPRateLimitsConfig{
		Enabled:      true,
		DefaultRPM:   0,
		DefaultBurst: 0,
	}
	rateLimiter := mcpinspect.NewRateLimiterRegistry(rlCfg)

	registry := mcpregistry.NewRegistry()
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "h1"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, ev)
	}

	interceptor := NewSSEInterceptor(
		registry, policy, DialectAnthropic,
		"sess-1", "req-1", onEvent, slog.Default(),
		nil,            // no analyzer
		rateLimiter,    // NEW
		nil,            // no version pin
	)

	// Simulate Anthropic SSE stream with a tool_use block.
	stream := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"stop_reason":null}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"get_weather","input":{}}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	var buf bytes.Buffer
	interceptor.Stream(io.NopCloser(strings.NewReader(stream)), &buf)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "block" {
		t.Errorf("event Action = %q, want %q", events[0].Action, "block")
	}
	if !strings.Contains(events[0].Reason, "rate limit") {
		t.Errorf("event Reason = %q, want to contain 'rate limit'", events[0].Reason)
	}
}

func TestSSEInterceptor_VersionPinBlock(t *testing.T) {
	registry := mcpregistry.NewRegistry()
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v1"},
	})
	registry.Register("server-1", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "hash-v2"},
	})

	policy := mcpinspect.NewPolicyEvaluator(config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "none",
	})

	vpCfg := &config.MCPVersionPinningConfig{
		Enabled:  true,
		OnChange: "block",
	}

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		events = append(events, ev)
	}

	interceptor := NewSSEInterceptor(
		registry, policy, DialectAnthropic,
		"sess-1", "req-1", onEvent, slog.Default(),
		nil,    // no analyzer
		nil,    // no rate limiter
		vpCfg,  // version pin
	)

	stream := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"stop_reason":null}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"get_weather","input":{}}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	var buf bytes.Buffer
	interceptor.Stream(io.NopCloser(strings.NewReader(stream)), &buf)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Action != "block" {
		t.Errorf("event Action = %q, want %q", events[0].Action, "block")
	}
	if !strings.Contains(events[0].Reason, "hash changed") {
		t.Errorf("event Reason = %q, want to contain 'hash changed'", events[0].Reason)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/llmproxy/ -run "TestSSEInterceptor_RateLimit|TestSSEInterceptor_VersionPin" -v`
Expected: FAIL — wrong number of arguments to `NewSSEInterceptor`.

**Step 3: Add rate limiter and version pin fields to SSEInterceptor**

In `internal/llmproxy/sse_intercept.go`:

1. Add fields to `SSEInterceptor` struct (after `logger`):
```go
rateLimiter   *mcpinspect.RateLimiterRegistry
versionPinCfg *config.MCPVersionPinningConfig
```

2. Update `NewSSEInterceptor` signature — change from variadic `optAnalyzer` to explicit params:
```go
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
```

3. Store the new fields in the constructor.

4. Update `lookupAndEvaluate` to insert rate limit and version pin checks between cross-server and policy, following the same pattern as the non-SSE path:

```go
func (s *SSEInterceptor) lookupAndEvaluate(toolName, toolCallID string) (*mcpregistry.ToolEntry, *mcpinspect.PolicyDecision, *mcpinspect.CrossServerDecision) {
	if s.registry == nil || s.policy == nil {
		return nil, nil, nil
	}

	entry := s.registry.Lookup(toolName)
	if entry == nil {
		return nil, nil, nil
	}

	// Cross-server check + record.
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
				dec := mcpinspect.PolicyDecision{
					Allowed: true,
					Reason: fmt.Sprintf("tool %q hash changed (pinned: %s, current: %s) [alert only]",
						toolName, pinnedHash, entry.ToolHash),
				}
				return entry, &dec, nil
			}
		}
	}

	// Policy evaluation.
	decision := s.policy.Evaluate(entry.ServerID, toolName, entry.ToolHash)

	if !decision.Allowed && s.analyzer != nil {
		s.analyzer.MarkBlocked(entry.ServerID, toolName, toolCallID, s.requestID)
	}

	return entry, &decision, nil
}
```

**Step 4: Update `sseProxyTransport` and `SetInterceptor`**

In `internal/llmproxy/streaming.go`:

1. Add fields to `sseProxyTransport`:
```go
rateLimiter   *mcpinspect.RateLimiterRegistry
versionPinCfg *config.MCPVersionPinningConfig
```

2. Update `SetInterceptor` to accept the new params — change variadic `optAnalyzer` to explicit:
```go
func (t *sseProxyTransport) SetInterceptor(
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	dialect Dialect,
	sessionID, requestID string,
	onEvent func(mcpinspect.MCPToolCallInterceptedEvent),
	logger *slog.Logger,
	analyzer *mcpinspect.SessionAnalyzer,
	rateLimiter *mcpinspect.RateLimiterRegistry,
	versionPinCfg *config.MCPVersionPinningConfig,
) {
```

3. In `RoundTrip`, where `NewSSEInterceptor` is called, pass the new fields through.

**Step 5: Update proxy.go SSE setup call site**

In `proxy.go`, update the `sseTransport.SetInterceptor(...)` call (around line 314) to pass the new params:

```go
sseTransport.SetInterceptor(
	reg, p.policy, dialect,
	sessionID, requestID,
	p.getEventCallback(),
	p.logger,
	p.getSessionAnalyzer(),
	p.rateLimiter,
	p.versionPinCfg(),
)
```

**Step 6: Update existing test call sites**

All existing calls to `NewSSEInterceptor` and `SetInterceptor` that used the variadic `optAnalyzer` pattern need to be updated to pass explicit `nil` for the new params. Search for `NewSSEInterceptor(` and `SetInterceptor(` in test files and add the missing params.

**Step 7: Run tests**

Run: `go test ./internal/llmproxy/ -v`
Expected: ALL PASS.

**Step 8: Commit**

```bash
git add internal/llmproxy/sse_intercept.go internal/llmproxy/streaming.go internal/llmproxy/proxy.go
git add internal/llmproxy/*_test.go
git commit -m "feat(llmproxy): wire rate limiter and version pinning into SSE path"
```

---

### Task 4: Integration test and cross-compilation verification

**Files:**
- Modify: `internal/llmproxy/proxy_test.go`

**Context:** Add one end-to-end proxy test that exercises rate limiting through the full HTTP stack (proxy → upstream → response). Also verify cross-compilation.

**Step 1: Write integration test**

Add to `internal/llmproxy/proxy_test.go`:

```go
func TestProxyRateLimitBlocksToolCall(t *testing.T) {
	// Set up a mock upstream that returns a tool_use response.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":   "msg_1",
			"type": "message",
			"role": "assistant",
			"content": []map[string]any{
				{"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": map[string]any{}},
			},
			"stop_reason": "tool_use",
		})
	}))
	defer upstream.Close()

	// Create proxy with rate limiting enabled (0 RPM = blocks everything).
	cfg := Config{
		SessionID: "test-sess",
		Proxy:     config.ProxyConfig{Port: 0},
		MCP: config.SandboxMCPConfig{
			EnforcePolicy: true,
			ToolPolicy:    "none",
			RateLimits: config.MCPRateLimitsConfig{
				Enabled:      true,
				DefaultRPM:   0,
				DefaultBurst: 0,
			},
		},
	}

	proxy, err := New(cfg, "", slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	// Register the tool.
	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "h1"},
	})
	proxy.SetRegistry(reg)

	// ... (set up upstream URL, make request through proxy, verify response has blocked tool)
	// The exact wiring depends on how existing integration tests set up the upstream —
	// follow the pattern of existing tests in proxy_test.go.
}
```

**Step 2: Run the full test suite**

Run: `go test ./internal/llmproxy/ -v -race`
Expected: ALL PASS.

**Step 3: Run cross-compilation check**

Run: `GOOS=windows go build ./...`
Expected: No errors.

Run: `go test ./internal/mcpregistry/... ./internal/mcpinspect/... ./internal/llmproxy/...`
Expected: ALL PASS.

**Step 4: Commit**

```bash
git add internal/llmproxy/proxy_test.go
git commit -m "test(llmproxy): add integration test for proxy-level rate limiting"
```
