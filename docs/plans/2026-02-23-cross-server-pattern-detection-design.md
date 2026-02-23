# Cross-Server Pattern Detection for MCP Tool Calls

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Detect and block coordinated attacks across multiple MCP servers within a session. A new `SessionAnalyzer` component maintains a sliding window of recent MCP tool calls and evaluates cross-server rules in real-time, blocking suspicious patterns before the tool call reaches the regular policy evaluator.

**Architecture:** A per-session `SessionAnalyzer` is created at session start (near-zero cost). It activates when the MCP registry detects a second distinct server registering tools. Once active, every MCP tool call is checked against four detection patterns before regular policy evaluation. The analyzer is wired into the LLM proxy hot path alongside the existing `PolicyEvaluator`.

**Tech Stack:** Go, `sync.Mutex`, existing `mcpregistry.Registry` + `mcpinspect.PolicyEvaluator`, existing event pipeline

---

## Background

The MCP security threat model (documented in `docs/mcp-security.md`, Attack Vector #5) describes cross-server orchestration attacks: when an agent connects to multiple MCP servers, a malicious server can coordinate with a legitimate server to exfiltrate data through indirect paths.

Example: Server A (`db-server`) provides `query_database` — a legitimate read tool. Server B (`evil-server`) provides `send_email`. The LLM, manipulated by prompt injection, queries sensitive data via Server A and passes it to Server B. Each individual action is policy-compliant, but the combination is malicious.

Currently, the `PolicyEvaluator` evaluates each tool call independently with no session context. Cross-server patterns are invisible.

## Decisions

- **Real-time blocking:** Cross-server rules block tool calls, not just alert. This matches the existing MCP interception model (SSE + non-SSE blocking).
- **Lazy activation:** The `SessionAnalyzer` is always created but near-zero cost until 2+ MCP servers register tools. Push activation from the Registry avoids per-call overhead.
- **Category-based rules:** Tool names are classified into abstract categories (`read`, `write`, `send`, `compute`) so rules are portable across different MCP server implementations.
- **Before policy:** Cross-server check runs before `PolicyEvaluator.Evaluate()`. If the analyzer blocks, the tool is denied regardless of per-tool rules.
- **Shadow tracking always on:** Tool collision detection doesn't require activation since `Registry.Register()` already reports overwrites. The `NotifyOverwrite()` callback works from session start.

## Tool Call Classification

Tools are classified by name pattern into categories. The classifier uses glob matching with sane defaults:

| Category | Default patterns | Meaning |
|----------|-----------------|---------|
| `read` | `read_*`, `get_*`, `query_*`, `list_*`, `fetch_*`, `search_*`, `find_*`, `lookup_*` | Accesses data |
| `write` | `write_*`, `update_*`, `set_*`, `create_*`, `delete_*`, `remove_*`, `put_*`, `insert_*` | Modifies data |
| `send` | `send_*`, `post_*`, `upload_*`, `http_*`, `email_*`, `notify_*`, `publish_*`, `push_*` | Outbound communication |
| `compute` | `run_*`, `exec_*`, `eval_*`, `execute_*`, `invoke_*`, `call_*` | Executes code |

Tools that don't match any pattern are classified as `unknown` and don't trigger category-based rules. Custom classifier overrides are out of scope for v1.

## Data Model

### ToolCallRecord — sliding window entry

```go
type ToolCallRecord struct {
    Timestamp time.Time
    ServerID  string // which MCP server
    ToolName  string // tool that was called
    RequestID string // LLM request ID (for same-turn detection)
    Action    string // "allow" or "block"
    Category  string // "read", "write", "send", "compute", "unknown"
}
```

### CrossServerDecision — output of Check()

```go
type CrossServerDecision struct {
    Blocked  bool
    Rule     string // "read_then_send", "burst", "cross_server_flow", "shadow_tool"
    Reason   string // human-readable
    Severity string // "critical", "high", "medium"
    Related  []ToolCallRecord // calls that triggered the rule
}
```

## Detection Patterns

### 1. Read-then-send (severity: critical)

**Triggers when:** Server B calls a `send`-category tool AND within the window, a different Server A called a `read`-category tool that was allowed.

**Why critical:** This is the canonical data exfiltration pattern. Server A reads data legitimately, the LLM relays it, Server B sends it out.

**Config:**
```yaml
read_then_send:
  enabled: true
  window: 30s
```

**Logic:**
```
on Check(serverID=B, toolName with category=send):
  for each record in window where category=read AND action=allow:
    if record.serverID != B:
      return BLOCK("Server 'B' attempted send after 'A' read data Ns ago")
```

### 2. Burst from single server (severity: high)

**Triggers when:** The same server makes more than `max_calls` tool calls within `window`.

**Why high:** A compromised server trying to act fast before detection, or automated abuse.

**Config:**
```yaml
burst:
  enabled: true
  max_calls: 10
  window: 5s
```

**Logic:**
```
on Check(serverID=S):
  count = calls from S in last window duration
  if count >= max_calls:
    return BLOCK("Server 'S' exceeded burst limit: N calls in Xs")
```

### 3. Cross-server data flow (severity: high)

**Triggers when:** Server A's `read` tool was called, then Server B's `write` or `send` tool is called in the same LLM turn (same `requestID`). Same-turn correlation is a strong signal because the LLM is orchestrating a pipeline within a single response.

**Config:**
```yaml
cross_server_flow:
  enabled: true
  same_turn_only: true   # only flag if in same LLM request
  window: 30s            # fallback if same_turn_only: false
```

**Logic:**
```
on Check(serverID=B, toolName with category in [write,send], requestID=R):
  for each record in window where category=read AND action=allow:
    if same_turn_only AND record.requestID != R:
      continue
    if record.serverID != B:
      return BLOCK("Cross-server data flow: 'A' read → 'B' write in same turn")
```

### 4. Shadow tool invocation (severity: critical)

**Triggers when:** A tool that was overwritten by a later server registration is called. The tool's provider changed from Server A to Server B (name collision), and now it's being invoked.

**Why critical:** This is tool shadowing exploitation — the caller thinks they're using Server A's tool but Server B intercepted the name.

**Config:**
```yaml
shadow_tool:
  enabled: true
```

**Logic:**
```
on NotifyOverwrite(toolName, oldServerID, newServerID):
  shadows[toolName] = {old: oldServerID, new: newServerID}

on Check(serverID, toolName):
  if toolName in shadows:
    return BLOCK("Tool 'X' was shadowed: originally from 'A', now served by 'B'")
```

This pattern doesn't need the sliding window or activation — it works from session start.

## SessionAnalyzer Type

New file: `internal/mcpinspect/session_analyzer.go`

```go
type SessionAnalyzer struct {
    mu         sync.Mutex
    active     bool                  // flipped by Activate()
    sessionID  string
    rules      CrossServerRules      // from config
    classifier *ToolClassifier       // tool name → category

    // Sliding window — only allocated on Activate()
    window     []ToolCallRecord
    maxWindow  time.Duration         // max age of records to keep

    // Shadow tracking — populated by NotifyOverwrite(), always active
    shadows    map[string]shadowInfo // toolName → overwrite info

    // Burst tracking — per-server call timestamps
    bursts     map[string][]time.Time // serverID → recent timestamps
}

type shadowInfo struct {
    OriginalServerID string
    NewServerID      string
}
```

### Public methods

```go
// NewSessionAnalyzer creates an inactive analyzer. Near-zero cost.
func NewSessionAnalyzer(sessionID string, cfg config.CrossServerConfig) *SessionAnalyzer

// Activate transitions the analyzer to active state. Called by the
// Registry when a 2nd distinct MCP server registers tools.
func (a *SessionAnalyzer) Activate()

// NotifyOverwrite records a tool name collision. Always works, even
// before activation. Called by Registry.Register() when it detects
// an overwrite.
func (a *SessionAnalyzer) NotifyOverwrite(toolName, oldServerID, newServerID string)

// Check evaluates cross-server rules for a pending tool call.
// Returns nil if no rule triggers (tool call is allowed to proceed
// to regular policy evaluation). Returns a decision if blocked.
// When inactive and no shadows exist, returns nil immediately.
func (a *SessionAnalyzer) Check(serverID, toolName, requestID string) *CrossServerDecision

// Record adds a completed tool call to the sliding window.
// No-op when inactive.
func (a *SessionAnalyzer) Record(rec ToolCallRecord)
```

### Activation flow

```
Session starts
  → NewSessionAnalyzer("sess-1", cfg)  [active=false, shadows=map{}]

Registry.Register("server-a", ...)
  → 1st server, no activation

Registry.Register("server-b", ...)
  → 2nd server → analyzer.Activate()
  → window=[]ToolCallRecord{}, bursts=map{}{}

Proxy intercepts tool_use "get_weather" from server-a
  → analyzer.Check("server-a", "get_weather", "req-1")
  → runs all enabled rules against window
  → returns nil (no suspicious pattern)
  → PolicyEvaluator.Evaluate() runs normally
  → tool allowed
  → analyzer.Record({ServerID: "server-a", Category: "read", ...})

Proxy intercepts tool_use "send_email" from server-b
  → analyzer.Check("server-b", "send_email", "req-1")
  → read_then_send rule: found read from server-a 2s ago → BLOCK
  → returns CrossServerDecision{Blocked: true, Rule: "read_then_send"}
  → tool blocked, event emitted
```

## Integration Points

### Registry → Analyzer (push activation + shadow notification)

In `mcpregistry/registry.go`, `Register()` already tracks distinct servers and returns `[]OverwrittenTool`. Add an optional callback:

```go
type RegistryCallbacks struct {
    OnMultiServer func()                                    // 2nd server detected
    OnOverwrite   func(toolName, oldServerID, newServerID string)
}

func (r *Registry) SetCallbacks(cb RegistryCallbacks)
```

In `Register()`:
- After adding a new server to the server set, if `len(servers) == 2`, call `cb.OnMultiServer()`.
- For each `OverwrittenTool` returned, call `cb.OnOverwrite()`.

### Proxy → Analyzer (check + record)

In `llmproxy/sse_intercept.go`, add `analyzer *SessionAnalyzer` to `SSEInterceptor`. In `lookupAndEvaluate()`:

```go
entry := s.registry.Lookup(toolName)
if entry == nil {
    return nil, nil
}

// Cross-server check (before policy)
if s.analyzer != nil {
    if block := s.analyzer.Check(entry.ServerID, toolName, s.requestID); block != nil {
        return entry, &PolicyDecision{Allowed: false, Reason: block.Reason}
    }
}

decision := s.policy.Evaluate(entry.ServerID, toolName, entry.ToolHash)
```

After the allow/block decision, call `s.analyzer.Record(...)`.

Same pattern in `mcp_intercept.go` for the non-SSE path.

### Proxy → Analyzer (wiring)

In `proxy.go`, add `SetSessionAnalyzer(*SessionAnalyzer)` alongside `SetRegistry()` and `SetEventCallback()`.

In `app.go`, create the analyzer at session start and wire it:

```go
analyzer := mcpinspect.NewSessionAnalyzer(sessionID, cfg.MCP.CrossServer)
registry.SetCallbacks(mcpregistry.RegistryCallbacks{
    OnMultiServer: analyzer.Activate,
    OnOverwrite:   analyzer.NotifyOverwrite,
})
proxy.SetSessionAnalyzer(analyzer)
```

### Event emission

When a cross-server rule blocks a call, the event is emitted through the existing event callback. The `MCPToolCallInterceptedEvent` already has `Action` and `Reason` fields — the reason will indicate the cross-server rule that triggered. A new `MCPCrossServerEvent` type provides richer detail:

```go
type MCPCrossServerEvent struct {
    Type             string            // "mcp_cross_server_blocked"
    Timestamp        time.Time
    SessionID        string
    Rule             string            // "read_then_send", "burst", etc.
    Severity         string            // "critical", "high", "medium"
    BlockedServerID  string
    BlockedToolName  string
    RelatedCalls     []ToolCallRecord
    Reason           string
}
```

Converted and persisted through the same `store.AppendEvent()` + `broker.Publish()` pipeline.

## Configuration

Extends `config.SandboxMCPConfig`:

```go
type CrossServerConfig struct {
    Enabled          bool                    `yaml:"enabled"`
    ReadThenSend     ReadThenSendConfig      `yaml:"read_then_send"`
    Burst            BurstConfig             `yaml:"burst"`
    CrossServerFlow  CrossServerFlowConfig   `yaml:"cross_server_flow"`
    ShadowTool       ShadowToolConfig        `yaml:"shadow_tool"`
}

type ReadThenSendConfig struct {
    Enabled bool          `yaml:"enabled"`
    Window  time.Duration `yaml:"window"`  // default: 30s
}

type BurstConfig struct {
    Enabled  bool          `yaml:"enabled"`
    MaxCalls int           `yaml:"max_calls"` // default: 10
    Window   time.Duration `yaml:"window"`    // default: 5s
}

type CrossServerFlowConfig struct {
    Enabled      bool          `yaml:"enabled"`
    SameTurnOnly bool          `yaml:"same_turn_only"` // default: true
    Window       time.Duration `yaml:"window"`          // default: 30s
}

type ShadowToolConfig struct {
    Enabled bool `yaml:"enabled"` // default: true
}
```

All patterns default to `enabled: true` when `cross_server.enabled` is `true`.

## Edge Cases

- **Single MCP server session:** Analyzer never activates. `Check()` returns nil immediately (one branch check). Only shadow tracking is live (near-zero cost with no overwrites).
- **Burst rule + legitimate high-throughput server:** The burst window and threshold are configurable. Operators can tune `max_calls` per deployment.
- **Read-then-send false positive:** A session where Server A reads config and Server B sends a notification is legitimate. The 30s window limits false positives. Operators can increase the window or disable the rule.
- **Window cleanup:** The sliding window is pruned on every `Record()` call — entries older than `maxWindow` are dropped. No background goroutine needed.
- **Concurrency:** All state is under a single `sync.Mutex`. The critical section is short (window scan + rule eval). No contention concern at MCP tool call rates.
- **Analyzer created but never activated:** GC'd with the session. Cost: one struct allocation.

## Performance

- **Inactive path:** One nil check + one `len(shadows)` check. Sub-nanosecond.
- **Active path, no match:** Mutex lock, window scan (typically <50 entries), 4 rule evaluations, mutex unlock. Microseconds.
- **Window size:** Bounded by time, not count. At 30s window and realistic MCP call rates (<1/s), window holds <30 entries. Linear scan is fine.
- **No allocations in hot path:** `Check()` returns nil (no match) or a stack-allocated decision. `Record()` appends to a pre-allocated slice.

## Testing

### Unit tests (`session_analyzer_test.go`)

1. **Inactive returns nil** — analyzer not activated, `Check()` always returns nil
2. **Activation allocates state** — after `Activate()`, window and bursts are initialized
3. **Read-then-send detection** — record read from A, check send from B → blocked
4. **Read-then-send same server** — record read from A, check send from A → allowed (same server)
5. **Read-then-send expired** — record read from A, wait past window, check send from B → allowed
6. **Burst detection** — 11 calls from same server in 5s → blocked
7. **Burst under threshold** — 9 calls from same server in 5s → allowed
8. **Cross-server flow same turn** — read from A and send from B with same requestID → blocked
9. **Cross-server flow different turn** — read from A and send from B with different requestID, same_turn_only=true → allowed
10. **Shadow tool detection** — `NotifyOverwrite("tool", "A", "B")`, then `Check("B", "tool")` → blocked
11. **Shadow tool before activation** — shadows work even when analyzer is inactive
12. **Window pruning** — old records are removed on `Record()`
13. **Classifier** — tool name → category mapping tests
14. **Config disabled** — `enabled: false` means `Check()` always returns nil

### Integration test (`proxy_test.go`)

15. **End-to-end read-then-send blocking** — full proxy with 2 MCP servers, first request returns allowed read tool, second request returns send tool → send blocked with cross-server event emitted

## Files

| File | Change |
|------|--------|
| `internal/mcpinspect/session_analyzer.go` | New: `SessionAnalyzer`, `ToolClassifier`, rules, `CrossServerDecision` |
| `internal/mcpinspect/session_analyzer_test.go` | New: unit tests (cases 1-14) |
| `internal/mcpinspect/events.go` | Modify: add `MCPCrossServerEvent` |
| `internal/mcpregistry/registry.go` | Modify: add `RegistryCallbacks`, call `OnMultiServer` + `OnOverwrite` |
| `internal/mcpregistry/registry_test.go` | Modify: test callback invocation |
| `internal/config/config.go` | Modify: add `CrossServerConfig` to `SandboxMCPConfig` |
| `internal/llmproxy/sse_intercept.go` | Modify: add `analyzer` field, check in `lookupAndEvaluate()`, record after decision |
| `internal/llmproxy/mcp_intercept.go` | Modify: add analyzer check + record to non-SSE path |
| `internal/llmproxy/proxy.go` | Modify: add `SetSessionAnalyzer()`, pass to SSE transport |
| `internal/llmproxy/streaming.go` | Modify: add analyzer field to `sseProxyTransport.SetInterceptor()` |
| `internal/api/app.go` | Modify: create analyzer, wire callbacks, pass to proxy |
| `internal/api/mcp_event.go` | Modify: convert `MCPCrossServerEvent` for store |
| `internal/llmproxy/proxy_test.go` | Modify: add end-to-end integration test (case 15) |
