# MCP Tool Call Interception Design

**Status:** Proposed
**Created:** 2026-02-22
**Author:** Claude + Eran
**Depends on:** `2026-01-06-mcp-tool-inspection-design.md`

## Overview

This design adds **MCP tool call detection and policy enforcement** to agentsh across three interception layers: the LLM proxy, the shell shim, and the network monitor. The existing MCP inspection system (Phase 1-4) covers tool *definitions* — it detects poisoning, rug pulls, and suspicious patterns in `tools/list` responses. This design extends coverage to tool *executions* — detecting when an MCP tool is about to be called, enforcing policy before it runs, and creating an audit trail of every invocation.

## Problem Statement

The current MCP inspection system watches `tools/list` responses to track what tools exist. But it has no visibility into when tools are actually called:

1. **The shim** detects `tools/call` messages (`MessageToolsCall` in `protocol.go`) but the inspector ignores them — the switch statement only handles `MessageToolsListResponse`.
2. **The LLM proxy** sees the LLM's `tool_use` / `tool_calls` responses (the signal that triggers MCP calls) but has zero MCP awareness — no imports, no parsing, no correlation.
3. **Network MCP servers** (HTTP/SSE) are completely invisible — the shim only wraps stdio processes, and the LLM proxy doesn't know which tools are MCP tools.

This means agentsh cannot:
- Block an MCP tool call based on policy before it executes
- Log which MCP tools were actually invoked during a session
- Distinguish MCP tool calls from native tool calls in the LLM conversation
- Detect or audit network MCP server interactions at all

## Goals

1. **Pre-execution policy enforcement**: Block MCP tool calls before they execute, for both stdio and network MCP servers
2. **Audit trail**: Log every MCP tool invocation with tool name, arguments, server identity, and policy decision
3. **Transport detection**: Distinguish stdio MCP from network MCP and know the server address for network servers
4. **Correlation**: Link the LLM's intent (tool_use response) to the actual execution (JSON-RPC call or network connection) via shared event store
5. **Streaming support**: Handle SSE streaming responses without buffering the entire stream

## Non-Goals

- Modifying MCP protocol messages in-flight (beyond stripping blocked tool_use blocks)
- Supporting MCP servers discovered at runtime without session config (future work)
- Decrypting TLS traffic to inspect MCP protocol over HTTPS (we use address-level detection)

## Design Decisions (from brainstorming)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Interception model** | Three layers (proxy + shim + netmonitor) | Each layer covers a different gap; no single point sees everything |
| **MCP tool identification** | Active registry populated at session startup | Tool names have no universal MCP naming convention; heuristics are unreliable |
| **Policy enforcement point** | LLM proxy (primary), network monitor (defense in depth) | Proxy sees tool calls before agent does; network layer is a fallback |
| **Streaming handling** | Inspect SSE chunks for tool name (arrives early) | Both Anthropic and OpenAI send tool name in the first chunk; no full-stream buffering needed |
| **Registry storage** | In-memory map (hot path) backed by SQLite mcp_tools table (persistence) | Fast lookups on every LLM response; durable across restarts |

## Architecture

### Three-Layer Interception

```
                    ┌──────────────────┐
                    │    LLM API       │
                    │ (Anthropic/OpenAI)│
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │   LLM Proxy      │  Layer 2: Parses tool_use/tool_calls
                    │  (llmproxy/)     │  from LLM responses. Registry lookup.
                    │                  │  Policy enforcement. Event emission.
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │   Agent          │
                    │  (Claude Code,   │
                    │   Cursor, etc.)  │
                    └───┬──────────┬───┘
                        │          │
            ┌───────────▼──┐  ┌───▼────────────┐
            │ Stdio MCP    │  │ Network MCP     │
            │ Server       │  │ Server          │
            │              │  │                 │
            │ ┌──────────┐ │  │ mcp.example.com │
            │ │  Shim    │ │  └───────▲─────────┘
            │ │ Layer 1  │ │          │
            │ └──────────┘ │   ┌──────┴──────┐
            └──────────────┘   │  Network    │  Layer 3: Watches outbound
                               │  Monitor   │  connections to known MCP
                               │  Layer 3   │  server addresses.
                               └─────────────┘
```

### Event Timeline for a Single MCP Tool Call

**Network MCP:**
```
t=0ms   mcp_tool_call_intercepted   (LLM proxy parsed tool_use from LLM response)
t=5ms   mcp_network_connection      (network monitor saw outbound to MCP server addr)
```

**Stdio MCP:**
```
t=0ms   mcp_tool_call_intercepted   (LLM proxy parsed tool_use from LLM response)
t=5ms   mcp_tool_called             (shim saw tools/call JSON-RPC on server stdin)
```

## MCP Tool Registry

The registry is the central data structure shared by all three layers. It maps tool names to MCP server identity and connection details.

### Data Model

```go
// internal/mcpregistry/registry.go

// Registry maps tool names to their MCP server metadata.
type Registry struct {
    mu    sync.RWMutex
    tools map[string]*ToolEntry // keyed by tool name
    addrs map[string]string     // server addr → server ID (for network monitor)
}

// ToolEntry describes a single MCP tool and the server that provides it.
type ToolEntry struct {
    ToolName     string
    ServerID     string
    ServerType   string    // "stdio" | "http" | "sse"
    ServerAddr   string    // "" for stdio, "host:port" for network
    ToolHash     string
    RegisteredAt time.Time
}
```

### Registration Methods

```go
// Register adds tools from a server. Called at session startup and when
// mcp_tool_seen events arrive.
func (r *Registry) Register(serverID, serverType, serverAddr string, tools []ToolEntry)

// Lookup returns the registry entry for a tool name, or nil if not found.
// Used by the LLM proxy on every tool_use block.
func (r *Registry) Lookup(toolName string) *ToolEntry

// LookupBatch returns entries for multiple tool names at once.
// Used when an LLM response contains parallel tool calls.
func (r *Registry) LookupBatch(toolNames []string) map[string]*ToolEntry

// ServerAddrs returns all known network MCP server addresses.
// Used by the network monitor to build its watch list.
func (r *Registry) ServerAddrs() map[string]string // addr → serverID
```

### Population Flow

**Stdio MCP servers:**
1. Shim wraps MCP server process (detected via `IsMCPServer` patterns)
2. Inspector sees `tools/list` response, emits `mcp_tool_seen` events
3. Server receives events, calls `registry.Register(serverID, "stdio", "", tools)`

**Network MCP servers:**
1. Session config declares MCP server URLs
2. Session manager connects to each server, sends `tools/list`
3. Receives tool definitions, calls `registry.Register(serverID, "http", "host:port", tools)`
4. Publishes server addresses to network monitor watch list

## Event Types

### mcp_tool_call_intercepted (LLM Proxy)

Emitted when the LLM proxy detects a tool_use/tool_calls block that matches a registered MCP tool.

```go
// internal/mcpinspect/events.go

type MCPToolCallInterceptedEvent struct {
    Type        string          `json:"type"`         // "mcp_tool_call_intercepted"
    Timestamp   time.Time       `json:"timestamp"`
    SessionID   string          `json:"session_id"`
    RequestID   string          `json:"request_id"`   // LLM proxy request ID
    Dialect     string          `json:"dialect"`       // "anthropic" | "openai"

    // From LLM response
    ToolName    string          `json:"tool_name"`
    ToolCallID  string          `json:"tool_call_id"`  // "toolu_..." or "call_..."
    Input       json.RawMessage `json:"input"`

    // From registry lookup
    ServerID    string          `json:"server_id"`
    ServerType  string          `json:"server_type"`   // "stdio" | "http" | "sse"
    ServerAddr  string          `json:"server_addr,omitempty"`
    ToolHash    string          `json:"tool_hash"`

    // Policy decision
    Action      string          `json:"action"`        // "allow" | "block"
    Reason      string          `json:"reason,omitempty"`
}
```

### mcp_tool_called (Shim — stdio only)

Emitted when the shim sees an actual `tools/call` JSON-RPC request on the MCP server's stdin.

```go
type MCPToolCalledEvent struct {
    Type      string          `json:"type"`      // "mcp_tool_called"
    Timestamp time.Time       `json:"timestamp"`
    SessionID string          `json:"session_id"`
    ServerID  string          `json:"server_id"`

    // From JSON-RPC request
    ToolName  string          `json:"tool_name"`
    JSONRPCID json.RawMessage `json:"jsonrpc_id"`
    Input     json.RawMessage `json:"input"`
}
```

### mcp_network_connection (Network Monitor — network only)

Emitted when the network monitor sees an outbound connection to a known MCP server address.

```go
type MCPNetworkConnectionEvent struct {
    Type       string    `json:"type"`        // "mcp_network_connection"
    Timestamp  time.Time `json:"timestamp"`
    SessionID  string    `json:"session_id"`

    // Connection info
    RemoteAddr string    `json:"remote_addr"` // "host:port"
    ServerID   string    `json:"server_id"`   // from registry lookup
    ServerType string    `json:"server_type"`

    // Policy decision
    Action     string    `json:"action"`      // "allow" | "block"
}
```

### Event Correlation

All three events share `session_id`. A query like "show me everything about tool call X" joins on:
- `session_id` + `tool_name` + approximate timestamp (within ~100ms window)
- `mcp_tool_call_intercepted.server_id` == `mcp_tool_called.server_id` (stdio)
- `mcp_tool_call_intercepted.server_addr` == `mcp_network_connection.remote_addr` (network)

## LLM Proxy Response Parsing

### Non-Streaming Responses

The proxy already reads and buffers the full response body in `logResponse` (`proxy.go:309`). After reading the body, we parse it for tool calls:

```go
// internal/llmproxy/mcp_intercept.go

// ExtractToolCalls parses tool call blocks from an LLM response body.
func ExtractToolCalls(body []byte, dialect Dialect) []ToolCall {
    switch dialect {
    case DialectAnthropic:
        return extractAnthropicToolCalls(body)
    case DialectOpenAI:
        return extractOpenAIToolCalls(body)
    }
    return nil
}

// ToolCall represents a tool invocation extracted from an LLM response.
type ToolCall struct {
    ID    string          // "toolu_..." or "call_..."
    Name  string          // tool name
    Input json.RawMessage // arguments
}
```

**Anthropic format** — look for `stop_reason: "tool_use"` and content blocks with `type: "tool_use"`:

```go
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
            calls = append(calls, ToolCall{ID: block.ID, Name: block.Name, Input: block.Input})
        }
    }
    return calls
}
```

**OpenAI format** — look for `finish_reason: "tool_calls"` and the `tool_calls` array:

```go
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
```

### Streaming (SSE) Responses

Both Anthropic and OpenAI send the tool name early in the stream, before the arguments are fully streamed:

**Anthropic** — tool name is in the `content_block_start` event:
```
event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_...","name":"get_weather","input":{}}}
```

**OpenAI** — function name is in the first tool_calls delta chunk:
```
data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_...","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}
```

The existing `sseProxyTransport` in `llmproxy/` already processes SSE events. We add a hook that inspects each SSE chunk:

1. Parse the SSE `data:` line
2. Check for tool call signals (content_block_start with type=tool_use, or delta with tool_calls)
3. Extract tool name
4. Registry lookup + policy check
5. If blocked: stop forwarding SSE events, send a terminal event to the agent

This requires **no full-stream buffering** — we make the policy decision as soon as the tool name arrives.

## Proxy Configuration: Passthrough Mode

The LLM proxy currently couples two concerns: DLP (redaction/tokenization) and request/response logging. For MCP tool call interception, some deployments want the proxy to capture traffic and enforce MCP policy *without* running DLP processing.

### Existing DLP Modes

DLP already supports `mode: "disabled"` (in `llmproxy/dlp.go:96`), which skips all pattern matching. This means the proxy can already run without redaction. However, there's no explicit "passthrough" concept that makes this intent clear in config.

### New Proxy Mode: `mcp-only`

Add a new proxy mode alongside the existing `embedded` mode:

```yaml
# Existing: full proxy with DLP + MCP interception
proxy:
  mode: embedded
dlp:
  mode: redact

# New: proxy captures traffic and enforces MCP policy, no DLP
proxy:
  mode: mcp-only    # Implies dlp.mode: disabled, llm_storage.store_bodies: true
```

When `mode: mcp-only`:
- DLP processing is skipped entirely (equivalent to `dlp.mode: disabled`)
- Request/response bodies are stored (for audit and MCP tool call extraction)
- MCP tool call interception is active (registry lookup, policy enforcement, events)
- Minimal latency overhead — no regex scanning of bodies

```go
// internal/config/proxy.go

type ProxyConfig struct {
    Mode      string               `yaml:"mode"`      // "embedded" | "mcp-only" | "disabled"
    Port      int                  `yaml:"port"`
    Providers ProxyProvidersConfig `yaml:"providers"`
}

// IsMCPOnly returns true if the proxy runs in MCP-interception-only mode.
func (c ProxyConfig) IsMCPOnly() bool {
    return c.Mode == "mcp-only"
}
```

In the proxy startup path, when `mcp-only` mode is detected:
- Force DLP to disabled
- Force body storage on (needed to parse tool calls from responses)
- Enable MCP interception hooks

This keeps the config simple for the common case: "I just want MCP security, I don't need DLP."

## MCP Server Policy Configuration

The existing `SandboxMCPConfig` (`config.go:499`) has `AllowedTools` and `DeniedTools` with `MCPToolRule` structs that match on server + tool + hash. This works for tool-level rules but lacks:

1. **Server-level allow/deny** — "block all tools from server X" without listing each tool
2. **Network MCP server identity** — server rules reference `server_id` but don't declare server addresses
3. **MCP server declarations** — nowhere to define what MCP servers exist and how to reach them

### Extended Configuration

```yaml
sandbox:
  mcp:
    enforce_policy: true
    fail_closed: true           # Block unknown tools/servers

    # Server declarations — the source of truth for the registry
    servers:
      - id: filesystem
        type: stdio
        command: npx
        args: ["@modelcontextprotocol/server-filesystem", "/home/user"]

      - id: weather-api
        type: http
        url: https://mcp.example.com/sse

      - id: internal-tools
        type: http
        url: https://mcp.internal.corp:8443/mcp
        # Optional: pin expected TLS fingerprint
        tls_fingerprint: "sha256:abc123..."

    # Server-level policy: which servers are allowed at all
    server_policy: allowlist     # "allowlist" | "denylist" | "none"
    allowed_servers:
      - id: filesystem
      - id: weather-api
    denied_servers:
      - id: "*"                  # Deny everything not explicitly allowed

    # Tool-level policy (existing, extended)
    tool_policy: denylist
    allowed_tools:
      - server: "*"
        tool: "*"               # Allow all tools by default
    denied_tools:
      - server: weather-api
        tool: "delete_*"        # Block destructive tools from weather API
      - server: "*"
        tool: "execute_command" # Block dangerous tool names from any server

    # Version pinning (existing)
    version_pinning:
      enabled: true
      on_change: block
      auto_trust_first: true

    # Rate limits (existing)
    rate_limits:
      enabled: true
      default_rpm: 60
      per_server:
        weather-api:
          calls_per_minute: 10
          burst: 3
```

### New Config Types

```go
// internal/config/config.go

// MCPServerDeclaration defines an MCP server and how to connect to it.
type MCPServerDeclaration struct {
    ID             string   `yaml:"id"`
    Type           string   `yaml:"type"`            // "stdio" | "http" | "sse"
    Command        string   `yaml:"command"`          // For stdio
    Args           []string `yaml:"args"`             // For stdio
    URL            string   `yaml:"url"`              // For http/sse
    TLSFingerprint string   `yaml:"tls_fingerprint"`  // Optional cert pin
}

// MCPServerRule matches servers by ID (supports "*" wildcard).
type MCPServerRule struct {
    ID string `yaml:"id"`
}
```

Extended `SandboxMCPConfig`:

```go
type SandboxMCPConfig struct {
    EnforcePolicy  bool                    `yaml:"enforce_policy"`
    FailClosed     bool                    `yaml:"fail_closed"`

    // Server declarations
    Servers        []MCPServerDeclaration  `yaml:"servers"`

    // Server-level policy
    ServerPolicy   string                  `yaml:"server_policy"`   // allowlist, denylist, none
    AllowedServers []MCPServerRule         `yaml:"allowed_servers"`
    DeniedServers  []MCPServerRule         `yaml:"denied_servers"`

    // Tool-level policy (existing)
    ToolPolicy     string                  `yaml:"tool_policy"`
    AllowedTools   []MCPToolRule           `yaml:"allowed_tools"`
    DeniedTools    []MCPToolRule           `yaml:"denied_tools"`

    // Existing
    VersionPinning MCPVersionPinningConfig `yaml:"version_pinning"`
    RateLimits     MCPRateLimitsConfig     `yaml:"rate_limits"`
}
```

### Policy Evaluation Order

When the LLM proxy intercepts a tool call and finds it in the registry:

```
1. Server-level check
   ├─ Is the server in denied_servers? → BLOCK
   ├─ server_policy == "allowlist" && server NOT in allowed_servers? → BLOCK
   └─ Pass

2. Tool-level check
   ├─ Does tool match any denied_tools rule? → BLOCK
   ├─ tool_policy == "allowlist" && tool NOT in allowed_tools? → BLOCK
   └─ Pass

3. Version pinning check
   ├─ Is version_pinning enabled?
   ├─ Does tool hash match pinned hash?
   ├─ If changed: on_change == "block" → BLOCK, "alert" → ALLOW + emit event
   └─ Pass

4. Rate limit check
   ├─ Is rate_limits enabled?
   ├─ Has server/tool exceeded calls_per_minute?
   └─ If exceeded → BLOCK

5. Result: ALLOW (emit event with action: "allow")
```

### Fail-Closed Behavior

When `fail_closed: true`:
- Tools NOT in the registry (unknown MCP tools) are blocked
- Servers NOT declared in config are blocked
- This protects against dynamic MCP server injection or undeclared servers

When `fail_closed: false` (default):
- Unknown tools pass through (assume they're native, not MCP)
- Only explicitly denied tools/servers are blocked

## Policy Enforcement

### Decision Matrix

| Registry Match | Policy Result | Action |
|---|---|---|
| MCP tool, server allowed, tool allowed, hash matches | Pass through | Emit event with `action: "allow"` |
| MCP tool, server denied | Strip/terminate | Emit event with `action: "block", reason: "server denied"` |
| MCP tool, tool denied | Strip/terminate | Emit event with `action: "block", reason: "tool denied"` |
| MCP tool, hash mismatch | Block (rug pull) | Emit `mcp_tool_changed` + `action: "block"` |
| MCP tool, rate limit exceeded | Strip/terminate | Emit event with `action: "block", reason: "rate limit"` |
| Not in registry, fail_closed=true | Strip/terminate | Emit event with `action: "block", reason: "unknown tool, fail closed"` |
| Not in registry, fail_closed=false | Pass through | No event (assume native tool) |

### Blocking Mechanism

**Non-streaming:** Replace the `tool_use` content block with a text block and change `stop_reason` to `"end_turn"`:

```json
// Before (LLM response):
{
  "stop_reason": "tool_use",
  "content": [
    {"type": "text", "text": "I'll check the weather..."},
    {"type": "tool_use", "id": "toolu_...", "name": "get_weather", "input": {...}}
  ]
}

// After (proxy rewrites before forwarding to agent):
{
  "stop_reason": "end_turn",
  "content": [
    {"type": "text", "text": "I'll check the weather..."},
    {"type": "text", "text": "[agentsh] Tool 'get_weather' blocked by policy: reason"}
  ]
}
```

**Streaming:** Stop forwarding SSE events and emit a `content_block_stop` + `message_stop` to cleanly end the stream.

**Network layer (defense in depth):** The network monitor can refuse outbound connections to MCP server addresses that are on the block list, providing a second enforcement point.

## Shim Extension

The shim already detects `MessageToolsCall` in `DetectMessageType` (`protocol.go:81`) but the inspector ignores it. The extension is minimal:

### New Message Parser

```go
// internal/mcpinspect/protocol.go

type ToolsCallRequest struct {
    JSONRPC string `json:"jsonrpc"`
    ID      any    `json:"id"`
    Method  string `json:"method"` // "tools/call"
    Params  struct {
        Name      string          `json:"name"`
        Arguments json.RawMessage `json:"arguments"`
    } `json:"params"`
}

func ParseToolsCallRequest(data []byte) (*ToolsCallRequest, error) {
    var req ToolsCallRequest
    if err := json.Unmarshal(data, &req); err != nil {
        return nil, fmt.Errorf("parse tools/call request: %w", err)
    }
    return &req, nil
}
```

### Inspector Handler

```go
// internal/mcpinspect/inspector.go — Inspect method

switch msgType {
case MessageToolsListResponse:
    return i.handleToolsListResponse(data)
case MessageToolsCall:                    // NEW
    return i.handleToolsCall(data)        // NEW
}

func (i *Inspector) handleToolsCall(data []byte) error {
    req, err := ParseToolsCallRequest(data)
    if err != nil {
        return err
    }

    event := MCPToolCalledEvent{
        Type:      "mcp_tool_called",
        Timestamp: time.Now(),
        SessionID: i.sessionID,
        ServerID:  i.serverID,
        ToolName:  req.Params.Name,
        JSONRPCID: req.ID,
        Input:     req.Params.Arguments,
    }
    i.emitEvent(event)
    return nil
}
```

## Session Startup Flow

### Complete Initialization Sequence

```
Session Start
    │
    ├─ Read MCP server config
    │   ├─ Stdio servers: {id: "filesystem", cmd: "mcp-server-filesystem", args: [...]}
    │   └─ Network servers: {id: "weather", url: "https://mcp.example.com/sse"}
    │
    ├─ Create MCPToolRegistry (empty)
    │
    ├─ For each stdio MCP server:
    │   ├─ Shim wraps process (existing behavior)
    │   ├─ Shim inspector sees tools/list response
    │   ├─ Emits mcp_tool_seen events
    │   └─ Server populates registry: tool → {serverID, "stdio", ""}
    │
    ├─ For each network MCP server:
    │   ├─ Session manager connects to URL
    │   ├─ Calls tools/list via MCP protocol
    │   ├─ Registers tools: tool → {serverID, "http", "host:port"}
    │   ├─ Emits mcp_tool_seen events
    │   └─ Publishes server address to network monitor watch list
    │
    ├─ LLM Proxy receives registry reference
    │   └─ Uses it for lookups on every LLM response
    │
    └─ Network Monitor receives watch list
        └─ Tags connections to listed addresses as MCP traffic
```

## CLI Extensions

Extend the existing `agentsh mcp` commands:

```
agentsh mcp calls [--direct-db]              # List MCP tool calls
    --session <id>                            # Filter by session
    --server <id>                             # Filter by server
    --tool <name>                             # Filter by tool name
    --action allow|block                      # Filter by policy decision
    --since <time>                            # Start time
    --json                                    # JSON output

agentsh mcp events [--direct-db]             # Existing, now includes new event types
    --type mcp_tool_call_intercepted          # New filter value
    --type mcp_tool_called                    # New filter value
    --type mcp_network_connection             # New filter value
```

## Implementation Phases

### Phase 1: Shim Extension (smallest, immediate value)
- Add `handleToolsCall` to inspector
- Add `MCPToolCalledEvent` type
- Add `ParseToolsCallRequest` to protocol.go
- ~50 lines of code, all in `internal/mcpinspect/`

### Phase 2: Config Extensions
- Add `MCPServerDeclaration` and `MCPServerRule` types
- Extend `SandboxMCPConfig` with server declarations and server-level policy
- Add `proxy.mode: mcp-only` option
- Wire `mcp-only` mode to disable DLP and enable body storage

### Phase 3: MCP Tool Registry
- New package `internal/mcpregistry/`
- In-memory map with sync.RWMutex
- Registration from mcp_tool_seen events (stdio path)
- Registration from server declarations in config (network path)
- Wire into server/session lifecycle

### Phase 4: LLM Proxy Tool Call Detection
- New file `internal/llmproxy/mcp_intercept.go`
- Response parsing for Anthropic and OpenAI dialects
- Registry lookup integration
- Event emission for `mcp_tool_call_intercepted`
- Non-streaming support first

### Phase 5: Streaming Support
- SSE chunk inspection in `sseProxyTransport`
- Early tool name detection from `content_block_start` (Anthropic) and first delta (OpenAI)
- Stream termination for blocked tools

### Phase 6: Policy Enforcement
- Server-level allow/deny evaluation
- Tool-level allow/deny evaluation (extends existing `PolicyEvaluator`)
- Response rewriting for non-streaming (strip tool_use blocks)
- Stream termination for SSE
- Fail-closed mode for unknown tools

### Phase 7: Network Monitor Integration
- Publish MCP server addresses from registry to network monitor
- Tag matching connections as MCP traffic
- Emit `mcp_network_connection` events
- Optional connection blocking as defense-in-depth

## Testing Strategy

- **Unit tests**: Parser tests for both Anthropic and OpenAI response formats (non-streaming + SSE chunks)
- **Registry tests**: Concurrent registration and lookup, edge cases (duplicate tool names across servers)
- **Policy tests**: Server-level allow/deny, tool-level allow/deny, wildcard matching, fail-closed vs fail-open, rate limiting, version pinning interaction
- **Integration tests**: End-to-end flow with mock LLM responses containing tool_use blocks, verify events emitted
- **Shim tests**: Extend existing `mcp_integration_test.go` with tools/call interception
- **Blocking tests**: Verify rewritten responses are valid (non-streaming: valid JSON, streaming: clean SSE termination)
- **Config tests**: `mcp-only` proxy mode correctly disables DLP and enables body storage
- **Fail-closed tests**: Unknown tools blocked when fail_closed=true, passed when false
