# Proxy Rate Limiting & Version Pinning Design

**Goal:** Wire the existing `RateLimiterRegistry` and version pinning into the LLM proxy's tool call evaluation path so both non-SSE and SSE interception enforce rate limits and detect tool hash changes.

**Architecture:** Extend `mcpregistry.Registry` with pinned hash tracking. Add `RateLimiterRegistry` to the proxy struct. Insert both checks into the evaluation pipeline between cross-server detection and policy evaluation.

**Tech Stack:** Go, existing `mcpinspect.RateLimiterRegistry`, existing `mcpregistry.Registry`

---

## 1. Registry Changes (Version Pinning State)

Add pinned hash tracking to `mcpregistry.Registry`:

- New field: `pinnedHashes map[string]string` (toolName → first-seen hash), initialized in `NewRegistry()`
- In `Register()`: for each tool, if `toolName` is not in `pinnedHashes`, store its hash. The very first registration pins the hash regardless of which server provides it.
- New method: `PinnedHash(toolName string) (hash string, pinned bool)` — read-locked lookup
- On `Remove()`: do NOT clear pinned hashes. A tool's pinned hash should survive server restarts — if a server restarts with a modified tool, that's exactly what version pinning should catch.

No changes to `ToolEntry`, `ToolInfo`, `OverwrittenTool`, or any existing method signatures.

## 2. Proxy Wiring — Rate Limiter

Add `*mcpinspect.RateLimiterRegistry` to the proxy, following the same pattern as `PolicyEvaluator`:

- New field on `Proxy`: `rateLimiter *mcpinspect.RateLimiterRegistry`
- In `New()`: create it when `cfg.MCP.RateLimits.Enabled` is true (same guard pattern as `newPolicyEvaluator`)
- Pass it through to both enforcement paths:
  - Non-SSE: `interceptMCPToolCalls` gets a new `rateLimiter` parameter
  - SSE: `SSEInterceptor` gets a new `rateLimiter` field, set via `SetInterceptor`

**Evaluation order** (both paths): registry lookup → cross-server → **rate limit** → version pin → policy

When `rateLimiter.Allow(serverID, toolName)` returns false:
- action = "block"
- reason = `"rate limit exceeded for server %q"`
- Emit `MCPToolCallInterceptedEvent` with that reason
- For cross-server analyzer: call `MarkBlocked` so the window record doesn't cause false positives

## 3. Proxy Wiring — Version Pinning

Version pin checking happens in the same evaluation path, after rate limiting:

- Both `interceptMCPToolCalls` and `SSEInterceptor.lookupAndEvaluate` get access to the registry (already have it) and `cfg.MCP.VersionPinning` config
- After rate limit passes, check: `registry.PinnedHash(toolName)` → if pinned and `entry.ToolHash != pinnedHash`:
  - `on_change: "block"` → block with reason `"tool %q hash changed (pinned: %s, current: %s)"`
  - `on_change: "alert"` → allow, but emit event with reason `"tool %q hash changed (alert only)"` and action `"allow"`
  - `on_change: "allow"` or empty → no action, skip check entirely
- When `on_change: "block"` fires, call `MarkBlocked` on the analyzer (same pattern as policy blocks)
- `VersionPinning.Enabled` gates the entire check — when false, skip completely
- `AutoTrustFirst` is implicit (pin on first `Register`). Explicit hash requirements are YAGNI for now.

## 4. Testing Strategy

**Registry tests** (`mcpregistry/registry_test.go`):
- `TestPinnedHash_FirstRegistration` — register tool, verify pinned hash matches
- `TestPinnedHash_HashChangePreservesPinned` — register tool, re-register with new hash from different server, verify pinned hash is still the original
- `TestPinnedHash_RemoveDoesNotClearPin` — register, remove server, verify pinned hash survives
- `TestPinnedHash_UnknownTool` — verify `PinnedHash` returns `false` for unknown tools

**Non-SSE interception tests** (`llmproxy/mcp_intercept_test.go`):
- `TestInterceptRateLimitBlocks` — rate limiter returns false, verify tool is blocked with correct reason and event
- `TestInterceptVersionPinBlock` — hash mismatch with `on_change: "block"`, verify blocked
- `TestInterceptVersionPinAlert` — hash mismatch with `on_change: "alert"`, verify allowed but event emitted with alert reason
- `TestInterceptVersionPinDisabled` — `Enabled: false`, verify hash mismatch is ignored

**SSE interception tests** (`llmproxy/sse_intercept_test.go` or `streaming_test.go`):
- Mirror the above rate limit and version pin tests for the SSE path

**Integration test** (`llmproxy/proxy_test.go`):
- One end-to-end test with rate limiting enabled that confirms the full proxy blocks when the limiter is exhausted
