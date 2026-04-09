# Plan 5 Design: Session Startup + Proxy Egress Wiring

**Parent spec:** `docs/superpowers/specs/2026-04-07-external-secrets-design.md`
**Prerequisite plans:** Plans 1-4 (proxy rename, credsub.Table, SecretProvider + keyring, Vault + registry)

## Goal

Wire the credential substitution pipeline end-to-end: session startup fetches secrets and generates length-preserving fakes, the proxy substitutes fakes with reals on egress and scrubs reals from responses, and a leak guard blocks requests that would exfiltrate fakes to unregistered hosts.

Plan 5 uses a hard-coded test service configuration (no YAML parsing). YAML config, the full service model, host-pattern matching, and cloud-specific plugins (AWS SigV4, GCP OAuth) are deferred to later plans.

## Scope

**In scope:**
- Fake credential generator with format parsing and length preservation
- `HookAbortError` type for custom HTTP status codes from hooks
- Hook invocation wired into `proxy.ServeHTTP` (PreHook before forwarding, PostHook on response)
- `CredsSubHook` — fake-to-real substitution on request body, real-to-fake on response body
- `LeakGuardHook` — scan requests for known fakes, block with 403 if detected
- Session startup: construct registry, fetch secrets, generate fakes, populate `credsub.Table`, register hooks
- Session cleanup: zero table, close registry
- Audit log events for leak detection and initialization
- Buffer-then-substitute for response bodies (no streaming substitution)

**Out of scope:**
- YAML config parsing for `providers:` and `services:` sections
- Service interface, host-pattern matching, service registry
- AWS SigV4 and GCP OAuth plugins
- SSE streaming substitution with chunk-boundary buffering
- Cross-service-use detection (fake for service A in request to service B)
- Named provider instances
- `agentsh policy lint` rules for secrets

## Section 1 — Fake Credential Generator

New file: `internal/proxy/secrets/fakegen.go`

### Format syntax

```
<prefix>{rand:<count>}
```

Examples:
- `ghp_{rand:36}` — GitHub PAT format: `ghp_` prefix + 36 random base62 chars
- `sk-{rand:48}` — OpenAI key format
- `{rand:40}` — no prefix, 40 random chars

The `{rand:N}` placeholder is always at the end. Only one placeholder per format string.

### API

```go
// GenerateFake produces a fake credential matching the given format
// template whose total length equals realLen.
//
// The format must parse successfully via ParseFormat. The sum of the
// parsed prefix length and random-char count must equal realLen;
// otherwise ErrFakeLengthMismatch is returned.
//
// Random characters are drawn from the base62 alphabet
// [A-Za-z0-9] using crypto/rand.
func GenerateFake(format string, realLen int) ([]byte, error)

// ParseFormat extracts the prefix and random-char count from a
// format template string. Returns ErrInvalidFakeFormat if the
// template is malformed.
func ParseFormat(format string) (prefix string, randLen int, err error)
```

### Invariants

- **Length preservation:** `len(prefix) + randLen` must equal `realLen`. This is the fundamental invariant that enables future Mechanism B (eBPF in-place rewrite).
- **Minimum entropy:** `randLen` must be >= 24. Formats with fewer random chars are rejected with `ErrFakeEntropyTooLow`.
- **Cryptographic randomness:** Uses `crypto/rand`, not `math/rand`.

### Error types

```go
var ErrInvalidFakeFormat  = errors.New("secrets: invalid fake format template")
var ErrFakeLengthMismatch = errors.New("secrets: fake format length does not match real secret length")
var ErrFakeEntropyTooLow  = errors.New("secrets: fake format has fewer than 24 random characters")
```

### Collision handling

The caller (session startup) is responsible for collision detection. If `credsub.Table.Add` returns `ErrFakeCollision`, the caller regenerates the fake once. If the second attempt also collides, session creation fails.

## Section 2 — HookAbortError

Extend `internal/proxy/hooks.go` with a typed error that hooks can return to abort a request with a specific HTTP status code:

```go
// HookAbortError is returned by PreHook to abort a request with a
// specific HTTP status code. Any other error from PreHook results
// in a 502 Bad Gateway.
type HookAbortError struct {
    StatusCode int
    Message    string
}

func (e *HookAbortError) Error() string {
    return fmt.Sprintf("hook abort %d: %s", e.StatusCode, e.Message)
}
```

In `ServeHTTP`, when `ApplyPreHooks` returns an error:
- If the error is `*HookAbortError`, respond with its `StatusCode` and `Message`
- Otherwise, respond with 502 Bad Gateway

## Section 3 — Hook Invocation in Proxy

The `Hook` interface and `Registry` exist in `hooks.go` but are not currently called from `proxy.go`. Plan 5 wires them in.

### Proxy struct changes

Add a `hookRegistry` field to the `Proxy` struct:

```go
type Proxy struct {
    // ... existing fields ...
    hookRegistry *Registry
}
```

Initialize in `proxy.New()` with an empty registry. Expose `HookRegistry() *Registry` for callers to register hooks.

### Request flow insertion points

**PreHook** — after DLP processing, before request rewrite and logging:

```
Body read → DLP → PreHooks (LeakGuard, CredsSubHook) → Rewrite → Log → Forward
```

The proxy reads the body (existing line 333), applies DLP (line 342), then calls `hookRegistry.ApplyPreHooks("", req, requestCtx)`. If a hook error is returned, the proxy responds to the agent immediately (403 for `HookAbortError`, 502 otherwise) and does not forward the request.

After PreHooks run, the request body may have been replaced by `CredsSubHook` (fakes replaced with reals). The rewriter and logger see the post-substitution body.

**PostHook** — after reading response body, before MCP interception and logging:

```
Response body read → PostHooks (CredsSubHook scrubs reals) → MCP interception → Log → Return to agent
```

In `ModifyResponse`, after reading the upstream response body (existing line 402), call `hookRegistry.ApplyPostHooks("", resp, requestCtx)`. The hook may replace the response body (reals replaced with fakes). MCP interception and logging see the post-scrub body.

### RequestContext population

Before calling hooks, populate the `RequestContext`:

```go
reqCtx := &RequestContext{
    RequestID:   requestID,
    SessionID:   sessionID,
    ServiceName: "",  // no service matching in Plan 5
    StartTime:   startTime,
    Attrs:       make(map[string]any),
}
```

The `RequestContext` is passed through to both Pre and PostHooks. Store it in `r.Context()` via `context.WithValue` so `ModifyResponse` can access it (the `httputil.ReverseProxy` callback doesn't receive extra arguments).

## Section 4 — CredsSubHook

New file: `internal/proxy/credshook.go`

### CredsSubHook

```go
// CredsSubHook performs credential substitution using a credsub.Table.
// PreHook replaces fake credentials with real ones in the request body.
// PostHook replaces real credentials with fakes in the response body.
type CredsSubHook struct {
    table *credsub.Table
}
```

**PreHook behavior:**
1. Read `r.Body` into `[]byte`
2. Call `table.ReplaceFakeToReal(body)` — returns substituted body (same length)
3. Replace `r.Body` with new reader, update `r.ContentLength`

**PostHook behavior:**
1. Read `resp.Body` into `[]byte`
2. Call `table.ReplaceRealToFake(body)` — returns scrubbed body (same length)
3. Replace `resp.Body` with new reader, update `resp.ContentLength`

Both operations are infallible — if no fakes/reals are found, the body is returned unchanged.

### LeakGuardHook

```go
// LeakGuardHook blocks requests that contain known fake credentials.
// This prevents credential exfiltration to unregistered hosts.
type LeakGuardHook struct {
    table  *credsub.Table
    logger *slog.Logger
}
```

**PreHook behavior:**
1. Read `r.Body` into `[]byte` (put it back afterward)
2. Scan body for any known fake: iterate table entries, check if `bytes.Contains(body, entry.Fake)`
3. Also scan `r.URL.RawQuery` and select headers (`Authorization`, `X-Api-Key`, etc.)
4. If fake found: log audit event `secret_leak_blocked` with service name, request host, request ID
5. Return `&HookAbortError{StatusCode: 403, Message: "credential leak blocked"}`
6. If no fake found: return nil (request proceeds)

**PostHook:** No-op (returns nil).

### Registration order

LeakGuardHook is registered first, CredsSubHook second. The hook registry dispatches PreHooks in registration order, so leak detection runs before substitution.

This ordering is correct because:
- LeakGuard needs to see fakes in the body (before they're replaced)
- CredsSubHook needs to run after LeakGuard has cleared the request

### Body re-reading

Both hooks need to read `r.Body`. Since `r.Body` is an `io.ReadCloser` that can only be read once, each hook must:
1. Read the body
2. Process it
3. Replace `r.Body` with a new `bytes.NewReader`

This is the same pattern already used in `ServeHTTP` (line 346).

## Section 5 — Session Startup Integration

### ServiceConfig type

New file: `internal/session/secrets.go`

```go
// ServiceConfig describes one secret-backed service for credential
// substitution. Plan 5 uses this struct directly; future plans will
// parse it from YAML policy files.
type ServiceConfig struct {
    Name       string             // logical service name (e.g. "github")
    SecretRef  secrets.SecretRef   // where to fetch the real credential
    FakeFormat string             // fake template (e.g. "ghp_{rand:36}")
}
```

### Bootstrap function

```go
// BootstrapCredentials fetches secrets, generates fakes, and
// populates a credsub.Table. Returns the table and a cleanup
// function that zeros the table and closes the registry.
//
// If any fetch or fake generation fails, all already-fetched
// secrets are zeroed and the registry is closed before returning
// the error. The agent never starts with a partially populated
// table.
func BootstrapCredentials(
    ctx context.Context,
    registry *secrets.Registry,
    services []ServiceConfig,
) (*credsub.Table, func() error, error)
```

**Steps:**
1. Create `credsub.New()` table
2. For each service in `services`:
   a. `registry.Fetch(ctx, svc.SecretRef)` → get `SecretValue`
   b. `secrets.GenerateFake(svc.FakeFormat, len(sv.Value))` → generate fake
   c. `table.Add(svc.Name, fake, sv.Value)` → populate table
   d. If `table.Add` returns `ErrFakeCollision`, regenerate fake once. If second attempt collides, fail.
   e. `sv.Zero()` — wipe fetched secret from memory (table has its own copy)
3. If any step fails: `table.Zero()`, `registry.Close()`, return error
4. Return table + cleanup function (returns error from `registry.Close()`) that calls `table.Zero()` then `registry.Close()`

### Session struct changes

Add to `Session` in `internal/session/manager.go`:

```go
credsTable    *credsub.Table   // per-session credential table; nil if no secrets configured
secretsClose  func() error     // closes secrets registry; nil if no secrets
```

Add accessor methods:
```go
func (s *Session) CredsTable() *credsub.Table
func (s *Session) SetCredsTable(t *credsub.Table, closeFn func() error)
```

### LLM proxy startup extension

In `internal/session/llmproxy.go`, after the proxy is created and before storing it on the session:

1. If service configs are provided (non-empty):
   a. Call `BootstrapCredentials(ctx, registry, services)`
   b. Create `LeakGuardHook` and `CredsSubHook` with the returned table
   c. Register both on `proxy.HookRegistry()`
   d. Store table and cleanup on session via `SetCredsTable`
2. If no service configs: skip (backward compatible — existing sessions without secrets work unchanged)

### Cleanup

In `CloseLLMProxy()` (or session close path):
1. If `secretsClose != nil`: call it (zeros table, closes registry)
2. Nil out `credsTable` and `secretsClose`

## Section 6 — Failure Semantics

### Session startup failures (agent never starts)

Per the parent spec: "any step 1-7 failure aborts session creation with a structured error. The agent never starts. Partial success is not allowed."

| Failure | Error | Effect |
|---------|-------|--------|
| Registry construction fails | Provider-specific error | Session creation fails |
| Secret fetch fails (not found, auth, timeout) | `ErrSecretFetchFailed` wrapping provider error | Session creation fails; table zeroed, registry closed |
| Fake format invalid | `ErrInvalidFakeFormat` | Session creation fails |
| Fake length mismatch | `ErrFakeLengthMismatch` | Session creation fails |
| Fake entropy too low | `ErrFakeEntropyTooLow` | Session creation fails |
| Table collision (after retry) | `ErrFakeCollision` | Session creation fails |

### Runtime failures (during proxy operation)

| Failure | Effect |
|---------|--------|
| LeakGuard detects fake in request | 403 to agent + audit log `secret_leak_blocked` |
| CredsSubHook substitution | Infallible — body unchanged if no fakes found |
| Response scrubbing | Infallible — body unchanged if no reals found |

### Audit events

Logged via `slog.Logger` (structured logging, not stored in audit DB):

- `secrets_initialized` — emitted on successful bootstrap. Fields: `service_count`, `session_id`
- `secret_leak_blocked` — emitted when LeakGuardHook blocks a request. Fields: `session_id`, `request_id`, `service_name` (which service's fake was detected), `request_host`

## Section 7 — File Layout

```
internal/proxy/secrets/
  fakegen.go            # NEW: GenerateFake, ParseFormat, format errors
  fakegen_test.go       # NEW

internal/proxy/
  hooks.go              # MODIFY: add HookAbortError
  hooks_test.go         # MODIFY: add HookAbortError tests
  proxy.go              # MODIFY: add hookRegistry field, wire PreHook/PostHook calls
  credshook.go          # NEW: CredsSubHook, LeakGuardHook
  credshook_test.go     # NEW

internal/session/
  manager.go            # MODIFY: add credsTable, secretsClose fields + accessors
  llmproxy.go           # MODIFY: extend startup to bootstrap credentials + register hooks
  secrets.go            # NEW: ServiceConfig, BootstrapCredentials
  secrets_test.go       # NEW
```

No new packages. All changes fit within existing package boundaries.

## Section 8 — Testing Strategy

### Unit tests

- **fakegen_test.go:** Format parsing (valid, invalid, edge cases). Length enforcement. Entropy minimum. Cryptographic randomness (output length, charset). Multiple calls produce different output.
- **credshook_test.go:** CredsSubHook substitution on request body (fake→real). CredsSubHook scrubbing on response body (real→fake). LeakGuardHook detection in body, URL, headers. LeakGuardHook returns 403 via HookAbortError. No false positives (request without fakes passes). Hook ordering (leak guard before substitution).
- **hooks_test.go:** HookAbortError propagation — PreHook returning HookAbortError → caller gets status code. PreHook returning plain error → 502.
- **secrets_test.go:** BootstrapCredentials with MemoryProvider. Failure modes: fetch error, format error, collision. Cleanup on failure (table zeroed, registry closed). Successful bootstrap populates table correctly.

### Integration test

- httptest server as "upstream"
- Proxy with hooks registered via BootstrapCredentials
- Send request containing fake → verify upstream receives real
- Upstream responds containing real → verify agent receives fake
- Send request with fake to wrong path → verify 403 (leak guard)

## Section 9 — Deferred to Later Plans

- **Plan 6 (likely):** YAML config parsing for `providers:` and `services:` sections. Full `Service` interface with host-pattern matching. Service registry.
- **Plan 7+:** AWS SigV4 plugin, GCP OAuth plugin. SSE streaming substitution. Cross-service-use detection. `agentsh policy lint` rules.
