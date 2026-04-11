# HTTP Path/Verb Filtering for Declared Services — Design

**Date:** 2026-04-10
**Status:** Design (pre-implementation)
**Related specs:**
- `docs/superpowers/specs/2026-04-09-plan-06-service-config-routing-design.md` (existing `services:` credential-substitution section — overlapping concern, kept separate by design)
- `docs/superpowers/specs/2026-04-07-external-secrets-design.md` (parent of Plan 6)

## Problem

`agentsh`'s policy engine filters outbound network calls at the host/port/CIDR level via `NetworkRule`, and resolves domains at DNS time. There is no way to say "allow `GET /repos/*`, deny `DELETE /repos/*`" — once a host is allowed, every method and every path on that host is reachable.

Agents are increasingly wired to general HTTP/HTTPS APIs (GitHub, Stripe, internal services) and the operator wants to grant the minimum useful surface: read-only access to some paths, specific verbs on others, deny on destructive operations. Today the only option is binary allow/deny on `api.github.com`, which means an agent that needs to `GET /repos/owner/repo/issues` also has authority to `DELETE /repos/owner/repo` and every other endpoint on the same host.

Two hard constraints rule out the obvious approaches:

- **No MITM.** Terminating TLS with a trusted CA was explicitly rejected — the existing `ConnectRedirectRule` even hard-errors on `mode: mitm`. The design must not depend on intercepting TLS with a proxy CA.
- **Cannot modify arbitrary upstream SDKs.** The design must work with agents that use ordinary HTTP clients (Python `requests`, Go `net/http`, etc.) by setting an environment variable, the same way `ANTHROPIC_BASE_URL` routes the Anthropic SDK through the LLM proxy today.

## Goal

Let operators declare HTTP services in policy with per-service method/path allow/deny rules. Route cooperating agents through a local gateway that applies the rules before forwarding upstream over real TLS. Fail closed on any attempt to bypass the gateway with direct HTTPS to a declared host.

## Architecture

Three independent enforcement layers that stack:

1. **Gateway evaluator** — cooperating child sets `<NAME>_API_URL=http://127.0.0.1:<port>/svc/<name>`, the gateway reads the plaintext request, evaluates `CheckHTTPService(service, method, path)`, forwards to the real upstream over TLS if allowed.
2. **Fail-closed CONNECT check** — `internal/netmonitor/proxy.go` denies CONNECT (and plain HTTP) to any hostname that appears as an upstream in `http_services`, catching children that ignore the env var.
3. **Existing network policy** — unchanged; seccomp-backed `NetworkRule` still gates raw `connect(2)`.

Cooperation is by base-URL env var injection, not by DNS rerouting. There is no trusted CA, no TLS interception, no kernel interposition. Credential material intended for the upstream stays in the gateway (via the existing `HeaderInjectionHook` pattern) and is never handed to the child.

## Scope

**In scope:**
- New top-level `http_services:` policy YAML section
- New `policy.Engine` methods: `CheckHTTPService`, `HTTPServices`, `DeclaredHTTPServiceHost`
- Extend `internal/proxy/proxy.go` `ServeHTTP` with a path-prefix dispatch to declared services, bypassing LLM dialect detection when the request targets `/svc/<name>/...`
- New `serveDeclaredService` handler that reuses `hookRegistry`, DLP, storage, redaction (not `RequestRewriter` — see §2)
- Extend `Proxy.EnvVars()` to emit per-service `<NAME>_API_URL` entries
- Fail-closed CONNECT and plain-HTTP checks in `internal/netmonitor/proxy.go`
- New event types: `http_service_request`, `http_service_denied_direct`, `http_service_approve`
- Path-matching fuzz target

**Out of scope:**
- Unifying with the existing `services:` credential-substitution section (Plan 6) — orthogonal concerns, a follow-up can consolidate
- Query-string matching in rules (v1 matches method + path only)
- Per-service rate limiting (existing LLM rate limiter stays LLM-only)
- Local DNS redirect to force uncooperative clients into the gateway
- Redirect decisions (v1 supports allow/deny/approve/audit only)
- Policy hot-reload of `http_services` for already-running children
- Header-value matching in rules

**Relationship to the existing `services:` section (Plan 6)**

The existing `services:` section declares services for credential substitution: `name`, `match.hosts`, `secret.ref`, `fake.format`, `inject.header`. Its matcher resolves `r.Host` to a service name and dispatches per-service hooks. It does not filter, rewrite paths, or inject env vars for generic HTTP clients.

This design adds `http_services:` as a separate top-level section with different responsibilities: routing by path prefix, filtering by method/path rules, and injecting base-URL env vars. A service can appear under the same name in both sections — they compose, because Plan 6's hook dispatch is driven by `RequestContext.ServiceName` and this design sets that field from the path-prefix resolution. The two surfaces will be merged in a future pass; for v1 they are intentionally separate to avoid disturbing working Plan 6 code.

---

## Section 1 — YAML Schema

New top-level `http_services:` key in `Policy` (`internal/policy/model.go`):

```go
type Policy struct {
    // ... existing fields ...
    HTTPServices []HTTPService `yaml:"http_services,omitempty"`
}

type HTTPService struct {
    Name        string            `yaml:"name"`
    Upstream    string            `yaml:"upstream"`            // https://api.github.com
    ExposeAs    string            `yaml:"expose_as,omitempty"` // env var name; default <NAME>_API_URL
    Aliases     []string          `yaml:"aliases,omitempty"`   // extra hostnames for fail-closed check
    AllowDirect bool              `yaml:"allow_direct,omitempty"` // escape hatch; default false
    Default     string            `yaml:"default,omitempty"`   // allow | deny; default deny
    Rules       []HTTPServiceRule `yaml:"rules,omitempty"`
}

type HTTPServiceRule struct {
    Name     string   `yaml:"name"`
    Methods  []string `yaml:"methods,omitempty"` // empty or "*" means any
    Paths    []string `yaml:"paths"`             // gobwas/glob patterns, '/' separator
    Decision string   `yaml:"decision"`          // allow | deny | approve | audit
    Message  string   `yaml:"message,omitempty"`
    Timeout  duration `yaml:"timeout,omitempty"` // only meaningful for approve
}
```

Example:

```yaml
http_services:
  - name: github
    upstream: https://api.github.com
    expose_as: GITHUB_API_URL
    default: deny
    rules:
      - name: read-issues
        methods: [GET]
        paths:
          - /repos/*/*/issues
          - /repos/*/*/issues/*
        decision: allow
      - name: open-issue
        methods: [POST]
        paths:
          - /repos/*/*/issues
        decision: approve
        message: "Agent wants to open an issue in {{path}}"
        timeout: 30s
      - name: block-repo-delete
        methods: [DELETE]
        paths:
          - /repos/**
        decision: deny
        message: "Repository deletion is never allowed"

  - name: stripe
    upstream: https://api.stripe.com
    default: deny
    rules:
      - name: read-customers
        methods: [GET]
        paths:
          - /v1/customers
          - /v1/customers/*
        decision: allow
```

Semantics:

- **First-match-wins** on `rules` in declaration order.
- **Default fallback** applies if no rule matches. Unspecified `default` means `deny`.
- **Decisions** supported in v1: `allow`, `deny`, `approve`, `audit`. Not supported: `redirect` (requires a different execution path), `soft_delete` (nonsensical for HTTP).
- **Timeout** applies only to `approve` and governs how long the gateway waits for operator resolution before failing closed.

---

## Section 2 — Component: Generalized Service Gateway

Extend `internal/proxy/proxy.go` rather than building a new proxy. Rationale: reuse `hookRegistry`, DLP, storage, request logging, redaction, and the existing listener — most of what a declared-service gateway needs already exists there. `RequestRewriter` is **not** reused (it is LLM-dialect-specific); a small request-clone helper is added instead (see step 5 below).

### Dispatch changes in `ServeHTTP`

```go
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // New: path-prefix dispatch to declared services.
    if svc, rest, ok := p.declaredService(r.URL.Path); ok {
        p.serveDeclaredService(w, r, svc, rest)
        return
    }

    // Existing LLM dispatch path, unchanged.
    dialect := p.detector.Detect(r)
    if dialect == DialectUnknown {
        http.Error(w, "unknown LLM dialect", http.StatusBadRequest)
        return
    }
    // ... existing flow ...
}
```

`declaredService(path)` strips a leading `/svc/<name>` prefix and returns the compiled service + remaining path. Lookup is case-insensitive on the service name. If the path has `/svc/` but no registered service name, return a 404 with `"no such service"` rather than falling through to dialect detection — declared services and LLM services must not mask each other.

### `serveDeclaredService` responsibilities

1. Read and buffer the request body (same as the LLM path).
2. Build `RequestContext{ServiceName: svc.Name, ...}` and assign a `request_id`.
3. Call `p.policy.CheckHTTPService(svc.Name, r.Method, rest)`. The evaluator handles traversal rejection and empty-path coercion (see §3) — the gateway does not duplicate those checks. Apply `maybeApprove`-style approval semantics, reusing the pattern from `netmonitor/proxy.go`.
4. Dispatch hooks via `hookRegistry.ApplyPreHooks(svc.Name, r, ctx)` — service-scoped, so `HeaderInjectionHook` for this service fires and injects the real credential. Plan 6's `LeakGuardHook` already skips when `ServiceName != ""`.
5. Build a fresh outbound `*http.Request` for `svc.Upstream + rest` (preserving query string, headers, method, body). Do **not** reuse the LLM-side `RequestRewriter` — it takes a `Dialect` parameter and its rewrite logic (auth header swapping, OpenAI OAuth routing) is LLM-specific. A small helper on `Proxy` that clones the request and retargets it to the upstream URL is sufficient.
6. Forward via the existing upstream transport (`http.DefaultTransport` or whatever the LLM path uses — decide in the implementation plan). Capture response into storage. Apply post-hooks. Emit `http_service_request` event.
7. Stream the response back to the caller.

### Env var plumbing

`Proxy.EnvVars()` currently returns the LLM env vars. Extend it to append one entry per declared service, using the service's `expose_as` field (or the derived default `<NAME>_API_URL`). The returned map is already consumed at the session spawn point (same path as `ANTHROPIC_BASE_URL`), so no new wiring is needed to reach child processes.

Values are of the form:

```
GITHUB_API_URL=http://127.0.0.1:<port>/svc/github
STRIPE_API_URL=http://127.0.0.1:<port>/svc/stripe
```

### Why path-prefix, not Host-based routing

- Host-based routing (`Host: api.github.com` with the proxy on `127.0.0.1`) only works if the SDK preserves the original Host header under a base-URL override. Most SDKs do not.
- The path-prefix `/svc/<name>/...` is what SDKs naturally produce when the user sets a base URL ending in `/svc/github` and the SDK joins its own path onto it.
- A single listener port serves all declared services and the LLM proxy without collision.

### What stays untouched

- Dialect detection, DLP, MCP interception, SSE streaming, LLM rate limiting — all LLM-specific and only run on the LLM path.
- The existing `services:` credential-substitution path from Plan 6 — still matches by `r.Host` for its own use cases and is not touched.
- `internal/netmonitor/proxy.go` except for the fail-closed checks in §5.

---

## Section 3 — Path/Verb Rule Evaluator

New evaluator on `policy.Engine`, mirroring the shape of `CheckNetworkCtx`, `CheckFile`, etc.

### Compiled structures

```go
type compiledHTTPServiceRule struct {
    rule    HTTPServiceRule
    methods map[string]struct{} // uppercase; empty or "*" means any
    paths   []glob.Glob          // gobwas/glob with '/' separator
}

type compiledHTTPService struct {
    cfg      HTTPService
    rules    []compiledHTTPServiceRule
    upstream *url.URL            // parsed once at compile time
    envVar   string              // resolved ExposeAs or derived default
    defaultDecision string       // allow | deny (deny if unspecified)
}

// On Engine:
httpServices     map[string]*compiledHTTPService // keyed by lowercase name
httpServiceHosts map[string]*compiledHTTPService // upstream host -> compiled service
```

Built in `NewEngine` alongside `compiledNetworkRule`, `compiledFileRule`, etc.

### Check method

```go
// CheckHTTPService evaluates method+reqPath against the rules for service.
// reqPath is the path portion AFTER the /svc/<name> prefix has been stripped.
// Returns a wrapped Decision in the same shape as CheckNetworkCtx.
func (e *Engine) CheckHTTPService(service, method, reqPath string) Decision {
    cs, ok := e.httpServices[strings.ToLower(service)]
    if !ok {
        return e.wrapDecision("deny", "", "unknown http_service", 0)
    }

    // Traversal guard: reject any path that doesn't survive path.Clean unchanged.
    if reqPath == "" {
        reqPath = "/"
    }
    if path.Clean(reqPath) != reqPath {
        return e.wrapDecision("deny", "", "path traversal rejected", 0)
    }

    method = strings.ToUpper(method)

    for _, r := range cs.rules {
        if !methodMatches(r, method) {
            continue
        }
        if !pathMatches(r, reqPath) {
            continue
        }
        return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, r.rule.Timeout)
    }

    // Fallback to the service-level default.
    if cs.defaultDecision == "allow" {
        return e.wrapDecision("allow", "default", "", 0)
    }
    return e.wrapDecision("deny", "default", "no rule matched", 0)
}
```

`methodMatches` returns true if `r.methods` is empty, contains `*`, or contains the canonicalized method. `pathMatches` ORs across the compiled globs.

### Matching semantics

- **Method:** case-insensitive comparison after uppercasing both sides. Empty list or `["*"]` means any method. Multiple methods in a single rule are OR-ed.
- **Path:** `gobwas/glob` with `/` separator. `*` matches one segment (no `/` in the matched portion). `**` matches a subtree (may span slashes). These are the same semantics used by `FileRule.Paths` today.
- **Query string:** **not** included in v1 matching. Gateway logs the full path including query string for audit purposes, but the rule matcher sees only the path portion.
- **Traversal:** `path.Clean(p) != p` rejects `/foo/..`, `/foo//bar`, `/foo/./bar`, and leading-slash variants. This runs before method matching so a traversal attempt never matches an allow rule.
- **Case on path:** case-sensitive. REST paths are case-sensitive by convention and making rules case-insensitive would cause surprising matches.
- **First-match-wins:** rule order in YAML is preserved into `compiledHTTPService.rules`.

### Decision wrapping

`e.wrapDecision` is the existing helper that populates `Decision{EffectiveDecision, RuleName, Message, Timeout, ...}`. Reusing it means `http_services` decisions flow through the same approval/audit bus as file, network, and command decisions — no new decision-handling code.

### Gateway call shape

```go
dec := p.policy.CheckHTTPService(svc.Name, r.Method, rest)
dec, err := p.maybeApprove(r.Context(), dec, approvalReq)
if err != nil { /* timeout or error */ }

switch dec.EffectiveDecision {
case "allow":
    // proceed to hooks + forward
case "deny":
    http.Error(w, dec.Message, http.StatusForbidden)
    return
case "audit":
    // log and proceed
}
```

`maybeApprove` is the existing wrapper in `netmonitor/proxy.go`; it will be lifted to a shared location if needed or duplicated if lifting is messy — deferred to the implementation plan.

---

## Section 4 — Cooperation Mechanism

How a child process's HTTP call actually reaches the gateway, without TLS interception or DNS trickery.

### URL shape: path-prefix on the existing proxy port

Each declared service gets a URL under the proxy's existing listen port:

```
GITHUB_API_URL=http://127.0.0.1:<port>/svc/github
STRIPE_API_URL=http://127.0.0.1:<port>/svc/stripe
```

The SDK joins its own path onto that base. For the GitHub example, `client.get("/repos/owner/repo/issues")` becomes `GET http://127.0.0.1:<port>/svc/github/repos/owner/repo/issues`. The gateway strips `/svc/github`, leaving `/repos/owner/repo/issues` as the path passed to `CheckHTTPService` and forwarded upstream.

Host-based routing was rejected: it requires SDKs to preserve the original `Host` header under a base-URL override, which most do not. Path-prefix routing works with any client that joins URLs onto a base.

### Env var injection plumbing

`Proxy.EnvVars()` currently returns `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `AGENTSH_SESSION_ID`. Extend it to append one entry per declared `http_services` entry, using the service's `expose_as` field (or the derived default `<NAME>_API_URL`).

The returned map is already merged into the child process environment at the session spawn point — the existing consumer in `internal/api/app.go` passes these through unchanged. No new injection path, no new config surface.

### Derived env-var name default

If `expose_as` is omitted on a service, the name is derived as:

```
strings.ToUpper(name) + "_API_URL"
```

`github` becomes `GITHUB_API_URL`, `stripe-billing` becomes `STRIPE_BILLING_API_URL` (hyphens stay — they're legal in env var names on POSIX shells in practice, though some programs complain; `expose_as` is available for explicit control).

### Plaintext is acceptable

Children speak plaintext HTTP to `127.0.0.1`. The gateway terminates and re-issues the upstream call over real TLS using Go's default transport. Same trust model as the LLM proxy: the gateway runs in the TCB, and localhost plaintext is fine because the egress hop is where encryption matters.

Credentials destined for the upstream (e.g. a real GitHub personal access token) live in the gateway's credential store and are injected by a `HeaderInjectionHook` — never carried by the child. This preserves the property that child processes do not hold upstream credentials in their environment.

### No DNS redirect in v1

Children that ignore the env var and connect to `api.github.com` directly do not reach the gateway via DNS rerouting. They are caught by §5's fail-closed CONNECT check in `netmonitor/proxy.go`. Rerouting DNS would require a second interception layer with its own breakage modes (TTLs, caching resolvers, tools that bypass `/etc/resolv.conf`) for no enforcement benefit that §5 doesn't already provide.

---

## Section 5 — Fail-Closed CONNECT Check

The anti-bypass layer in `internal/netmonitor/proxy.go`. Without this, a child that skips the env var and hits `api.github.com:443` directly would tunnel through netmonitor's opaque CONNECT path, and the gateway would never see the request.

### Where the check lives

`handleConnect` at `internal/netmonitor/proxy.go:110` runs before the CONNECT tunnel is established. Add a check: if the target host matches a declared service upstream, reject with 403 and emit an event.

`handleHTTP` at `internal/netmonitor/proxy.go:230` gets the symmetric check against `req.Host`. Plain HTTP to declared services is rare but the symmetric check is cheap and prevents an asymmetric bypass.

### How netmonitor learns the declared hosts

New method on the policy engine:

```go
// DeclaredHTTPServiceHost reports whether host belongs to a declared
// http_services entry and returns the service name and the env-var name
// used by the gateway (for the guidance message).
func (e *Engine) DeclaredHTTPServiceHost(host string) (serviceName, envVar string, ok bool)
```

Built at engine construction time by parsing the host component of each `http_services[i].upstream` URL and merging in any `aliases`. Stored in `Engine.httpServiceHosts` (see §3). `netmonitor.StartProxy` already holds a `*policy.Engine`; no new wiring, just a new method call. Querying at request time (rather than snapshotting in `StartProxy`) keeps the door open for future hot reload.

### Match semantics

- Strip port (bracket-aware for IPv6), lowercase, strip trailing dot.
- Exact match on registered hosts plus aliases. No wildcards — declared services name concrete upstreams.

### Action on match

- CONNECT: return `HTTP/1.1 403 Forbidden` with body `direct HTTPS to <host> is blocked; use <ENV_VAR_NAME> to route through the gateway`.
- Plain HTTP: 403 with the same body.
- Emit `http_service_denied_direct` with `{service_name, env_var, request_host, client_addr, pid}` for audit.
- The tunnel is never established, so no bytes flow to the upstream.

### Escape hatch

`http_services[i].allow_direct: true` (default `false`) disables the fail-closed check for that service. Use case: the upstream hostname hosts both the API and a user-legitimate web UI on the same host. Documented as weakening the bypass guarantee; not recommended.

### What this does NOT cover

- Raw `connect(2)` to `api.github.com:443` that bypasses netmonitor entirely — handled by the existing `NetworkRule` + seccomp socket filter, not here.
- IP-literal access (direct connect to the resolved IP) — also caught at the network policy layer.

The CONNECT check is the proxy-layer belt to those existing suspenders.

---

## Section 6 — Events and Audit

### Emission path: mirror the LLM proxy

The LLM side of `internal/proxy/proxy.go` already has the full pipeline for per-request logging: `RequestLogEntry` with `RequestInfo{Method, Path, Headers, BodySize, BodyHash}`, storage persistence via `Config.Storage`, and header redaction for `Authorization`-style fields. Declared services reuse all of it unchanged. The only addition is a discriminator on the log entry:

```go
type RequestLogEntry struct {
    // ... existing fields ...
    ServiceKind string `json:"service_kind"` // "llm" | "http"
    ServiceName string `json:"service_name"` // e.g. "github"
    RuleName    string `json:"rule_name"`    // matched rule or "default"
}
```

No new storage schema, no new sink.

### New event types

| Event | Source | Fields |
|---|---|---|
| `http_service_request` | `serveDeclaredService` | service_name, request_id, method, path, decision, rule_name, status_code, latency_ms, upstream_host |
| `http_service_denied_direct` | `netmonitor.handleConnect` / `handleHTTP` | service_name, env_var, request_host, client_addr, pid |
| `http_service_approve` | gateway, when decision = approve | service_name, request_id, method, path, rule_name |

`rule_name` is the `name` field from the matched `HTTPServiceRule`, or the literal string `"default"` when the service's top-level fallback fires. Operators grep the audit log for `"rule_name":"default"` to find traffic that slipped through without an explicit rule.

### Header handling

Request and response headers are logged as `name → length` pairs, with an allowlist of safe headers (`Content-Type`, `User-Agent`, `X-Request-Id`) logged with values. `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and anything injected by a `HeaderInjectionHook` are never logged. Reuse the LLM proxy's existing redaction helper — do not reimplement.

### Body hashing

Request and response bodies are hashed (SHA256). Hash and byte count go to storage unconditionally. Full bodies are persisted only when the existing LLM-proxy storage config says to — same knob, no new config surface. This keeps the audit log useful for "did agent X read resource Y?" without turning the store into a credential honeypot.

### Correlation

`request_id` is a stable per-request UUID assigned in `serveDeclaredService`. It threads through every event and log entry for that request. Same pattern as the LLM proxy. The `http_service_denied_direct` event does not have a `request_id` because there is no gateway request — it has the client PID and address so operators can correlate with process tables.

### What is NOT emitted

- Per-byte progress events — too noisy.
- Per-header-value events unless the value is in the allowlist — credential risk.
- Any event for requests to undeclared hosts that hit netmonitor's normal allow path — those still emit the existing `net_http_request` event, unchanged.

---

## Section 7 — Config Loading and Layering

### Single source of truth: policy YAML

`http_services:` lives in the same policy file as `network_rules`, `file_rules`, `command_rules`, etc. No separate config file, no server-config duplication, no split ownership. Loaded by `internal/policy.Load()` along with everything else, validated in the same pass, and compiled in `NewEngine` alongside `compiledNetworkRule`.

### Engine additions (`internal/policy/engine.go`)

- `Engine.httpServices map[string]*compiledHTTPService` — keyed by lowercase name, built in `NewEngine`
- `Engine.httpServiceHosts map[string]*compiledHTTPService` — upstream host → compiled service, for §5 fail-closed lookup
- `Engine.CheckHTTPService(service, method, path string) Decision` — §3
- `Engine.HTTPServices() []HTTPService` — enumeration for the gateway's `EnvVars()` plumbing (returns the source config, not the compiled form, so the gateway can read `ExposeAs`, derived env var names, etc.)
- `Engine.DeclaredHTTPServiceHost(host string) (serviceName, envVar string, ok bool)` — §5

### Compile-time validation

Run in `NewEngine` before the engine is returned, so any error aborts startup:

- Name is non-empty and unique (case-insensitive)
- `upstream` parses as an `https://` URL with a non-empty host
- Every upstream host (including aliases) is unique across all `http_services` — no two services can claim the same host
- `default` is `""`, `"allow"`, or `"deny"` (empty means deny)
- `rules[i].decision` is `"allow"`, `"deny"`, `"approve"`, or `"audit"`
- Every `paths` entry compiles as a `gobwas/glob` pattern with `/` separator
- `methods` entries, if present, are non-empty strings (any casing)
- `expose_as`, if present, matches `^[A-Za-z_][A-Za-z0-9_]*$`; the derived default from `name` is checked with the same rule after uppercasing
- `timeout` is non-negative and only meaningful on `approve` rules (warn otherwise, don't error)

Errors include the service name and rule name (if applicable) in the message so operators can grep back to the YAML line.

### Layering with existing network policy

Three independent enforcement points, ordered by proximity to the wire:

1. **Network rule layer** (`CheckNetworkCtx`, socket syscalls via seccomp) — existing deny-at-socket path. If the child is denied by `NetworkRule`, the connection never opens. Unchanged. An operator who wants to fully cut off `api.github.com` at the network layer still can.
2. **Netmonitor CONNECT/HTTP check** (§5) — catches HTTPS/HTTP proxy clients trying to reach declared hosts directly. Fail-closed.
3. **Gateway evaluator** (§3) — runs on cooperating clients that use the env-var URL. Rule-based.

These stack. A request must pass every applicable layer. If an operator denies `api.github.com` at layer 1 *and* declares a gateway service for it, the gateway's own upstream fetch must still succeed — the outbound hop runs in the gateway's process context, not the child's. This is already the case because the gateway is in the TCB and runs outside the sandbox's network policy scope for outbound fetches, but document it explicitly so operators don't accidentally break their own gateway with overzealous child-targeted network rules.

### Relationship to `ConnectRedirectRule`

Orthogonal. `http_services` does not use or require `connect_redirect`. Existing redirect rules can still rewrite SNI or redirect TCP destinations. Operators mixing the two should understand that `connect_redirect: rewrite_sni` is transport-level and does not feed the gateway — only the env-var mechanism does. `mitm` mode is still rejected at `internal/policy/model.go:499` and this design does not change that.

### Relationship to Plan 6 `services:`

The two sections can coexist and reference the same logical service (e.g. `github` declared in both). The Plan 6 path uses `r.Host`-based matching and fires per-service `HeaderInjectionHook`. This design's path-prefix dispatch sets `RequestContext.ServiceName` before calling `hookRegistry.ApplyPreHooks`, so if the operator has also declared `github` in `services:` with an `inject.header`, that hook fires for declared-service requests as well. No wiring change in the registry.

A future consolidation pass can merge `services:` and `http_services:` into a single declaration with composable features (secrets + filtering + routing). That pass is explicitly out of scope here to keep Plan 6 undisturbed.

### Hot reload

If `policy.Reload` is added later, rebuilding the compiled `httpServices` map is trivial — everything derives from `Policy.HTTPServices` at compile time. Caveat: already-running child processes keep their injected env vars until they restart, so a reload that adds a service only reaches children spawned after. Document; don't engineer around it in v1.

---

## Section 8 — Testing Strategy

### Unit tests

**`internal/policy/engine_test.go` — `TestCheckHTTPService`** (table-driven):

- Method matching: single method; multiple methods; `*` wildcard; empty list (any); case-insensitive canonicalization on both sides
- Path matching: literal (`/repos/anthropics/claude-code`); single-segment glob (`/repos/*/claude-code`); subtree glob (`/repos/**`); multiple patterns OR-ed in one rule
- Traversal rejection: `/repos/../admin`, `/repos//admin`, `/repos/./admin`, and their percent-encoded forms all rejected at `path.Clean` with decision `deny`
- First-match-wins: earlier rule wins for the same method + path
- Default fallback: unmatched request falls through to service `default`; unspecified `default` means deny
- Unknown service: `CheckHTTPService("nope", ...)` returns deny
- Query string ignored: `/foo?x=1` matches the same rule as `/foo`
- Empty path coerced to `/`

**`internal/policy/engine_test.go` — `TestDeclaredHTTPServiceHost`**:

- Exact match; port stripping (`api.github.com:443`); lowercase normalization; alias match; IPv6 bracket handling; no-match returns `ok=false`
- Env var name returned for guidance messages

**`internal/policy/model_test.go` additions**:

- Duplicate service name rejected at load
- Duplicate upstream host (including across aliases) rejected at load
- Invalid upstream URL rejected (not https, missing host)
- Invalid glob in `paths` rejected (error mentions rule name)
- Invalid decision value rejected
- Invalid `expose_as` (starts with digit, contains hyphen) rejected
- Empty `rules` without `default` is allowed (implicit deny-all)

### Gateway integration tests in `internal/proxy/proxy_test.go`

Spin up an `httptest.Server` as fake upstream. Build a `Proxy` with an `http_services` entry pointing at it. Exercise `ServeHTTP` directly:

- `POST /svc/github/repos/anthropics/claude-code/issues` with a matching allow rule → upstream receives the body and headers, response flows back
- `DELETE /svc/github/repos/anthropics/claude-code` with a deny rule → 403 with the rule's `message`, upstream not contacted
- `HeaderInjectionHook` populates `Authorization` on the upstream-bound request, credential never visible in the request log
- `http_service_request` event emitted with `rule_name` set to the matched rule or `"default"`
- Approve-decision path: request is held until approval resolves; timeout honored; emits `http_service_approve`
- Path `/svc/nosuchservice/...` returns 404, does NOT fall through to dialect detection
- LLM path untouched: `POST /v1/messages` with `x-api-key` still routes to the Anthropic dialect handler

### Netmonitor integration tests

Extend existing netmonitor tests (or new file):

- CONNECT to `api.github.com:443` when `github` is declared → 403 with guidance mentioning `GITHUB_API_URL`
- CONNECT to a non-declared host tunnels through unchanged (regression guard)
- Plain HTTP to `api.github.com` via `handleHTTP` → 403 with the same guidance
- `allow_direct: true` service lets CONNECT through (escape hatch proven wired)
- `http_service_denied_direct` event emitted with expected fields

### Path-matching fuzz target

`internal/policy/engine_fuzz_test.go` — `FuzzCheckHTTPServicePath`. Feeds random strings containing `%2e`, `%2f`, `\x00`, double slashes, Unicode dot variants, mixed slashes, and asserts:

1. Whatever decision comes back, the raw path never reaches the upstream without surviving `path.Clean` unchanged (i.e. allow decisions require traversal-clean paths).
2. The evaluator never panics.
3. Method matching is stable under arbitrary casing.

Path handling is the attack surface most likely to grow subtle bugs — the fuzz target is proportionate to the risk.

### Cross-compile gate

`GOOS=windows go build ./...` before commit, per `CLAUDE.md`. All new code is pure Go in `internal/policy` and `internal/proxy` — no `runtime.GOOS` branching expected, but the gate proves it.

### What NOT to retest

- `gobwas/glob` — upstream tested
- `storage`, `redaction`, `hookRegistry` — existing LLM-proxy tests cover these; reuse without duplication
- Network policy layer (`CheckNetworkCtx`, seccomp) — §7 layering is architectural, no new code in those paths
- Plan 6's existing `services:` matcher — untouched by this design

---

## Open Questions

- **`maybeApprove` location.** Currently lives in `internal/netmonitor/proxy.go` as a private helper. The gateway needs the same behavior. Lift to a shared package (`internal/policy` or `internal/approvals`) or duplicate? Deferred to the implementation plan.
- **Request-body approval context.** The approval prompt for a write operation should probably show a hash/excerpt of the body, not just the path. Worth a follow-up once the basic approve flow is wired — do not gate v1 on it.
- **Service-level body size limits.** `http_services[i].max_body_bytes` would be useful (default to the LLM-proxy's existing limit). Not in v1 scope but the schema has room for it.

## Future Work

- Unify `services:` and `http_services:` into a single declaration.
- Query-string matching in rules (keys and value patterns).
- Header-value matching in rules.
- Local DNS redirect for uncooperative clients (with its own trade-offs).
- Per-service rate limiting, extending the existing LLM rate limiter.
- `redirect` decisions that swap one upstream for another (requires careful thought about what a redirect means for HTTP semantics).
