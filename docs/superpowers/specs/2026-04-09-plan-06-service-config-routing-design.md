# Plan 6: Service Config & Host Routing — Design

**Date:** 2026-04-09
**Status:** Design (pre-implementation)
**Parent spec:** `docs/superpowers/specs/2026-04-07-external-secrets-design.md` (Sections 2, 3, 5, 7)
**Depends on:** Plans 1-5 (proxy rename, credsub.Table, SecretProvider + keyring, Vault + registry, session proxy wiring)

## Problem

Plans 1-5 built the credential substitution infrastructure: credsub.Table, Hook interface + Registry, CredsSubHook, LeakGuardHook, fakegen, SecretProvider (keyring + Vault), provider Registry with topo sort, and BootstrapCredentials. But it is all hard-wired — the production caller passes `nil, nil` for secrets, hooks are registered globally (service name `""`), and there is no host matching or YAML configuration.

Plan 6 connects this infrastructure to real per-service configuration: operators declare providers and services in policy YAML, the proxy matches requests to services by host pattern, and per-service hooks inject real credentials into outbound headers.

## Goal

Parse `providers:` and `services:` from policy YAML. Match inbound proxy requests to services by host pattern. Inject real credentials into outbound request headers per service. Extend fake-to-real substitution to cover headers, URL query, and URL path (not just body).

## Architecture

**ServiceMatcher** resolves `Host` header to a service name via literal + wildcard patterns. The existing hook Registry already dispatches hooks by service name. A new **HeaderInjectionHook** is registered per service to set the `Authorization` (or other) header using the real credential from a template. The **bootstrap flow** reads policy YAML, constructs providers, fetches secrets, generates fakes, populates the table, builds the matcher, and registers per-service hooks.

## Scope

**In scope:**
- `providers:` YAML parsing (keyring, vault; extensible to future providers)
- `services:` YAML parsing (name, match.hosts, secret.ref, fake.format, inject.header)
- Policy validation for both sections
- ServiceMatcher with literal + wildcard host matching
- HeaderInjectionHook for per-service header injection
- Table.RealForService method
- CredsSubHook extended to substitute in headers, URL query, and URL path
- Updated bootstrap flow: policy YAML to live proxy
- Updated production caller (nil,nil to real config)

**Parsed but not wired (forward compatibility):**
- `inject.env` (env var injection — wired in a later plan)
- `scrub_response` (response scrubbing config)
- `hooks` (LLM-specific hook names like `dlp`, `mcp_intercept`)

**Out of scope:**
- Go Service plugin interface (AWS SigV4, GCP OAuth)
- Cross-service detection (`secret_cross_service_use`)
- SSE streaming substitution
- Additional providers (AWS SM, GCP SM, Azure KV, 1Password)
- `process_contexts[].secrets` scoping

---

## Section 1 — YAML Config Model

Two new optional top-level keys in the Policy struct (`internal/policy/model.go`):

```go
Providers map[string]yaml.Node `yaml:"providers,omitempty"`
Services  []ServiceYAML        `yaml:"services,omitempty"`
```

### Provider YAML

Each provider entry has a `type` field plus type-specific fields. The policy model stores entries as `yaml.Node` to defer type-specific parsing to the secrets package (vault needs address/namespace/auth; keyring needs nothing).

```yaml
providers:
  keyring:
    type: keyring
  vault:
    type: vault
    address: https://vault.corp.internal
    namespace: engineering
    auth:
      method: token
      token_ref: keyring://agentsh/vault_token
```

A resolver function decodes each `yaml.Node` into the appropriate `ProviderConfig` based on `type`:

```go
func resolveProviderConfig(name string, node yaml.Node) (secrets.ProviderConfig, error)
```

This switches on `type` and decodes into `keyring.Config`, `vault.Config`, etc.

### Service YAML

Services are an ordered list. Declaration order determines first-match-wins precedence for overlapping host patterns.

```go
type ServiceYAML struct {
    Name          string               `yaml:"name"`
    Match         ServiceMatchYAML     `yaml:"match"`
    Secret        ServiceSecretYAML    `yaml:"secret"`
    Fake          ServiceFakeYAML      `yaml:"fake"`
    Inject        ServiceInjectYAML    `yaml:"inject,omitempty"`
    ScrubResponse bool                 `yaml:"scrub_response,omitempty"`
    Hooks         []string             `yaml:"hooks,omitempty"`
}

type ServiceMatchYAML struct {
    Hosts []string `yaml:"hosts"`
}

type ServiceSecretYAML struct {
    Ref       string `yaml:"ref"`
    OnMissing string `yaml:"on_missing,omitempty"` // "fail" (default); "skip" and "fake_only" reserved for future plans
}

type ServiceFakeYAML struct {
    Format string `yaml:"format"`
}

type ServiceInjectYAML struct {
    Header *ServiceInjectHeaderYAML `yaml:"header,omitempty"`
    Env    []ServiceInjectEnvYAML   `yaml:"env,omitempty"`
}

type ServiceInjectHeaderYAML struct {
    Name     string `yaml:"name"`
    Template string `yaml:"template"` // e.g. "Bearer {{secret}}"
}

type ServiceInjectEnvYAML struct {
    Name string `yaml:"name"`
}
```

Example:

```yaml
services:
  - name: github
    match:
      hosts: ["api.github.com", "*.github.com"]
    secret:
      ref: vault://kv/data/github#token
      on_missing: fail
    fake:
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"

  - name: anthropic
    match:
      hosts: ["api.anthropic.com"]
    secret:
      ref: keyring://agentsh/anthropic_key
      on_missing: fail
    fake:
      format: "sk-ant-{rand:93}"
    inject:
      header:
        name: x-api-key
        template: "{{secret}}"
```

---

## Section 2 — Policy Validation

All validation runs at parse time, before any providers are constructed or secrets fetched. Failures are fatal — session creation aborts with a structured error.

### Provider validation

- Every provider must have a non-empty `type` matching a known scheme (keyring, vault; extensible)
- Duplicate provider names rejected
- Auth-chaining refs (e.g. `token_ref: keyring://...`) must reference a declared provider's scheme
- Circular auth-chaining detected by `secrets.NewRegistry`'s topological sort (existing behavior)

### Service validation

- Duplicate service names rejected
- `match.hosts` must be non-empty; each pattern is either a literal hostname or `*.suffix`
- `secret.ref` must parse as a valid `secrets.SecretRef` (via `secrets.ParseRef`) whose scheme maps to a declared provider
- `fake.format` validated by `fakegen.ParseFormat` (must have `{rand:N}` with N >= 24)
- If `inject.header` is present, `template` must contain `{{secret}}` placeholder
- `on_missing` defaults to `"fail"` if omitted; Plan 6 only accepts `"fail"` — other values (`"skip"`, `"fake_only"`) rejected at parse time until implemented in a later plan
- Overlapping host patterns across services produce a **warning** (not a hard error) with both service names — first-match-wins is intentional

### Backward compatibility

Existing policies without `providers:` or `services:` continue working. Both fields are `omitempty`. When absent, no credential substitution is configured and the proxy behaves exactly as it does today.

---

## Section 3 — ServiceMatcher

New type in `internal/proxy/services/matcher.go`. Pure function — no state, no I/O, no dependencies on proxy or hooks.

### Host pattern matching

- **Literal:** exact match, case-insensitive (`api.github.com` matches `API.GitHub.com`)
- **Wildcard:** `*.example.com` matches `api.example.com` but NOT `example.com` and NOT `sub.api.example.com` (single-level wildcard only)
- **Port stripping:** `api.github.com:443` strips port before matching
- **First-match-wins:** declaration order in YAML determines precedence

### API

```go
type ServicePattern struct {
    Name  string
    Hosts []string // literal hostnames or "*.suffix" wildcards
}

type Matcher struct {
    // pre-compiled patterns, ordered
}

func NewMatcher(services []ServicePattern) *Matcher
func (m *Matcher) Match(host string) (serviceName string, ok bool)
```

The constructor pre-compiles wildcard patterns into suffix checks. `Match` is read-only and safe for concurrent use.

---

## Section 4 — Header Injection

### Real-credential access

The Table's API avoids exposing Real bytes (ContainsFake returns only the service name). But `inject.header` fundamentally needs the real credential to set `Authorization: Bearer <real>`. This is safe because:

- The hook is internal proxy code, not agent-facing
- Real bytes are used transiently within a single request and zeroed after use
- The hook does not store real bytes persistently

New method on `credsub.Table`:

```go
func (t *Table) RealForService(serviceName string) ([]byte, bool)
```

Returns a deep copy. Callers must zero the returned slice when done. Documented as internal proxy use only.

### HeaderInjectionHook

```go
type HeaderInjectionHook struct {
    serviceName string
    headerName  string   // e.g. "Authorization"
    template    string   // e.g. "Bearer {{secret}}"
    table       *credsub.Table
}

func NewHeaderInjectionHook(serviceName, headerName, template string, table *credsub.Table) *HeaderInjectionHook
```

**PreHook behavior:**
1. Look up real credential via `table.RealForService(serviceName)`
2. Strip any existing value the agent set for this header (`req.Header.Del`)
3. Build value: `strings.Replace(template, "{{secret}}", string(real), 1)`
4. Set header: `req.Header.Set(headerName, value)`
5. Zero the temporary real-credential copy

**PostHook:** no-op.

**Registration:** Per service name, so it only fires for matched requests. Runs after CredsSubHook (body substitution happens first, then header is set from scratch).

### Extended CredsSubHook substitution

Plan 5's CredsSubHook substitutes fakes in the request body only. The parent design spec (Section 6 step 4) calls for substitution in headers, URL query, and URL path as well.

Plan 6 extends CredsSubHook.PreHook to also call `table.ReplaceFakeToReal` on:
- Each header value (iterate `r.Header`, replace values in place)
- `r.URL.RawQuery`
- `r.URL.Path` and `r.URL.RawPath`

This handles cases where an SDK puts the fake credential in a query parameter or path segment.

---

## Section 5 — Proxy Integration

### New field and method

The Proxy struct gets a `matcher *services.Matcher` field:

```go
func (p *Proxy) SetMatcher(m *services.Matcher) // thread-safe setter
```

Called after bootstrap completes. No getter needed — matcher is internal.

### ServeHTTP changes

Early in ServeHTTP, after reading the Host header:

```go
serviceName := ""
if p.matcher != nil {
    if name, ok := p.matcher.Match(r.Host); ok {
        serviceName = name
    }
}
reqCtx.ServiceName = serviceName
```

The existing hook dispatch calls `registry.ApplyPreHooks(serviceName, req, ctx)` — global hooks run first (service name `""`), then service-scoped hooks. No change to the Registry needed.

### Hook registration strategy

| Hook | Registration | Rationale |
|------|-------------|-----------|
| LeakGuardHook | Global (`""`) | Must scan ALL requests — but skips matched services (see below) |
| CredsSubHook | Global (`""`) | Table-wide substitution covers all known fakes |
| HeaderInjectionHook | Per service name | Only injects header for the matched service |

**LeakGuardHook service-awareness (Plan 6 change).** In Plan 5, LeakGuardHook blocks any request containing a known fake. This was safe because the table was empty (production caller passed nil,nil). In Plan 6, the table is populated — agents are expected to send fakes to matched services. LeakGuardHook must now check `RequestContext.ServiceName`: if non-empty (host matched a service), skip the scan. If empty (unmatched host), scan for fakes and block with 403 if found. Cross-service detection (service-A fake in service-B request) is out of scope for Plan 6.

**Ordering for a matched request:** LeakGuardHook (global, skips because service matched) -> CredsSubHook (global, body + headers + query + path) -> HeaderInjectionHook (per-service, sets header from scratch). Header injection runs last so it overwrites whatever CredsSubHook did to the same header.

For unmatched hosts (`serviceName = ""`): only global hooks fire. LeakGuardHook scans for fakes and blocks if found. CredsSubHook still runs (harmless — no fakes in unmatched requests unless leak attempted).

---

## Section 6 — Bootstrap Flow

End-to-end wiring from policy YAML to a running proxy with per-service hooks.

### Resolver layer

New `internal/session/secretsconfig.go` bridges policy YAML types to the existing secrets infrastructure:

1. **Parse:** Policy loader deserializes `providers:` and `services:` into YAML types (Section 1).
2. **Resolve providers:** For each provider entry, decode the `yaml.Node` into the appropriate `ProviderConfig` based on `type`. Build `map[string]ProviderConfig` for `secrets.NewRegistry`.
3. **Resolve services:** For each service entry, build a `session.ServiceConfig` (Name, SecretRef, FakeFormat) for `BootstrapCredentials`. Also extract host patterns for ServiceMatcher and inject.header config for HeaderInjectionHook.
4. **Construct provider registry:** `secrets.NewRegistry(ctx, configs, constructors)` — topo sort, auth chaining (existing Plan 4 code).
5. **Bootstrap credentials:** `BootstrapCredentials(ctx, registry.Fetch, serviceConfigs)` — fetch secrets, generate fakes, populate table (existing Plan 5 code).
6. **Build matcher:** `services.NewMatcher(patterns)` from service host patterns.
7. **Register hooks:** LeakGuardHook + CredsSubHook globally (same as Plan 5). For each service with `inject.header`, register `HeaderInjectionHook` under the service name.
8. **Wire proxy:** `proxy.SetMatcher(matcher)`.

### StartLLMProxy signature change

Currently takes `secretsFetcher SecretFetcher, services []ServiceConfig` (Plan 5). Plan 6 changes this to accept the parsed policy provider/service YAML, since the resolver translates YAML to configs internally. The production caller in `app.go` passes the policy's providers/services sections instead of `nil, nil`.

### Failure semantics

Unchanged from Plan 5. Any step failing aborts session creation. Agent never starts with partial config. Already-constructed providers are closed on failure (existing Registry behavior).

---

## Section 7 — Testing

### ServiceMatcher tests

- Literal match, case-insensitive
- Wildcard `*.example.com` matches `api.example.com`, rejects `example.com` and `sub.api.example.com`
- Port stripping (`host:443` matches `host` pattern)
- First-match-wins with overlapping patterns
- No match returns `"", false`
- Empty matcher (no services) — everything unmatched

### HeaderInjectionHook tests

- Template substitution (`Bearer {{secret}}` produces correct header value)
- Strips existing header before setting
- No-op when service not in table
- Zeros temporary credential copy
- PostHook is no-op

### Table.RealForService tests

- Returns deep copy (mutating returned slice does not affect table)
- Returns false for unknown service
- Returns empty after Zero()

### CredsSubHook extended substitution tests

- Fake in header value replaced with real
- Fake in URL query replaced
- Fake in URL path replaced
- Multiple fakes across surfaces all replaced
- Body substitution unchanged (existing tests still pass)

### Policy YAML parsing tests

- Valid config: keyring + vault providers, two services, all fields populated
- Unknown provider type rejected
- Service referencing undeclared provider scheme rejected
- Duplicate service names rejected
- Invalid fake.format rejected
- Missing `{{secret}}` in inject.header.template rejected
- Overlapping hosts produce warning (not error)
- Empty providers/services sections: backward compatible with existing policies
- on_missing defaults to "fail" when omitted
- Invalid on_missing value rejected

### Integration test

End-to-end: parse policy YAML with test-double providers, bootstrap credentials, construct matcher and hooks, send HTTP request to proxy with matching host, verify:
- Host matched to correct service
- Body fakes replaced with reals
- Header injected with real credential from template
- Response body reals replaced with fakes

---

## Section 8 — File Layout

### New files

| File | Responsibility |
|------|---------------|
| `internal/proxy/services/matcher.go` | ServiceMatcher, host pattern matching |
| `internal/proxy/services/matcher_test.go` | Matcher unit tests |
| `internal/policy/secrets.go` | ProviderYAML, ServiceYAML types, validation functions |
| `internal/policy/secrets_test.go` | YAML parsing and validation tests |
| `internal/session/secretsconfig.go` | Resolver: YAML to ProviderConfig + ServiceConfig, wiring logic |
| `internal/session/secretsconfig_test.go` | Resolver tests |

### Modified files

| File | Change |
|------|--------|
| `internal/policy/model.go` | Add `Providers` and `Services` fields to Policy struct |
| `internal/proxy/credsub/table.go` | Add `RealForService` method |
| `internal/proxy/credsub/table_test.go` | RealForService tests |
| `internal/proxy/credshook.go` | Add HeaderInjectionHook; extend CredsSubHook for headers/query/path |
| `internal/proxy/credshook_test.go` | HeaderInjectionHook tests, extended substitution tests |
| `internal/session/llmproxy.go` | Updated bootstrap flow, accepts policy config |
| `internal/session/llmproxy_test.go` | Updated call sites |
| `internal/proxy/proxy.go` | Add matcher field, SetMatcher, use matcher in ServeHTTP |
| `internal/api/app.go` | Pass policy providers/services to StartLLMProxy |
