# Unified HTTP Services — Design

**Date:** 2026-04-12
**Status:** Design (pre-implementation)
**Related specs:**
- `docs/superpowers/specs/2026-04-10-http-path-verb-filtering-design.md` (existing `http_services:` path/verb filtering)
- `docs/superpowers/specs/2026-04-09-plan-06-service-config-routing-design.md` (existing `services:` credential substitution)
- `docs/superpowers/specs/2026-04-07-external-secrets-design.md` (parent secrets design)

## Problem

Operators today configure the same logical service in two separate YAML sections:

- `services:` (Plan 6) — credential substitution: `name`, `match.hosts`, `secret.ref`, `fake.format`, `inject.header`. Dispatches by Host-header matching via `services.Matcher`.
- `http_services:` — path/verb filtering: `name`, `upstream`, `rules`, `default`. Dispatches by `/svc/<name>/` path prefix.

This split is confusing and error-prone. An operator who wants GitHub routed through the gateway with credential injection AND read-only path filtering must configure the same service in two places, keep the names in sync, and understand two dispatch mechanisms. Internally, the codebase carries two matchers, two compiled structures, two registration flows, and two bootstrap paths for what is conceptually one thing.

Additionally, the `LeakGuardHook` already enforces cross-service credential isolation (`serviceName != ctx.ServiceName`), but the audit log does not distinguish "fake leaked to unmatched host" from "fake from service A sent to service B." Operators need separate event names to triage these differently.

## Goal

Merge `services:` into `http_services:` as a single unified declaration. Remove the Host-based `services.Matcher`. Add a differentiated `secret_cross_service_use` audit event. Update operator documentation with credential-backed recipes.

## Approach

**Full unification, path-prefix only.** The `http_services:` YAML key absorbs the credential fields (`secret`, `inject`, `scrub_response`) from the old `services:` section. The `services:` key is removed entirely (clean break — no backward compatibility shim). The Host-based `services.Matcher` is deleted; all declared-service dispatch is via `/svc/<name>/` path prefix. The `providers:` section is unchanged.

Two alternatives were considered and rejected:

- **Unified YAML + host-based fallback:** Keeps the `Matcher` for requests that arrive on the LLM path with a matching Host header. Rejected because no current use case needs it — LLM traffic has its own dialect detection, and declared-service traffic routes through the path prefix.
- **Unified YAML surface, two internal models:** Single YAML section but internally parses into both `compiledHTTPService` and Plan 6 service config. Rejected because it preserves all the internal complexity under a cosmetic fix.

---

## Section 1 — Unified YAML Schema

The `http_services:` entry absorbs credential fields from the old `services:` section. Both `secret` and `rules` are independently optional, allowing three usage patterns: credentials-only, filtering-only, or both.

The `providers:` top-level key is unchanged — it declares secret stores. `http_services[].secret.ref` references a declared provider via URI scheme.

### Full example

```yaml
providers:
  vault:
    type: vault
    address: https://vault.corp.internal
    namespace: engineering
    auth:
      method: token
      token_ref: keyring://agentsh/vault_token
  keyring:
    type: keyring

http_services:
  # Full service: credentials + path/verb filtering
  - name: github
    upstream: https://api.github.com
    expose_as: GITHUB_API_URL
    aliases: [api.github.com]
    allow_direct: false
    default: deny

    secret:
      ref: vault://kv/data/github#token
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"
    scrub_response: true

    rules:
      - name: read-issues
        methods: [GET]
        paths:
          - /repos/*/*/issues
          - /repos/*/*/issues/*
        decision: allow
      - name: create-issue
        methods: [POST]
        paths:
          - /repos/*/*/issues
        decision: approve
        message: "Agent wants to create an issue"
        timeout: 30s

  # Credentials only (no filtering — all requests forwarded)
  - name: anthropic
    upstream: https://api.anthropic.com
    secret:
      ref: keyring://agentsh/anthropic_key
      format: "sk-ant-{rand:93}"
    inject:
      header:
        name: x-api-key
        template: "{{secret}}"

  # Filtering only (no credentials)
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

### Semantics

- **At least one of `secret` or `rules` must be present.** A service with neither is rejected at load time.
- **`inject` requires `secret`.** Rejected if `inject` is set but `secret` is nil.
- **`scrub_response`** defaults to `true` when `secret` is present, `false` when absent. Explicit `false` with `secret` is honored.
- **`default` behavior depends on whether rules are present.** When `default` is explicitly set, that value is used. When `default` is empty and `rules` are present, it defaults to `deny` (fail-closed, same as today). When `default` is empty and `rules` are absent (credentials-only service), it defaults to `allow` — because the entire point of a credentials-only service is forwarding requests with credential substitution, and denying everything would be useless.
- **Credentials-only services** (no `rules`) implicitly allow all requests — the gateway forwards everything, credential substitution and scrubbing still apply. Operators can still set `default: deny` explicitly to block all traffic while keeping the credential infrastructure wired (useful for emergency lockdown).
- **Filtering-only services** (no `secret`) work exactly as they do today — no hooks registered, no credential injection.

### What the old `services:` key looked like (removed)

For migration reference, the old `services:` section declared:

```yaml
# OLD — no longer accepted
services:
  - name: github
    match:
      hosts: ["api.github.com", "*.github.com"]
    secret:
      ref: vault://kv/data/github#token
    fake:
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"
```

In the unified model, `match.hosts` is gone (dispatch is by path prefix, not Host header). `fake.format` moves to `secret.format`. Everything else maps directly.

---

## Section 2 — Policy Model Changes

### Removed

**Delete `internal/policy/secrets.go` entirely.** Types removed:

- `ServiceYAML`, `ServiceMatchYAML`, `ServiceSecretYAML`, `ServiceFakeYAML`
- `ServiceInjectYAML`, `ServiceInjectHeaderYAML`, `ServiceInjectEnvYAML`
- `ValidateSecrets` function
- `knownProviderTypes` map (moves to `http_service.go`)

**Remove from `internal/policy/model.go`:**

- `Services []ServiceYAML` field from `Policy` struct
- The comment "orthogonal to `services:` (Plan 6)"

### Added to `internal/policy/http_service.go`

New types extending `HTTPService`:

```go
type HTTPService struct {
    Name        string            `yaml:"name"`
    Upstream    string            `yaml:"upstream"`
    ExposeAs    string            `yaml:"expose_as,omitempty"`
    Aliases     []string          `yaml:"aliases,omitempty"`
    AllowDirect bool              `yaml:"allow_direct,omitempty"`
    Default     string            `yaml:"default,omitempty"`
    Rules       []HTTPServiceRule `yaml:"rules,omitempty"`

    // Credential substitution (absorbed from old services:).
    Secret        *HTTPServiceSecret `yaml:"secret,omitempty"`
    Inject        *HTTPServiceInject `yaml:"inject,omitempty"`
    ScrubResponse *bool              `yaml:"scrub_response,omitempty"` // nil = default based on Secret presence
}

type HTTPServiceSecret struct {
    Ref    string `yaml:"ref"`    // e.g. "vault://kv/data/github#token"
    Format string `yaml:"format"` // e.g. "ghp_{rand:36}"
}

type HTTPServiceInject struct {
    Header *HTTPServiceInjectHeader `yaml:"header,omitempty"`
}

type HTTPServiceInjectHeader struct {
    Name     string `yaml:"name"`     // e.g. "Authorization"
    Template string `yaml:"template"` // e.g. "Bearer {{secret}}"
}
```

`ScrubResponse` is `*bool` to distinguish "not set" (default based on `Secret` presence) from explicit `false`.

`knownProviderTypes` and provider-scheme validation logic move from the deleted `secrets.go` into `http_service.go`.

`Providers map[string]yaml.Node` stays on the `Policy` struct unchanged.

---

## Section 3 — Validation Merge

`ValidateSecrets` is deleted. Its responsibilities merge into `ValidateHTTPServices`, which becomes the single validation entry point for both structural and credential rules.

### New validation rules

| Rule | Error |
|------|-------|
| At least one of `secret` or `rules` present | `"service %q has no secret and no rules"` |
| `inject` without `secret` | `"service %q: inject requires secret"` |
| `secret.ref` parses via `secrets.ParseRef` | `"service %q: invalid secret ref: %v"` |
| `secret.ref` scheme matches a declared provider | `"service %q: secret ref scheme %q has no matching provider"` |
| `secret.format` passes `fakegen.ParseFormat` | `"service %q: invalid fake format: %v"` |
| `inject.header.template` contains `{{secret}}` | `"service %q: inject.header.template must contain {{secret}}"` |

### Existing validation (unchanged)

- Service name uniqueness and URL-safe characters (`^[A-Za-z0-9._-]+$`)
- Upstream must be `https://` with non-empty host
- Duplicate host detection (upstream + aliases across all services)
- Env var name validation (`expose_as` or derived default) and collision detection with reserved names
- Rule validation: decision values, glob compilation, methods
- `allow_direct`, `timeout` validation

### `default` defaulting

When `Default` is empty:
- If `Rules` is non-empty: `deny` (fail-closed — operator must whitelist explicitly)
- If `Rules` is empty: `allow` (credentials-only service — forwarding is the point)

Resolved at validation time and stored on the compiled structure.

### `scrub_response` defaulting

When `ScrubResponse` is nil:
- If `Secret != nil`: treated as `true`
- If `Secret == nil`: treated as `false`

Resolved at validation time and stored on the compiled structure.

### Old `services:` key rejection

Go's `yaml.v3` silently ignores unknown keys by default. To detect the old `services:` key, add a `Services yaml.Node` field to `Policy` with the tag `yaml:"services,omitempty"`. During validation, if this field is non-zero (i.e. the YAML contained `services:`), emit a clear error: `"the 'services:' key has been replaced by 'http_services:' — move secret, inject, and scrub_response fields into your http_services entries"`. The field is never used for anything else — it exists solely as a migration tripwire.

### Backward compatibility

Policies without `providers:` or `http_services:` continue working. Both fields are `omitempty`. When absent, no credential substitution or service filtering is configured.

---

## Section 4 — Session Bootstrap Changes

### `StartLLMProxy` signature

```go
func StartLLMProxy(
    sess *Session,
    proxyCfg config.ProxyConfig,
    dlpCfg config.DLPConfig,
    storageCfg config.LLMStorageConfig,
    mcpCfg config.SandboxMCPConfig,
    storagePath string,
    logger *slog.Logger,
    providers map[string]yaml.Node,
    httpServices []policy.HTTPService,  // was: policyServices []policy.ServiceYAML
    envInject map[string]string,
) (string, func() error, error)
```

### Bootstrap flow

1. **Filter** `httpServices` to those with `Secret != nil` — only these need credential bootstrap.
2. `ResolveProviderConfigs(providers)` — decode provider YAML nodes (unchanged).
3. `BuildSecretsRegistry` → `BootstrapCredentials` — fetch secrets, generate fakes, populate table (unchanged logic).
4. Register hooks: `LeakGuardHook` + `CredsSubHook` globally, `HeaderInjectionHook` per service with `Inject.Header` (unchanged).
5. **No `Matcher` construction, no `SetMatcher` call** — removed.
6. Service env vars handled by `Proxy.EnvVars()` via `http_services` — the separate `BuildServiceEnvVars` / `sess.SetServiceEnvVars` path for the old `services:` is removed.

### `ResolveServiceConfigs` changes

Input type changes from `[]policy.ServiceYAML` to `[]policy.HTTPService`. Iterates services where `Secret != nil`, extracting:

- `ServiceConfig{Name, SecretRef, FakeFormat}` from `svc.Secret`
- `InjectHeader{ServiceName, HeaderName, Template}` from `svc.Inject.Header`
- `ScrubServices` map from resolved `ScrubResponse` values

The `Patterns []services.ServicePattern` output (used by the old Matcher) is dropped.

### Caller change

`internal/api/app.go` passes `policy.HTTPServices` instead of `policy.Services`.

---

## Section 5 — Matcher Removal

The `services.Matcher` (Plan 6's Host-header-to-service-name resolver) has no remaining consumer after unification. All declared-service dispatch is via `declaredService()` path-prefix lookup.

### Deleted

| Item | Location |
|------|----------|
| `internal/proxy/services/matcher.go` | `Matcher`, `ServicePattern`, `hostPattern` types |
| `internal/proxy/services/matcher_test.go` | All matcher tests |
| `matcher *services.Matcher` field | `internal/proxy/proxy.go` `Proxy` struct |
| `SetMatcher(m *services.Matcher)` method | `internal/proxy/proxy.go` |
| `import "...proxy/services"` | `internal/proxy/proxy.go`, `internal/session/llmproxy.go` |
| `services.NewMatcher(resolved.Patterns)` + `p.SetMatcher(matcher)` | `internal/session/llmproxy.go` lines 161-162 |
| `Patterns` field | `secretsconfig.go` resolved config struct |
| `ServicePattern` construction from `ServiceMatchYAML.Hosts` | `secretsconfig.go` |

### What stays

- `DeclaredHTTPServiceHost()` on the policy engine — used by the fail-closed CONNECT check in `netmonitor/proxy.go`. Reads from `compiledHTTPService.upstream` + aliases. Unrelated to the removed `Matcher`.
- `declaredService()` in `proxy.go` — path-prefix dispatch, the sole service resolution mechanism.

---

## Section 6 — Cross-Service Audit Event

The enforcement logic in `LeakGuardHook` already blocks cross-service credential use (`serviceName != ctx.ServiceName` → 403). The change is a differentiated audit event so operators can distinguish the two failure modes.

### `LeakGuardHook.PreHook` change

When a fake is detected and `serviceName != ctx.ServiceName`:

- If `ctx.ServiceName == ""` (unmatched host): log `secret_leak_blocked` — unchanged.
- If `ctx.ServiceName != ""` (matched service, fake belongs to different service): log `secret_cross_service_use` with both service names.

```go
if serviceName != ctx.ServiceName {
    if ctx.ServiceName == "" {
        h.logLeak(ctx, serviceName, r.Host)
    } else {
        h.logCrossService(ctx, serviceName, ctx.ServiceName, r.Host)
    }
    return &HookAbortError{StatusCode: 403, Message: "credential leak blocked"}
}
```

### New `logCrossService` method

```go
func (h *LeakGuardHook) logCrossService(ctx *RequestContext, sourceService, targetService, requestHost string) {
    h.logger.Warn("secret_cross_service_use",
        "session_id", ctx.SessionID,
        "request_id", ctx.RequestID,
        "source_service", sourceService,
        "target_service", targetService,
        "request_host", requestHost,
    )
}
```

### 403 message stays generic

The response body says `"credential leak blocked"` in both cases. No information about which service's credential was detected or the routing mismatch — prevents attacker-controlled tools from probing the credential map.

---

## Section 7 — Documentation

### `docs/cookbook/http-services.md` updates

Add a "How credential substitution works" section at the top explaining the end-to-end flow:

1. Operator declares `providers:` (where secrets live) and `http_services:` entries with `secret:` (which service uses which secret)
2. At session start, agentsh fetches the real secret from the provider
3. A fake credential with matching format and length is generated
4. The agent receives `<NAME>_API_URL` pointing at the gateway — it never sees the real credential
5. On egress: gateway replaces fakes with reals in body, headers, query, path; injects real credential into configured header
6. On response: gateway replaces reals with fakes before returning to agent
7. LeakGuard blocks fakes sent to wrong service or unmatched hosts

New recipes:

- **Route GitHub through the gateway with a Vault-backed token** — full `providers:` + `http_services:` example with credential substitution and read-only rules
- **Use OS keyring for a simple API key** — minimal example with `keyring://` provider
- **Credential-only service (no path filtering)** — service with `secret:` and `inject:` but no `rules:`
- **Credentials + filtering combined** — the full pattern

### `docs/llm-proxy.md` updates

Update the "Declared HTTP Services" reference section:

- Add `secret:`, `inject:`, `scrub_response:` to the configuration example and schema table
- Document the relationship between `providers:` and `http_services[].secret.ref`
- Document `scrub_response` defaulting behavior
- Update "When to use http_services" guidance to mention credential substitution

---

## Section 8 — Testing Strategy

### Unit tests — policy validation (`internal/policy/http_service_test.go`)

- Service with `secret` + `rules` passes validation
- Service with `secret` only (no rules) passes
- Service with `rules` only (no secret) passes
- Service with neither `secret` nor `rules` rejected
- `inject` without `secret` rejected
- `secret.ref` referencing undeclared provider scheme rejected
- `secret.ref` with invalid URI rejected
- `secret.format` with invalid template rejected (missing `{rand:N}`, entropy < 24)
- `inject.header.template` missing `{{secret}}` rejected
- `scrub_response` defaults: `true` when secret present, `false` when absent
- Explicit `scrub_response: false` with secret honored
- `default` defaults to `deny` when rules present, `allow` when rules absent (credentials-only)
- Explicit `default: deny` on credentials-only service honored
- Provider validation rules carry over (unknown type, duplicate names, auth-chaining refs)
- Policy with only `providers:` and no `http_services:` loads fine
- Policy with old `services:` key rejected with clear migration error

### Unit tests — resolver (`internal/session/secretsconfig_test.go`)

- Mixed services (some with secrets, some without) — only secret-bearing services produce `ServiceConfig` entries
- `InjectHeaders` extracted correctly from services with `inject.header`
- `ScrubServices` map built correctly from `scrub_response` defaults and overrides
- No `Patterns` output (old matcher data gone)

### Unit tests — bootstrap (`internal/session/secrets_test.go`)

- `BootstrapCredentials` with services resolved from `HTTPService` structs
- Round-trip: real secret fetched → fake generated → table populated → hook registered → request with fake produces upstream with real → response with real returns fake to agent

### Integration tests — proxy (`internal/proxy/proxy_test.go`)

**Credential + filtering combined:**
- `GET /svc/github/repos/owner/repo/issues` with allow rule → upstream receives real credential in `Authorization` header, body fakes replaced, response reals scrubbed
- `DELETE /svc/github/repos/owner/repo` with deny rule → 403, upstream never contacted

**Credential-only service:**
- Any method/path forwards (implicit allow-all)
- Credential substitution works on body and headers

**Filtering-only service:**
- Allowed requests forward without credential injection
- Denied requests get 403
- No hooks registered for this service

**Cross-service audit event:**
- Service A fake in request to service B → 403, log contains `secret_cross_service_use` with `source_service` and `target_service`
- Service A fake in request to service A → allowed
- Any fake in request to unmatched host → 403, log contains `secret_leak_blocked`

**Matcher removal regression:**
- No `SetMatcher` call in bootstrap
- Request with `Host: api.github.com` but no `/svc/github/` prefix goes to LLM dialect path, not declared service

### Cross-compile gate

`GOOS=windows go build ./...` before commit, per CLAUDE.md.

---

## Section 9 — File Layout

### Deleted files

| File | Reason |
|------|--------|
| `internal/proxy/services/matcher.go` | Host-based matching removed |
| `internal/proxy/services/matcher_test.go` | Tests for removed code |
| `internal/policy/secrets.go` | `ServiceYAML` types replaced by unified `HTTPService` |
| `internal/policy/secrets_test.go` | Tests for removed types |

### Modified files

| File | Change |
|------|--------|
| `internal/policy/model.go` | Remove `Services []ServiceYAML` field from `Policy` |
| `internal/policy/http_service.go` | Add `HTTPServiceSecret`, `HTTPServiceInject`, `HTTPServiceInjectHeader` types; merge provider validation |
| `internal/policy/http_service_test.go` | Add credential validation tests, old-key rejection test |
| `internal/proxy/proxy.go` | Remove `matcher` field, `SetMatcher`, `services` import |
| `internal/proxy/credshook.go` | Add `logCrossService` method, branch in `PreHook` |
| `internal/proxy/credshook_test.go` | Cross-service audit event tests |
| `internal/session/llmproxy.go` | Signature change (`[]policy.HTTPService`), remove matcher construction |
| `internal/session/secretsconfig.go` | `ResolveServiceConfigs` takes `[]policy.HTTPService`, remove `Patterns` output |
| `internal/session/secretsconfig_test.go` | Updated for new input type |
| `internal/api/app.go` | Pass `policy.HTTPServices` instead of `policy.Services` |
| `docs/cookbook/http-services.md` | Credential-backed recipes, "how credential substitution works" explainer |
| `docs/llm-proxy.md` | Update "Declared HTTP Services" reference with `secret:`, `inject:`, `scrub_response:` |

No new files. No new packages.
