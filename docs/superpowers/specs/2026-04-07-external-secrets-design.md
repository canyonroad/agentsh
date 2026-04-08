# External Secrets & Fake Credential Substitution — Design

**Date:** 2026-04-07
**Status:** Design (pre-implementation)
**Owner:** Eran Sandler

## Problem

agentsh today lets operators inject environment variables into spawned sessions via `env_inject` and runs an LLM proxy that tokenizes PII out of LLM request bodies. Neither mechanism solves the broader problem that AI agents routinely need real credentials — GitHub tokens, AWS keys, Anthropic API keys, DB passwords — and any of those credentials, once in the agent's address space, can be exfiltrated by a misbehaving tool call, a prompt injection, or a subtly wrong HTTP destination.

We want agentsh to:

1. Fetch secrets from a variety of external secret stores (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, 1Password, OS keyring).
2. Give the spawned agent *fake* credentials with the same shape as the real ones.
3. When the agent makes an outbound HTTP request with a fake credential, substitute the real credential at egress.
4. Do this without TLS man-in-the-middle — terminate the request locally, rebuild it, send the real one upstream.
5. Cover all keys that the agent sees, including plain environment variables — not just LLM API keys.

v1 ships Mechanism A (explicit local proxy, cooperative SDKs) and leaves Mechanisms B (Linux TLS uprobes) and C (per-tool credential helpers) as future phases.

## Goals

- Real credentials never enter the spawned agent's address space.
- Fake credentials that leave the sandbox via a policy-allowed destination get rewritten to real credentials at egress.
- Fake credentials that try to leave the sandbox via an *unallowed* destination are blocked, and an audit event fires.
- Secret store support is extensible — adding Doppler or Infisical later does not require rewriting the core.
- Service support (GitHub, Stripe, Anthropic, ...) is extensible via config without recompiling for 80% of the cases.
- Pluggable for the 20% that need custom auth logic (AWS SigV4, OAuth refresh).
- Existing `internal/llmproxy` package is renamed to `internal/proxy` to reflect that it is now a general-purpose substituting proxy, not an LLM-specific thing. LLM-specific concerns move to `internal/proxy/llm`.

## Non-goals (v1)

See Section 10 at the end of this document for the full out-of-scope list. The headline exclusions:

- No per-request credential rotation.
- No lazy materialization — all secrets fetched at session start.
- No auto-renewal of Vault leases mid-session.
- No defense against local root attackers reading the daemon's memory.
- No defense against a malicious operator writing a policy that points at an attacker-controlled backend.
- Mechanism B (eBPF) and Mechanism C (per-tool helpers) are sketched but not implemented.

## Mechanism overview

Three layered mechanisms were considered. v1 ships only Mechanism A.

**A. Explicit local proxy (v1).** The spawned process's environment is set so that cooperating SDKs and tools talk to agentsh's local proxy for the services they use. The proxy terminates HTTP, scans the body and headers for known fakes, rewrites them to real credentials, and forwards the reconstructed request upstream. Covers: Anthropic/OpenAI SDKs via `*_BASE_URL`, any service with an SDK that honors `HTTPS_PROXY`, any service with a configurable endpoint. This is how the existing LLM proxy already works — we are generalizing it.

**B. Linux TLS uprobes (future).** eBPF uprobes on `SSL_write`, `gnutls_record_send`, and Go's `crypto/tls.(*Conn).Write` catch plaintext before encryption and rewrite in place. Covers the long tail of Linux tools that ignore proxy env vars. Linux-only, requires `CAP_BPF`. Not in v1 — risky, fragile, per-library work.

**C. Per-tool credential helpers (future).** `git credential.helper`, `aws credential_process`, `gh` auth, `kubectl` exec plugins, `docker` credsStore. Cross-platform, deterministic, one shim per tool. Not in v1 — unbounded per-tool work.

In v1 the agent SDK cases are Mechanism A. A tool that does not cooperate with Mechanism A either gets a best-effort fallback (the proxy sees the TLS CONNECT, cannot rewrite the body, and the tool's authentication fails loudly) or the operator excludes it from the fake-substitution set.

## Section 1 — Package rename

`internal/llmproxy` is renamed to `internal/proxy`. LLM-specific code moves to `internal/proxy/llm`.

**Why:** the existing package name is a lie after v1. It already carries generic substitution plumbing; with the addition of non-LLM services (GitHub, Stripe, AWS) it will be the generic egress substitution engine. Keeping the name `llmproxy` would confuse every future reader.

**Scope of the rename:**

- `internal/llmproxy/` → `internal/proxy/`
- `internal/llmproxy/proxy.go` → `internal/proxy/proxy.go` (generic HTTP termination, substitution, forwarding)
- `internal/llmproxy/dlp.go` → `internal/proxy/llm/dlp.go` (LLM-specific DLP stays LLM-specific)
- `internal/llmproxy/dialect.go` → `internal/proxy/llm/dialect.go` (Anthropic/OpenAI dialect detection)
- `internal/llmproxy/mcp*.go` → `internal/proxy/llm/mcp*.go` (MCP intercept is an LLM concern for now)
- Session field `llmProxyURL` → `proxyURL`
- Session method `LLMProxyEnvVars()` → `ProxyEnvVars()`
- Audit event type `llm_logs` → `proxy_logs` (with a brief compatibility shim that accepts both names during log ingest)

**Why this is cheap:** the public-facing types in the existing `internal/llmproxy/proxy.go` are already named `Proxy`, `Config`, `Server` — not `LLMProxy`. The rename is mostly a directory move plus find-and-replace on the import paths and three session field references.

**Backward compatibility:** operators with old configs that reference `llm_logs` in log filters continue working via the compatibility shim. The rename is not reflected in config keys because there are none with `llm` in them.

### Hooks for LLM-specific behavior

After the rename, `internal/proxy/proxy.go` is a generic HTTP substituting proxy. LLM-specific concerns — DLP tokenization, dialect detection, MCP intercept, SSE streaming awareness, token counting — move behind a `Hook` interface defined in `internal/proxy`:

```go
type Hook interface {
    Name() string
    PreHook(*http.Request, *RequestContext) error   // before substitution
    PostHook(*http.Response, *RequestContext) error // after upstream response
}
```

The LLM subpackage registers its hooks at session start via a hook registry keyed by service name:

```go
// internal/proxy/llm/register.go
func RegisterHooks(p *proxy.Proxy) {
    p.RegisterHook("anthropic", &DLPHook{...})
    p.RegisterHook("openai", &DLPHook{...})
    p.RegisterHook("anthropic", &MCPInterceptHook{...})
}
```

This keeps the generic substitution engine free of LLM-specific knowledge and lets future non-LLM services (GitHub, Stripe) opt in to their own hooks without touching the core.

## Section 2 — SecretProvider interface

```go
// internal/proxy/secrets/provider.go
type SecretProvider interface {
    Name() string
    Fetch(ctx context.Context, ref SecretRef) (SecretValue, error)
    Close() error
}

type SecretRef struct {
    URI      string            // "vault://kv/data/github#token"
    Metadata map[string]string // provider-specific hints
}

type SecretValue struct {
    Value     []byte
    TTL       time.Duration // zero means "no lease info"
    LeaseID   string        // empty if not leased
    Version   string        // for versioned stores
    FetchedAt time.Time
}
```

Providers implemented in v1:

| URI scheme | Provider | Tier | Notes |
|---|---|---|---|
| `vault://` | HashiCorp Vault + OpenBao | 1 | KV v1, KV v2, generic secrets. Auth via token / approle / kubernetes. |
| `aws-sm://` | AWS Secrets Manager | 1 | SigV4, ambient credentials or explicit IAM role. |
| `gcp-sm://` | GCP Secret Manager | 1 | ADC or explicit SA key. |
| `azure-kv://` | Azure Key Vault | 1 | MSI or explicit SP. |
| `op://` | 1Password (Connect API or CLI fallback) | 1 | Connect by default, `op` CLI as a pluggable backend. |
| `keyring://` | OS keyring | 1 | macOS Keychain, Linux Secret Service (GNOME Keyring, KWallet via libsecret), Windows Credential Manager. |

Each provider lives in its own subpackage: `internal/proxy/secrets/vault`, `.../awssm`, `.../gcpsm`, `.../azurekv`, `.../onepassword`, `.../keyring`. Each exports a `New(config ProviderConfig) (SecretProvider, error)` constructor.

**URI grammar.** Every secret reference is a URI of the shape `scheme://<provider-path>[#<field>]`. The scheme picks the provider; the path identifies the secret within the provider's namespace; the optional `#field` selects one key inside a multi-field secret (e.g., a KV entry with `{token: ..., endpoint: ...}`). For providers that do not have multi-field secrets (plain string values), the fragment is omitted. The `op://` scheme accepts either the 1Password URI format (`op://vault/item/field`) for both the Connect API and the `op` CLI backend — they are interchangeable once the provider is configured.

**Secret-reference auth chaining.** Providers that need their own credentials to bootstrap (e.g., Vault needs a token, 1Password Connect needs an API key) can reference another provider. The canonical example:

```yaml
providers:
  keyring:
    type: keyring
  vault:
    type: vault
    address: https://vault.corp.internal
    auth:
      method: token
      token_ref: keyring://agentsh/vault_token
```

The loader resolves `keyring` first, then passes the token into the Vault provider constructor. Circular references are detected at load time and rejected.

**Error handling.** Providers return `ErrNotFound` for missing secrets, `ErrUnauthorized` for auth failures, and wrapped transport errors otherwise. The service layer decides whether a missing secret is fatal for the session (`on_missing: fail | skip | fake_only`).

**Lifecycle.** `Close()` is called when the agentsh daemon shuts down. Providers that hold long-lived connections (Vault lease renewer, 1Password Connect HTTP client) clean up here. Per-session lifecycle is handled at a higher layer — v1 does not renew leases.

## Section 3 — Service abstraction

A "service" is a named external HTTP API that agentsh knows how to substitute credentials for. Examples: `github`, `stripe`, `anthropic`, `openai`, `datadog`, `pypi`.

Each service declaration answers five questions:

1. **Identity:** what is it called, and which hosts does it match?
2. **Secret source:** which provider URI yields the real credential?
3. **Fake shape:** how do we generate a fake with the same structure as the real one?
4. **Injection:** how does the real credential get injected into the outbound request? (Header? Query? Body?)
5. **Substitution:** on ingress from the agent, where in the request body do we scan for the fake?

v1 uses a hybrid model: YAML for the declarative 80%, Go plugins for the 20% with custom auth.

### YAML (declarative, generic engine)

```yaml
services:
  - name: github
    match:
      hosts: ["api.github.com", "*.github.com"]
    secret:
      ref: vault://kv/data/github#token
    fake:
      format: "ghp_{rand:36}"   # rand:N = N base62 random chars
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"
    scrub_response: true        # scan response body for real cred, substitute back to fake

  - name: stripe
    match:
      hosts: ["api.stripe.com"]
    secret:
      ref: op://Personal/Stripe/credential
    fake:
      format: "sk_live_{rand:24}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"
```

The generic engine handles:
- Host matching (literal + wildcard, first-match-wins ordering)
- Fake generation with length-preserving random strings
- Header substitution via template
- Response body scanning via Aho-Corasick
- Error propagation back to the agent (HTTP 401 if upstream rejected the real credential, unchanged status from upstream otherwise)

### Go plugins (escape hatch for hard cases)

```go
// internal/proxy/services/plugin.go
type Service interface {
    Name() string
    Match(host string) bool
    Inject(req *http.Request, secret SecretValue) error
    ScrubResponse(resp *http.Response, table *credsub.Table) error
}
```

Implemented in v1:

- **AWS (SigV4)** — canonical request construction, header rewrite, handles the `X-Amz-Security-Token` flow. YAML cannot express this because the signature depends on the method, path, query, and body.
- **GCP OAuth refresh** — service account JWT → OAuth access token, with caching. YAML cannot express token refresh.

Plugins register themselves at init time:

```go
// internal/proxy/services/aws/aws.go
func init() {
    services.Register(&AWSService{})
}
```

At load time the policy resolver checks: for each service reference in the policy, does it resolve to either a YAML declaration or a registered plugin? If not, load fails.

### Why hybrid over pure-YAML or pure-plugin

- **Pure YAML** cannot handle SigV4, OAuth refresh, or any service that needs multi-step auth. Ruled out.
- **Pure plugin** makes adding a new REST API service a compile-and-release cycle. That is the common case — we should keep it cheap.
- **Hybrid** gives us a declarative fast path and an escape hatch. The same model will handle secret stores (providers) and services uniformly.

## Section 4 — credsub.Table

```go
// internal/proxy/credsub/table.go
type Table struct {
    mu      sync.RWMutex
    entries []Entry
    // ahocorasick automaton rebuilt on each mutation
    ac      *ahocorasick.Matcher
}

type Entry struct {
    ServiceName string
    Fake        []byte
    Real        []byte
    AddedAt     time.Time
}

func New() *Table
func (t *Table) Add(serviceName string, fake, real []byte) error
func (t *Table) FakeForService(name string) ([]byte, bool)
func (t *Table) ReplaceFakeToReal(body []byte) []byte       // ingress from agent
func (t *Table) ReplaceRealToFake(body []byte) []byte       // egress to agent (response scrub)
func (t *Table) Contains(fake []byte) (Entry, bool)
func (t *Table) Zero()                                      // scrub all entries on session close
```

One table per session. Constructed at session start, stored on the `Session` struct in `internal/session/manager.go`, zeroed in the session's `Close()` path.

**Length preservation.** Every `Add` enforces that `len(fake) == len(real)`. This is critical for Mechanism B to work later (in-place `bpf_probe_write_user` rewrite). It is also nice for v1 because it means substitution does not shift byte offsets in JSON bodies — no need to recompute `Content-Length` in the substitution step (though the proxy recomputes it anyway from the rewritten body). The fake generator is given the real secret's length at session start; it emits a random string of that exact length using the format template's prefix and filling the remainder with base62 random chars. If the format template's fixed prefix (e.g., `ghp_`) is longer than the real secret's length, session creation fails with `secret_fake_format_too_long`.

**Collision handling.** Fake generation uses crypto/rand. The loader enforces a minimum of 24 random chars in any fake format template (birthday-bound collision probability ~2⁻⁷¹ for base62). v1 does a best-effort check at generation time: regenerate once if the fake already appears in the table or happens to equal the real value of any entry. If that retry also collides, session creation fails with `secret_fake_collision`.

**Substitution surfaces.** The proxy calls `ReplaceFakeToReal` separately for: the request body, each HTTP header value, the URL query string, and the URL path. The Table is a pure `[]byte → []byte` transformer; the proxy is responsible for deciding which byte slices to run through it. On responses, the proxy calls `ReplaceRealToFake` on the body only (headers and status lines are not scrubbed in v1).

**Real-to-fake substitution on responses.** If a service has `scrub_response: true`, the proxy scans response bodies (only; see substitution surfaces above) for the real credential and rewrites back to the fake before returning to the agent. Aho-Corasick scan is O(n + m) in body size + pattern count. Binary response blobs are scanned bytewise too — we do not try to parse content-types.

**No persistence.** The table lives in memory. Session close zeroes the buffers. v1 does not persist for restart recovery.

## Section 5 — Session start flow

Sequence when a new session begins:

1. **Policy load.** `internal/policy/loader.go` parses the policy YAML. New top-level keys: `providers`, `services`, and per-process-context `secrets:` lists.
2. **Provider instantiation.** For each provider in `providers:`, construct the `SecretProvider` via its `New()` constructor. Resolve any chained secret references. Fail session creation if a required provider fails to initialize.
3. **Service resolution.** For each service referenced by the policy, resolve to either a YAML declaration or a registered plugin. Fail on unresolved references.
4. **Secret fetch.** For each service, call `provider.Fetch(ctx, ref)`. All fetches happen here — no lazy materialization in v1. Fetch timeout is configurable per provider, default 10 s. On `ErrNotFound`, honor the service's `on_missing:` flag (`fail` aborts session creation, `skip` omits the service entirely, `fake_only` creates a fake that maps to nothing and will 401 on use).
5. **Fake generation.** For each fetched secret, generate a length-matched fake and add it to the session's `credsub.Table`.
6. **Env var injection.** For each service with `inject.env:`, add the fake value to the per-session env var map. This merges with the existing `env_inject` path in `internal/policy/env_policy.go` at `BuildEnv` call time. Collisions between `env_inject` and service env vars are a policy load error (we do not want silent overrides).
7. **Proxy registration.** Register each service with the session's proxy (`internal/proxy.Proxy`). This tells the proxy which hosts to handle and which fakes correspond to which real credentials. LLM hooks register themselves at this point too.
8. **Env vars for proxy routing.** `s.ProxyEnvVars()` continues to return `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and now also `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` (with the daemon UDS / localhost carved out) pointing at the same local proxy so that non-LLM cooperating SDKs route through it.
9. **Spawn.** `internal/api/exec.go` picks up the merged env (from `BuildEnv`) and starts the process.

**Failure semantics.** Any step 1–7 failure aborts session creation with a structured error. The agent never starts. The operator sees which service / which provider failed. Partial success is not allowed — we do not want to start an agent with a half-populated credential table.

**Audit events.** Session start emits `secrets_initialized` with the list of service names (no credentials, no fakes — just the names for observability).

## Section 6 — Egress flow

When the spawned agent makes an outbound HTTP request:

1. **Interception.** The request hits the local proxy because either (a) the SDK honors `*_BASE_URL` / `HTTPS_PROXY`, or (b) the netmonitor's `connect_redirect` hairpin lands the connection at the proxy. v1 relies on (a); (b) is a best-effort safety net.
2. **Service match.** The proxy looks up the Host header against the registered services. No match → request passes through unmodified (subject to `network_rules`). Match → proceed.
3. **Pre-hooks.** Registered pre-hooks for the matched service run. For LLM services this is where DLP tokenization and MCP intercept fire.
4. **Fake → real substitution.** The proxy scans the request body, each header value, the URL query string, and the URL path with the session's `credsub.Table.ReplaceFakeToReal`. For services with `inject.header`, the proxy then sets the configured header from scratch using the real credential — this is unconditional on matched services, so even an SDK that did not read the fake env var still ends up with a correctly-authenticated upstream request. Any header the agent attached is stripped before the injection.
5. **Service-specific injection.** For plugin services (AWS SigV4, GCP OAuth), the plugin's `Inject` method runs. This constructs the auth from the real credential; any existing header the agent attached is stripped.
6. **Upstream forward.** Rebuilt request goes to the real upstream via the existing reverse-proxy plumbing in `internal/proxy/proxy.go`.
7. **Post-hooks.** Response comes back, post-hooks run. For streaming responses (SSE), the hook is invoked per-chunk.
8. **Real → fake scrub.** If the service has `scrub_response: true`, the response body is scanned with `credsub.Table.ReplaceRealToFake` before returning to the agent. SSE streams get chunked scans.
9. **Return.** Response reaches the agent. From its perspective the request went directly to the service with the fake credential.

**Strict deny on unknown destinations.** If the agent makes a request to a host that is NOT a registered service, and the request body contains a known fake from the session's table, the proxy blocks the request, returns a synthetic 403 with a structured error body, and fires a `secret_fake_leak_attempt` audit event. This is the "strict" failure mode we chose in the design discussion.

**Cross-service use.** If service A's fake appears in a request to service B (also registered), the proxy blocks and fires `secret_cross_service_use`. This catches prompt-injection attacks that try to smuggle a GitHub token inside an OpenAI request body.

## Section 7 — Configuration schema

New top-level keys in the policy YAML:

```yaml
providers:
  keyring:
    type: keyring
  vault:
    type: vault
    address: https://vault.corp.internal
    namespace: engineering
    auth:
      method: approle
      role_id_ref: keyring://agentsh/vault_role_id
      secret_id_ref: keyring://agentsh/vault_secret_id
  aws_sm:
    type: aws-sm
    region: us-east-1
    auth:
      mode: ambient    # or "assume_role" with role_arn

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
      env:
        - name: GITHUB_TOKEN
    scrub_response: true

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
      env:
        - name: ANTHROPIC_API_KEY
    hooks:
      - dlp
      - mcp_intercept

  - name: aws
    match:
      hosts: ["*.amazonaws.com"]
    secret:
      ref: aws-sm://prod/iam/agentsh-role#credentials
    plugin: aws_sigv4   # escape hatch

process_contexts:
  - name: coder
    secrets:
      - github
      - anthropic
      - aws
```

**Provider naming.** Each provider gets a name used in `services[].secret.ref`. In v1 you cannot have two providers of the same `type` (e.g., two Vault clusters). This simplifies the URI resolver — `vault://` always maps to the single `vault` provider.

**`inject.env` semantics.** Each entry in `inject.env` adds one env var to the spawned process. The var's *value* is the service's fake credential — never the real one. The real credential is used only by the proxy at egress to reconstruct the outbound request. This is how the existing agent SDK flow extends beyond LLM keys: `GITHUB_TOKEN=ghp_<fake>`, `ANTHROPIC_API_KEY=sk-ant-<fake>`, and so on.

**Service referencing from process contexts.** The existing `process_contexts` concept grows a `secrets:` list naming which services this context can reach. Omitted = no services. This plugs into the existing `env_policy` layer.

**Loader validation.**

- Every `services[].secret.ref` must resolve to a provider.
- Every `inject.env[].name` must be allowed by the context's `env_policy.allow` — or the loader adds it automatically if `env_policy.auto_allow_service_env: true`.
- Every `process_contexts[].secrets[]` name must refer to a declared service.
- Every provider's chained secret references must not form cycles.
- Overlapping host patterns across services are allowed (first-match-wins) but produce a warning with line numbers so operators see the precedence.

## Section 8 — Failure modes and policy interactions

### A. Backend availability failures

| Condition | v1 behavior |
|---|---|
| Provider fails to initialize at session creation | Session creation fails with `provider_init_failed`. Agent does not start. |
| Provider times out on Fetch at session creation | Session creation fails with `secret_fetch_timeout`. Configurable per-provider, default 10 s. |
| Secret not found in backend | Honor `on_missing`: `fail` aborts, `skip` omits service, `fake_only` creates dangling fake. |
| Mid-session provider outage | v1 does not refresh mid-session. No effect until session ends. |
| Vault dynamic-secret lease expires mid-session | Upstream rejects the next request as `401` or `403`. Proxy fires `secret_upstream_auth_failure` audit event (cannot reliably distinguish lease expiry from other auth failures in v1). Agent gets the raw upstream status. No retry. |

### B. Credential leak attempts

| Attack | v1 response |
|---|---|
| Agent sends known fake to unregistered host | Proxy blocks with 403. `secret_fake_leak_attempt` audit event. This is the "strict deny" we picked. |
| Agent sends service-A fake inside a request to service B | Proxy blocks with 403. `secret_cross_service_use` audit event. |
| Agent tries to reach the secret backend directly (e.g., Vault endpoint) to fetch secrets itself | Default policy denies all provider endpoints. Loader validates that no service matches a provider host. `agentsh policy lint` explicitly flags this. |
| Agent logs real credential to stdout because it got substituted by the proxy | Does not happen — real credentials never leave the proxy. Agent only ever holds fakes. |
| Agent base64-encodes the fake and sends it out | Not caught in v1. Documented limitation. |
| Agent splits the fake across two requests | Each request individually does not contain the full fake. Not caught in v1. |
| Prompt injection tries to exfiltrate a fake by URL-encoding it | Aho-Corasick scan is bytewise — literal bytes match. URL-encoded form is a different byte sequence, so this is NOT caught. Documented limitation. |
| Agent binds to the local proxy port and impersonates it | The proxy listens on a per-session UDS path owned by the daemon. Agent cannot bind to the same path unless the sandbox policy is broken. |

### C. Configuration conflicts

| Condition | v1 behavior |
|---|---|
| `env_inject` and a service's `inject.env` set the same var name | Policy load fails with `env_inject_service_collision`. |
| Parent shell has `GITHUB_TOKEN` already set | The session's env builder overrides it with the fake. (This is the existing `env_inject` behavior, unchanged.) |
| Process context references an undeclared service | Policy load fails. |
| `network_rules` allows a host but no service matches it | Request flows unmodified (no substitution). This is intentional — not all network-allowed hosts need fake-credential substitution. |
| Two services match the same host | First declaration wins. Loader warns with file:line. |
| `fake.format` template omits entropy or has fewer than 24 random chars | Loader rejects. Minimum 24 random chars enforced (matches the collision-probability math in Section 4). |
| Two providers of the same `type` | v1 rejects at load time. v2 may add named instances. |

### D. Edge cases

| Condition | v1 behavior |
|---|---|
| Fake collides with a randomly-generated body field in the agent | Statistically impossible at 24+ random chars. If it happens, the unrelated request body gets a random mutation. Not defended against. |
| Binary response body contains the real credential by coincidence | Bytewise scan still rewrites. Response body may end up corrupted. Documented; rare in practice. |
| 301/302 redirect from a matched service to an unmatched host | Proxy does not follow redirects. Agent follows, and the follow-up request goes through the proxy again, subject to the same match rules. |
| WebSocket upgrade on a matched service | Upgrade is forwarded; post-upgrade frames are not scanned. WebSocket credentials are handled at the initial Upgrade request (which IS scanned). |
| Fake appears inside a JSON-encoded string that travels to a different service | Caught by `secret_cross_service_use` if the target is a registered service. Not caught if the target is unregistered (but strict-deny catches that path). |

### E. Subsystem interaction

- **`env_policy.BuildEnv`** runs after the proxy's service-env-var contribution. Collisions fail at load time, so BuildEnv never sees conflicts.
- **MCP interception** moves to `internal/proxy/llm/mcp*.go`. It registers as a hook under `hooks: [mcp_intercept]` in LLM service YAML. No behavior change.
- **DLP** similarly moves to `internal/proxy/llm/dlp.go` and registers as a `PreHook`. Per Section 1, pre-hooks run *before* substitution, so DLP sees request bodies that still contain the fake credentials. This is correct because DLP scrubs PII, not credentials — it has no reason to see real secrets. Substitution runs after DLP and produces the final upstream request body. No order-of-operations bug.
- **`netmonitor`'s `connect_redirect`** hairpins TCP connections to the local proxy for services the agent reaches via raw Host headers. Safety net for misbehaving SDKs.
- **Checkpoints** do not snapshot the `credsub.Table`. v1 refuses to restore a checkpoint for a session that had any `providers:` or `services:` entries in its policy — restore returns `checkpoint_has_external_secrets` and the operator must start a fresh session. This is the safest v1 default because the original fakes and real credentials are gone, and re-fetching may produce different fakes, invalidating any state the agent has written that embedded fakes.
- **`llm_logs` rename → `proxy_logs`**. Log ingest accepts both names. Report generator reads the new name and falls back to the old.
- **Session report generator** gains a `secrets` section: list of service names initialized at session start, count of fake→real substitutions performed, count of leak attempts blocked. No credentials in the report.
- **`agentsh policy generate`** gains a `--with-services` flag that adds a scaffolded `providers` + `services` block for common services detected from the workspace (e.g., sees `.github/`, scaffolds a GitHub entry).

### F. Security guarantees

**v1 guarantees:**

1. Real credentials never enter the spawned agent's address space.
2. Fake credentials cannot reach hosts the policy does not allow — either via the strict-deny egress gate or the cross-service use check.

**v1 does NOT guarantee:**

1. Protection against agents that bypass the proxy via raw TCP (depends on `network_rules` tightness — Mechanism B would close this).
2. Protection against encoded / split / binary-mangled fake exfiltration. Only bytewise literal matches are caught.

## Section 9 — Future phase sketches

### Mechanism B — Linux TLS uprobes

eBPF uprobes on `SSL_write`, `SSL_write_ex`, `gnutls_record_send`, and Go's `crypto/tls.(*Conn).Write` catch plaintext before encryption. BPF scan against a PID-filtered credsub.Table, `bpf_probe_write_user` for in-place rewrite. Length-preserving substitution is already enforced by v1, which means the rewrite needs no offset fixup.

Covers: 80-90% of dynamically-linked Linux tools (curl, wget, python-requests, node, ruby, php). Statically-linked Go binaries covered via Go uprobe with DWARF-assisted symbol resolution.

Constraints: Linux only. `CAP_BPF + CAP_PERFMON`. Library version drift is a real problem — needs a compatibility matrix maintained per release.

Slots in as `internal/proxy/tlsuprobe/` (linux build tag). Graceful fallback when capability missing.

Earns its own design spec when v2 starts.

### Mechanism C — Per-tool credential helpers

Cross-platform, no kernel work. Per-session config files + a small helper binary:

- `git credential.helper = !agentsh-credhelper git` via per-session `GIT_CONFIG_GLOBAL`
- `aws credential_process = agentsh-credhelper aws` via per-session `AWS_CONFIG_FILE`
- `gh` auth token streamed via FD or env
- `kubectl exec` auth plugin in per-session `KUBECONFIG`
- `docker-credential-agentsh` binary registered via per-session `docker/config.json`
- `npm`/`pip` via per-session config files with fakes that flow through the proxy

New binary `cmd/agentsh-credhelper` talks to the daemon over the existing UDS. Each tool gets a tiny case in the helper. Services in YAML grow an optional `tool_helpers:` section.

This mechanism is additive and incremental: v2+ ships helpers as needed. No single monolithic release required.

## Section 10 — Out of scope for v1

### Features

- Per-command credential rotation.
- Lazy materialization of secrets — all fetched at session start.
- Lease renewal / auto-refresh mid-session.
- Named provider instances (two Vault clusters in one policy).
- Encrypted-at-rest credsub.Table. Memory-only, zeroed on close. No mlock.
- Fake format beyond simple random-char templates (no JWT, no RSA, no X.509 fakes).
- Outbound substitution for non-HTTP protocols (SMTP, raw TCP, h2c gRPC). HTTPS gRPC works because it is HTTP/2 inside TLS.
- Inbound response scrubbing for encoded variants (base64-wrapped, URL-encoded, etc.). Only literal byte matches.
- Session-log scrubbing for pre-substitution debug logs inside agentsh itself. Obvious paths closed; comprehensive audit deferred.
- `agentsh secrets ls` / `agentsh secrets status` CLI commands. Observability via audit events only.

### Threat model exclusions

- Malicious operators writing policy that points at an attacker-controlled backend.
- Local root attackers reading the daemon's memory.
- Agents running as root inside the sandbox (assumed non-root).
- Side-channel leaks (timing, size, cache).
- Backend compromise — if Vault is compromised and returns a malicious secret, agentsh cannot tell.

### Naming / migration

- Package rename `internal/llmproxy` → `internal/proxy` is IN v1.
- Audit event rename `llm_logs` → `proxy_logs` is IN v1 with a compatibility shim.
- Config keys are already generic (`proxy_url`) — no rename needed.
- Policy YAML changes are purely additive (new `providers:` and `services:` keys). Existing policies keep working unchanged.

---

## File layout after v1

```
internal/
  proxy/
    proxy.go              # generic HTTP substituting proxy (renamed from llmproxy)
    config.go             # generic config
    hooks.go              # Hook interface + registry
    credsub/
      table.go            # per-session fake/real table
      ahocorasick.go      # bytewise scanner
    secrets/
      provider.go         # SecretProvider interface
      uri.go              # URI parser
      vault/
      awssm/
      gcpsm/
      azurekv/
      onepassword/
      keyring/
    services/
      service.go          # Service interface
      registry.go         # init-time plugin registration
      yaml.go             # declarative engine
      aws/                # SigV4 plugin
      gcp/                # OAuth refresh plugin
    llm/
      dlp.go              # moved from internal/llmproxy/dlp.go
      dialect.go          # moved from internal/llmproxy/dialect.go
      mcp.go              # moved from internal/llmproxy/mcp.go
      register.go         # RegisterHooks(*proxy.Proxy)

cmd/
  agentsh-credhelper/     # (Mechanism C; stub binary in v1, wired up in v2+)
```

## Open questions for the implementation plan

1. What does `agentsh policy lint` actually check for the "agent reaches provider directly" footgun? A concrete rule set should be defined in the implementation plan.
2. SSE streaming substitution chunking — how do we handle a fake that straddles two chunks? Buffer window of N bytes at chunk boundaries where N = longest fake length. Needs validation against real Anthropic/OpenAI SSE framing.
3. Per-provider timeout tuning — 10 s default is a guess. Revisit after first real deployments.
4. Implementation phasing — this spec's v1 scope is large (6 providers + 2 plugins + substitution engine + rename). The writing-plans skill should decompose into incremental merges: core substitution infra first, then providers one at a time starting with keyring (simplest) and ending with plugins.
