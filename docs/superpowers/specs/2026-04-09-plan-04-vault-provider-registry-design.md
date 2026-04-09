# Plan 4: Vault Provider + Provider Registry — Design

**Date:** 2026-04-09
**Status:** Design (pre-implementation)
**Owner:** Eran Sandler

## Problem

Plan 3 shipped the `SecretProvider` interface, URI parser, and keyring provider. The keyring provider is self-contained — it needs no credentials from another provider to bootstrap. The Vault provider is the first provider that needs auth credentials which may themselves come from another provider (e.g., the Vault token lives in the OS keyring). This creates a construction-ordering problem that requires a provider registry with dependency resolution.

Plan 4 ships two things together:

1. **Provider registry** — resolves auth-chaining dependencies via topological sort, constructs providers in the right order, and exposes them by name.
2. **Vault provider** — fetches secrets from HashiCorp Vault (and OpenBao) KV v2 engine, using the official `hashicorp/vault/api` client library.

## Goals

- A `Registry` type in `internal/proxy/secrets/` that constructs providers in dependency order with cycle detection.
- A Vault provider supporting token, AppRole, and Kubernetes auth methods.
- Auth chaining: Vault's bootstrap credentials can reference another provider (e.g., `keyring://agentsh/vault_token`).
- KV v2 secret reads with field extraction via URI fragment (`vault://kv/github#token`).
- Zero call sites inside the daemon — wiring happens in Plan 10.

## Non-goals

- KV v1 support (v2 only in this plan).
- Generic secret engine reads (only KV v2).
- Vault dynamic secrets or lease renewal.
- Session wiring, credsub.Table integration, or policy YAML parsing.
- Deletion of dormant `pkg/secrets/` (happens after Plans 4-5 both land).
- Integration tests against a real Vault server.

## Parent spec reference

`docs/superpowers/specs/2026-04-07-external-secrets-design.md`, Sections 2, 5, 7.

---

## Section 1 — Provider Registry

### Location

`internal/proxy/secrets/registry.go` (and `registry_test.go`).

### Core types

```go
// RefResolver lets a provider constructor fetch a secret from an
// already-constructed provider during auth chaining.
type RefResolver func(ctx context.Context, ref SecretRef) (SecretValue, error)

// ConstructorFunc builds a SecretProvider from its config. The
// resolver can fetch secrets from providers that have already been
// constructed (for auth chaining like vault's token_ref pointing
// at keyring://...).
type ConstructorFunc func(cfg ProviderConfig, resolver RefResolver) (SecretProvider, error)

// Registry holds constructed providers keyed by their config name.
type Registry struct {
    providers map[string]SecretProvider
}
```

### Dependencies() on ProviderConfig

The `ProviderConfig` interface gains a new method:

```go
type ProviderConfig interface {
    providerConfig()
    Dependencies() []SecretRef
}
```

`ProviderConfigMarker` gets a default implementation returning `nil`, so existing configs (`keyring.Config`) don't break without code changes.

Each provider config implements `Dependencies()` by returning the `*_ref` fields it needs resolved before construction. For example, `vault.Config` with `TokenRef: keyring://agentsh/vault_token` returns `[]SecretRef{{Scheme: "keyring", Host: "agentsh", Path: "vault_token"}}`.

### Construction flow

`NewRegistry(ctx context.Context, configs map[string]ProviderConfig, constructors map[string]ConstructorFunc) (*Registry, error)`:

1. **Validate** all configs have a matching constructor (keyed by provider type extracted from the config — each config knows its own type name).
2. **Build dependency graph.** For each config, call `Dependencies()`. Each returned `SecretRef`'s scheme maps to the provider config that handles that scheme. Node = config name, edge = "this config depends on the provider handling scheme X."
3. **Topological sort** (Kahn's algorithm). If cycle detected → return `ErrCyclicDependency` listing the cycle path.
4. **Construct in order.** For each config in topological order:
   - Build a `RefResolver` that dispatches to already-constructed providers by matching the ref's scheme to the provider that registered for it.
   - Call the `ConstructorFunc` with the config and resolver.
   - Store the resulting provider.
5. **Cleanup on failure.** If any constructor fails, `Close()` every already-constructed provider, then return the error.

### Registry API

```go
func NewRegistry(ctx context.Context, configs map[string]ProviderConfig, constructors map[string]ConstructorFunc) (*Registry, error)

// Provider returns a named provider. Used by the future session-start
// flow to fetch secrets for each service.
func (r *Registry) Provider(name string) (SecretProvider, bool)

// Fetch resolves a SecretRef by finding the provider that handles its
// scheme and delegating to that provider's Fetch.
func (r *Registry) Fetch(ctx context.Context, ref SecretRef) (SecretValue, error)

// Close calls Close() on every provider. Safe to call multiple times.
func (r *Registry) Close() error
```

### Scheme-to-provider mapping

The registry needs to know which provider handles which URI scheme. Each `ProviderConfig` has a `TypeName() string` method that returns the provider type name, which doubles as the URI scheme it handles. For example, `vault.Config.TypeName()` returns `"vault"`, and the registry maps `vault://` URIs to that provider.

The full revised `ProviderConfig` interface:

```go
type ProviderConfig interface {
    providerConfig()
    TypeName() string          // "keyring", "vault", etc.
    Dependencies() []SecretRef
}
```

`ProviderConfigMarker` provides a default `Dependencies()` returning `nil` (for providers with no auth chaining). It does NOT provide a default `TypeName()` — each config must implement it explicitly. This is a compile-time enforcement that every provider config declares its type.

### Error sentinel

New in `errors.go`:

```go
var ErrCyclicDependency = errors.New("secrets: cyclic provider dependency")
```

---

## Section 2 — Vault Provider

### Location

`internal/proxy/secrets/vault/` — `doc.go`, `config.go`, `provider.go`, `provider_test.go`.

### Config

```go
// Config configures the Vault provider.
type Config struct {
    secrets.ProviderConfigMarker

    // Address is the Vault server address (e.g. "https://vault.corp.internal").
    // Required.
    Address string

    // Namespace is the Vault enterprise namespace. Empty for open-source
    // Vault and OpenBao.
    Namespace string

    // Auth configures how the provider authenticates to Vault.
    Auth AuthConfig
}

// TypeName returns "vault".
func (Config) TypeName() string { return "vault" }

// Dependencies returns all *Ref fields that need resolution before
// construction.
func (c Config) Dependencies() []SecretRef {
    var deps []SecretRef
    if c.Auth.TokenRef != nil {
        deps = append(deps, *c.Auth.TokenRef)
    }
    if c.Auth.RoleIDRef != nil {
        deps = append(deps, *c.Auth.RoleIDRef)
    }
    if c.Auth.SecretIDRef != nil {
        deps = append(deps, *c.Auth.SecretIDRef)
    }
    return deps
}

type AuthConfig struct {
    // Method is the auth method: "token", "approle", or "kubernetes".
    Method string

    // Token auth. Exactly one of Token (literal) or TokenRef (chained)
    // must be set when Method == "token".
    Token    string
    TokenRef *secrets.SecretRef

    // AppRole auth. Each of RoleID/RoleIDRef and SecretID/SecretIDRef
    // is a literal-or-ref pair. At least one form must be set per field
    // when Method == "approle".
    RoleID      string
    RoleIDRef   *secrets.SecretRef
    SecretID    string
    SecretIDRef *secrets.SecretRef

    // Kubernetes auth.
    KubeRole      string // required when Method == "kubernetes"
    KubeMountPath string // default "kubernetes"
    KubeTokenPath string // default "/var/run/secrets/kubernetes.io/serviceaccount/token"
}
```

### URI format

**Deviation from parent spec:** The parent spec uses `vault://kv/data/github#token`. However, `vault/api`'s KV v2 helper (`client.KVv2(mount).Get(ctx, path)`) adds the `data/` prefix internally. To avoid double-prefixing, the Vault provider's URI format omits `data/`:

| URI | Mount (Host) | Path | Field |
|-----|--------------|------|-------|
| `vault://kv/github#token` | `kv` | `github` | `token` |
| `vault://secret/prod/api-key` | `secret` | `prod/api-key` | (auto if single-field) |
| `vault://kv/db#password` | `kv` | `db` | `password` |

If the user supplies a path starting with `data/`, the provider strips it with a warning log (common mistake when copying from the raw Vault HTTP API).

### Provider construction

`New(cfg Config, resolver secrets.RefResolver) (*Provider, error)`:

**Note on ConstructorFunc:** The generic `ConstructorFunc` receives a `ProviderConfig` interface. The Vault constructor function registered with the registry type-asserts to `vault.Config`:

```go
func vaultConstructor(cfg secrets.ProviderConfig, resolver secrets.RefResolver) (secrets.SecretProvider, error) {
    vc, ok := cfg.(vault.Config)
    if !ok {
        return nil, fmt.Errorf("expected vault.Config, got %T", cfg)
    }
    return vault.New(vc, resolver)
}
```

1. **Validate config:**
   - `Address` required.
   - `Auth.Method` must be `"token"`, `"approle"`, or `"kubernetes"`.
   - For token auth: exactly one of `Token` or `TokenRef` (not both, not neither).
   - For approle auth: RoleID or RoleIDRef (not both), SecretID or SecretIDRef (not both).
   - For kubernetes: `KubeRole` required.
2. **Resolve chained refs** via `resolver`:
   - If `TokenRef` is set, call `resolver(ctx, *TokenRef)` and use the value. Zero the SecretValue after extracting the string.
   - Same for `RoleIDRef`, `SecretIDRef`.
3. **Create `vault/api.Client`:**
   - Set address, namespace, TLS from system defaults.
   - Configure a reasonable timeout (30s default, matching the existing dormant code).
4. **Authenticate:**
   - **Token:** `client.SetToken(token)`.
   - **AppRole:** `client.Auth().Login(ctx, approle.NewAppRoleAuth(roleID, &approle.SecretID{FromString: secretID}))`. Requires new dep: `github.com/hashicorp/vault/api/auth/approle`.
   - **Kubernetes:** `client.Auth().Login(ctx, kubernetes.NewKubernetesAuth(role, kubernetes.WithServiceAccountTokenPath(path), kubernetes.WithMountPath(mount)))`. Already in `go.mod`.
5. **Verify connectivity:** `client.Auth().Token().LookupSelf()`. If this fails → `ErrUnauthorized`.
6. **Zero all resolved secret values.**

### Fetch

`Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error)`:

1. Check closed flag (same pattern as keyring: `atomic.Bool` + `sync.RWMutex`).
2. Validate: `ref.Scheme == "vault"`, `ref.Host` non-empty (KV v2 mount name), `ref.Path` non-empty (secret path).
3. Read secret: `client.KVv2(ref.Host).Get(ctx, ref.Path)`.
4. **Field extraction:**
   - If `ref.Field` is set: look up that key in the KV data map. Missing field → `ErrNotFound`.
   - If `ref.Field` is empty and data has exactly one field: return that field's value.
   - If `ref.Field` is empty and data has zero or multiple fields: `ErrInvalidURI` with message listing available fields.
5. Convert the value to `[]byte`. The Vault KV v2 helper returns `map[string]interface{}`; we `fmt.Sprintf("%s", val)` for string values, or `json.Marshal` for non-string values.
6. Build and return `SecretValue`:
   - `Value`: the extracted bytes.
   - `TTL`: from the Vault secret's `LeaseDuration` if available.
   - `LeaseID`: from the Vault secret's `LeaseID`.
   - `Version`: from the KV v2 metadata version.
   - `FetchedAt`: `time.Now()`.

### Error mapping

| Vault condition | Mapped error |
|---|---|
| 404 / secret not found | `ErrNotFound` |
| 403 / permission denied | `ErrUnauthorized` |
| Wrong scheme in ref | `ErrInvalidURI` |
| Missing host or path in ref | `ErrInvalidURI` |
| Field not found in KV data | `ErrNotFound` |
| Ambiguous (no field, multiple keys) | `ErrInvalidURI` |
| Network / timeout | Wrapped transport error |

### Close

1. If the provider authenticated via AppRole or Kubernetes (i.e., it created the token), call `client.Auth().Token().RevokeSelf()` best-effort. Token-auth tokens are not revoked (not ours).
2. Set closed flag.
3. Acquire write lock (wait for in-flight Fetches).
4. Nil the client.

### Concurrency

Same pattern as keyring: `atomic.Bool` for closed flag, `sync.RWMutex` for Fetch/Close synchronization. Same test seam hooks for race testing.

### OpenBao compatibility

OpenBao is a Vault API fork. The `vault/api` client works with OpenBao by pointing `Address` at the OpenBao server. No code changes needed. Documented in the package doc.

---

## Section 3 — Testing Strategy

### Vault provider tests (`vault/provider_test.go`)

Uses `net/http/httptest.Server` with mock Vault HTTP handlers. No new test dependencies — mock the Vault API responses directly. The `vault/api.Client` is configured to talk to the httptest server.

**Mock handler coverage:**
- `/v1/auth/token/lookup-self` — returns token metadata (for connectivity check).
- `/v1/auth/approle/login` — accepts role_id + secret_id, returns client_token.
- `/v1/auth/kubernetes/login` — accepts role + jwt, returns client_token.
- `/v1/{mount}/data/{path}` — KV v2 read, returns data + metadata.
- `/v1/auth/token/revoke-self` — accepts POST, returns 204.

**Test cases:**
- Happy path: token auth, KV v2 read with field, verify value + version.
- Field extraction: multi-field with `#field`, missing field, single-field auto-resolve, zero-field error.
- AppRole auth: mock login, verify token is used for subsequent reads.
- Kubernetes auth: mock login with JWT from temp file.
- Auth chaining: `secretstest.MemoryProvider` as RefResolver source, verify Vault gets chained token.
- Error mapping: 404 → `ErrNotFound`, 403 → `ErrUnauthorized`, wrong scheme → `ErrInvalidURI`.
- Close: Fetch after Close fails. Close is idempotent. AppRole tokens revoked on Close.
- Context cancellation: canceled ctx → immediate error.
- Config validation: missing address, conflicting literal+ref, bad auth method.

### Contract tests

`secretstest.ProviderContract(t, "vault", provider, probeRef)` with `probeRef` pointing at a non-existent KV path.

### Registry tests (`secrets/registry_test.go`)

Uses `secretstest.MemoryProvider` for all tests (no Vault needed):
- **Linear chain:** "keyring" → "vault" (memory provider simulating both). Construct in order. Verify resolver works.
- **Cycle detection:** A depends on B depends on A → `ErrCyclicDependency`.
- **Self-cycle:** A depends on itself → `ErrCyclicDependency`.
- **Missing constructor:** Config references a type with no constructor → error.
- **Constructor failure:** Second provider's constructor fails → first gets `Close()`d.
- **No dependencies:** All providers independent → all construct (order irrelevant).
- **Registry.Fetch dispatches correctly.**
- **Registry.Close closes all providers.**

---

## Section 4 — File Layout

### New files

```
internal/proxy/secrets/
    registry.go              # Registry, NewRegistry, topo sort, RefResolver, ConstructorFunc
    registry_test.go         # dependency resolution + lifecycle tests

internal/proxy/secrets/vault/
    doc.go                   # package doc (OpenBao note)
    config.go                # Config, AuthConfig, TypeName, Dependencies, compile-time assertions
    provider.go              # Provider, New, Fetch, Close
    provider_test.go         # httptest mock + contract tests
```

### Modified files

- `internal/proxy/secrets/provider.go` — add `TypeName() string` and `Dependencies() []SecretRef` to `ProviderConfig` interface. Add default `Dependencies()` to `ProviderConfigMarker`.
- `internal/proxy/secrets/errors.go` — add `ErrCyclicDependency` sentinel.
- `internal/proxy/secrets/keyring/config.go` — add `TypeName() string` returning `"keyring"`. (`Dependencies()` is inherited from the `ProviderConfigMarker` default.)
- `go.mod` — add `github.com/hashicorp/vault/api/auth/approle`.
- `go.sum` — regenerated.

### NOT modified

- `internal/session/`, `internal/api/`, `cmd/` — no session wiring.
- `internal/proxy/credsub/` — no credsub.Table connection.
- `pkg/secrets/` — dormant code untouched.

### Scope boundary

This plan produces a working Registry + Vault provider with zero call sites inside the daemon. Plan 10 wires the registry into session start.

---

## Section 5 — Dependency Hygiene

### New direct dependency

`github.com/hashicorp/vault/api/auth/approle` — needed for AppRole auth. This is a small module in the vault/api family, likely sharing most transitive deps with the already-present `vault/api` and `vault/api/auth/kubernetes`.

### Inspection required

The implementer must inspect the `go.sum` delta after `go mod tidy` and report any surprising transitive dependencies not already in the module graph.

### OpenBao

No `openbao` dependency needed. The `vault/api` client is wire-compatible with OpenBao's API.

---

## Open questions for the implementation plan

1. **TypeName() vs constructor-map key:** The design adds `TypeName()` to `ProviderConfig` and also has constructors keyed by type name in the constructor map. These must match. The implementation plan should validate this at `NewRegistry` time.
2. **Vault API version detection:** `client.KVv2()` assumes the mount is KV v2. If the mount is v1, the call fails. Should we attempt v2 first and fall back to v1, or just fail with a clear error? Decision: fail with a clear error — Plan 4 is KV v2 only.
3. **Token self-revocation on Close:** If the process crashes, the token is not revoked. This is acceptable for v1 — the spec explicitly defers lease management.
