# Plan 3 — SecretProvider interface + keyring provider

**Date:** 2026-04-08
**Status:** Design (pre-implementation)
**Owner:** Eran Sandler
**Parent spec:** [`2026-04-07-external-secrets-design.md`](./2026-04-07-external-secrets-design.md)
**Predecessor plan:** Plan 2 — `credsub.Table` core substitution engine (merged in #200)

## Goal

Land the abstraction agentsh's session-start path will use to fetch real credentials from external stores, plus the first concrete provider (OS keyring). After this plan merges, future plans (Plan 4: Vault, Plan 5: AWS Secrets Manager, etc.) can drop in a new file under `internal/proxy/secrets/<provider>/` and require zero changes to the interface or URI parser.

## Scope

### In scope

- `SecretProvider` interface, `SecretRef`, `SecretValue`, `ProviderConfig` types
- Sentinel error taxonomy
- URI parser that recognizes all six v1 schemes (`vault://`, `aws-sm://`, `gcp-sm://`, `azure-kv://`, `op://`, `keyring://`)
- Keyring provider implementation using `github.com/zalando/go-keyring`
- In-memory `MemoryProvider` in a `secretstest` subpackage for downstream test use
- Comprehensive unit tests; race-clean; cross-compile clean on Linux, macOS, and Windows
- Shared `ProviderContract` test helper (in `secretstest/`) applied to both real and fake providers

### Deferred to later plans

- **Provider registry / config loader** — the YAML `providers:` section parser. Lands when the second provider (Plan 4) needs it, or as its own glue plan.
- **Auth-chaining resolver** — the loader-time pass that resolves `keyring://agentsh/vault_token` and feeds the result into a Vault provider's constructor. Plan 4's job.
- **Wiring into `internal/session/`** — Plan 10.
- **Connection to `credsub.Table`** — Plan 10.
- **`pkg/secrets` cleanup** — `pkg/secrets/` is dormant (zero callers in the daemon). Plan 3 leaves it alone. A separate cleanup PR after Plans 4–5 land Vault and AWS in the new location will delete it.

## Decisions made during brainstorming

The brainstorming session settled the following questions. These are inputs to the implementation, not open questions:

1. **Scope:** Foundation + keyring. Interface + URI parser (full grammar) + keyring impl + MemoryProvider. No registry, no YAML loader, no chaining.
2. **Keyring library:** `github.com/zalando/go-keyring` (Apache 2.0).
3. **Headless Linux behavior:** Fail loud at provider construction with `ErrKeyringUnavailable`. Operator's choice: don't use keyring on this host, or set up a running keyring daemon. No "optional" flag.
4. **`pkg/secrets` disposition:** Leave alone. Not touched by this plan.
5. **Keyring URI grammar:** `keyring://<service>/<user>`. Host = OS keyring service name. Path = OS keyring account/user. Fragment (`#field`) is rejected — keyring entries are scalar.
6. **Test fake provider:** Ship `MemoryProvider` in `internal/proxy/secrets/secretstest/` in this plan.

## Package layout

```
internal/proxy/secrets/
  doc.go             # package docs
  errors.go          # sentinel errors
  provider.go        # SecretProvider interface, SecretRef, SecretValue, ProviderConfig
  uri.go             # ParseRef + SecretRef.String
  uri_test.go
  provider_test.go   # SecretValue.Zero, sentinel-error wrapping, sanity tests

  keyring/
    doc.go
    config.go        # KeyringConfig{} (empty struct + sealed marker)
    provider.go      # New(Config); Fetch; Close; Name
    provider_test.go # round-trip + URI validation; skips OS-touching tests when no keyring

  secretstest/
    doc.go
    memory.go        # MemoryProvider; implements secrets.SecretProvider
    memory_test.go
    contract.go      # ProviderContract(t, name, p) — shared behavioral test
    contract_test.go
```

**Why this layout:**
- The interface lives at `internal/proxy/secrets/` (the parent), not in a `secretsapi` subpackage, because every provider subpackage imports it. Putting it at the parent prevents an import cycle.
- Each provider gets its own subpackage so a heavy dependency (e.g., AWS SDK in Plan 5) doesn't pull into the interface package.
- `secretstest/` is a sibling subpackage. Naming follows stdlib `httptest`/`iotest` convention. Production code MUST NOT import it (documented in the package doc; we'll add a CI lint later if it ever gets imported by accident).

**Files outside the new package:** only `go.mod` / `go.sum` (zalando dep). Nothing in `internal/session/`, `internal/api/`, `cmd/`, or `pkg/` is touched.

## Section 1 — Core types and interface

```go
// internal/proxy/secrets/provider.go
package secrets

import (
    "context"
    "time"
)

// SecretProvider is implemented by every secret backend.
//
// Implementations must be safe for concurrent use by multiple
// goroutines. The daemon constructs one provider per backend at
// session start, calls Fetch zero or more times, and calls Close
// exactly once at session end.
type SecretProvider interface {
    // Name returns the provider's stable identifier (e.g. "keyring").
    // Used in audit events and error messages.
    Name() string

    // Fetch retrieves a single secret identified by ref.
    //
    // Returns ErrNotFound if the secret does not exist,
    // ErrUnauthorized if the backend rejected our credentials,
    // and a wrapped transport error otherwise.
    //
    // The returned SecretValue's Value buffer is owned by the
    // caller; the provider does not retain a reference. The
    // caller is responsible for calling SecretValue.Zero when
    // the value is no longer needed.
    Fetch(ctx context.Context, ref SecretRef) (SecretValue, error)

    // Close releases any resources held by the provider.
    // Safe to call multiple times; subsequent calls are no-ops.
    Close() error
}

// SecretRef identifies one secret in one provider.
//
// Constructed by ParseRef from a URI string. Callers should not
// build SecretRef literals directly except in tests — going
// through ParseRef ensures consistent validation.
type SecretRef struct {
    Scheme   string            // "keyring", "vault", ...
    Host     string            // URI host component
    Path     string            // URI path with leading slash trimmed
    Field    string            // optional fragment ("#token"); empty if absent
    Metadata map[string]string // provider-specific hints (currently unused; reserved)
}

// SecretValue is the result of a successful Fetch.
//
// The Value field holds the secret bytes. The caller owns this
// buffer and should call Zero on the SecretValue when done.
type SecretValue struct {
    Value     []byte        // secret material; caller-owned
    TTL       time.Duration // 0 = no lease information
    LeaseID   string        // empty if not leased
    Version   string        // empty if not versioned
    FetchedAt time.Time
}

// Zero overwrites the secret bytes with zeros and clears the
// other fields. After Zero returns, the SecretValue holds no
// secret material. Idempotent.
func (sv *SecretValue) Zero() {
    for i := range sv.Value {
        sv.Value[i] = 0
    }
    sv.Value = nil
    sv.LeaseID = ""
    sv.Version = ""
}

// ProviderConfig is a marker interface implemented by each
// provider's specific config struct (KeyringConfig, VaultConfig,
// etc.). The registry — to be added in a later plan — uses
// ProviderConfig to dispatch to the right constructor at policy
// load time. v3 has only one implementation: KeyringConfig.
type ProviderConfig interface {
    providerConfig() // sealed marker
}
```

### Notes

- **`SecretValue.Zero` mirrors `credsub.Table.Zero`.** Plan 10 will pull a `SecretValue` from a provider, hand its bytes to `credsub.Table.Add` (which copies them), and immediately call `SecretValue.Zero`. Real credentials live in two places briefly; both are zeroed deterministically.
- **`ProviderConfig` is sealed** with a private method so external packages can't accidentally implement it. The registry that consumes it ships in a later plan.
- **`Metadata map[string]string`** on `SecretRef` is reserved for v2 — providers in this plan don't read it. Including it now means adding a field to a public type later isn't a churn cost.
- **No mlock, no encryption-at-rest.** Section 10 of the parent spec excludes these.

## Section 2 — Sentinel errors

```go
// internal/proxy/secrets/errors.go
package secrets

import "errors"

var (
    // ErrNotFound is returned when a Fetch targets a secret that
    // does not exist in the backend.
    ErrNotFound = errors.New("secrets: not found")

    // ErrUnauthorized is returned when the backend rejects the
    // provider's own credentials.
    ErrUnauthorized = errors.New("secrets: unauthorized")

    // ErrInvalidURI is returned by ParseRef when a URI is
    // syntactically malformed (bad scheme delimiter, etc.).
    ErrInvalidURI = errors.New("secrets: invalid URI")

    // ErrUnsupportedScheme is returned by ParseRef when the
    // scheme is not one of the v1 schemes (vault, aws-sm,
    // gcp-sm, azure-kv, op, keyring).
    ErrUnsupportedScheme = errors.New("secrets: unsupported scheme")

    // ErrFieldNotSupported is returned by a provider when a
    // SecretRef carries a Field but the provider's backend
    // is single-valued (e.g. keyring entries are scalar).
    ErrFieldNotSupported = errors.New("secrets: field not supported")

    // ErrKeyringUnavailable is returned by the keyring
    // provider's New constructor when the OS keyring backend
    // cannot be reached at all (e.g. headless Linux with no
    // running Secret Service).
    ErrKeyringUnavailable = errors.New("secrets: keyring unavailable")
)
```

### Wrapping conventions

Every error returned from a public function in the `secrets` package and its subpackages either:
1. **Is** one of the sentinels, returned directly (e.g., `secrets.ErrNotFound`), or
2. **Wraps** a sentinel via `fmt.Errorf("%w: ...", sentinel, detail)` so callers can use `errors.Is(err, secrets.ErrNotFound)` to discriminate.

Callers in later plans will branch on `errors.Is(err, secrets.ErrNotFound)` to honor `on_missing: fail | skip | fake_only`. Wrapping is therefore part of the interface contract, not optional.

## Section 3 — URI parser

```go
// internal/proxy/secrets/uri.go
package secrets

import (
    "fmt"
    "net/url"
    "strings"
)

// supportedSchemes is the closed set of v1 URI schemes.
// ParseRef returns ErrUnsupportedScheme for anything else.
var supportedSchemes = map[string]struct{}{
    "vault":    {},
    "aws-sm":   {},
    "gcp-sm":   {},
    "azure-kv": {},
    "op":       {},
    "keyring":  {},
}

// ParseRef parses a secret reference URI of the form
//
//     scheme://host[/path][#field]
//
// and returns a SecretRef. The fragment, if present, becomes
// SecretRef.Field. The path's leading slash is stripped.
//
// ParseRef does not validate per-provider semantics — it only
// validates the URI grammar and that the scheme is one of the
// six known schemes. Each provider validates its own SecretRef
// in Fetch.
func ParseRef(uri string) (SecretRef, error) {
    if uri == "" {
        return SecretRef{}, fmt.Errorf("%w: empty", ErrInvalidURI)
    }

    u, err := url.Parse(uri)
    if err != nil {
        return SecretRef{}, fmt.Errorf("%w: %s", ErrInvalidURI, err)
    }

    if u.Scheme == "" {
        return SecretRef{}, fmt.Errorf("%w: missing scheme", ErrInvalidURI)
    }
    if _, ok := supportedSchemes[u.Scheme]; !ok {
        return SecretRef{}, fmt.Errorf("%w: %q", ErrUnsupportedScheme, u.Scheme)
    }
    if u.Host == "" {
        return SecretRef{}, fmt.Errorf("%w: missing host", ErrInvalidURI)
    }
    if u.RawQuery != "" {
        return SecretRef{}, fmt.Errorf("%w: query strings not allowed", ErrInvalidURI)
    }
    if u.User != nil {
        return SecretRef{}, fmt.Errorf("%w: userinfo not allowed", ErrInvalidURI)
    }

    return SecretRef{
        Scheme: u.Scheme,
        Host:   u.Host,
        Path:   strings.TrimPrefix(u.Path, "/"),
        Field:  u.Fragment,
    }, nil
}

// String renders a SecretRef back to its canonical URI form.
// Round-trips with ParseRef for any value ParseRef accepts.
func (r SecretRef) String() string {
    var b strings.Builder
    b.WriteString(r.Scheme)
    b.WriteString("://")
    b.WriteString(r.Host)
    if r.Path != "" {
        b.WriteByte('/')
        b.WriteString(r.Path)
    }
    if r.Field != "" {
        b.WriteByte('#')
        b.WriteString(r.Field)
    }
    return b.String()
}
```

### Examples

| URI | Scheme | Host | Path | Field |
|---|---|---|---|---|
| `keyring://agentsh/vault_token` | `keyring` | `agentsh` | `vault_token` | `` |
| `vault://kv/data/github#token` | `vault` | `kv` | `data/github` | `token` |
| `aws-sm://prod/api-keys/anthropic` | `aws-sm` | `prod` | `api-keys/anthropic` | `` |
| `op://Personal/Stripe/credential` | `op` | `Personal` | `Stripe/credential` | `` |
| `azure-kv://corp-vault/anthropic-key` | `azure-kv` | `corp-vault` | `anthropic-key` | `` |
| `gcp-sm://projects/123/secrets/x/versions/latest` | `gcp-sm` | `projects` | `123/secrets/x/versions/latest` | `` |

### Test coverage (`uri_test.go`)

- `TestParseRef_HappyPath` — each of the six schemes parses to the right struct.
- `TestParseRef_EmptyString` → `ErrInvalidURI`
- `TestParseRef_NoScheme` → `ErrInvalidURI`
- `TestParseRef_UnsupportedScheme` (`http://x`, `file://x`, `vault2://x`) → `ErrUnsupportedScheme`
- `TestParseRef_NoHost` (`vault:///path`) → `ErrInvalidURI`
- `TestParseRef_QueryStringRejected` (`keyring://a/b?x=1`) → `ErrInvalidURI`
- `TestParseRef_UserInfoRejected` (`keyring://user:pass@host/path`) → `ErrInvalidURI`
- `TestParseRef_WithFragment` — `vault://kv/data/x#token` → `Field: "token"`
- `TestParseRef_PathWithSlashes` — `vault://kv/data/path/to/secret` → `Path: "data/path/to/secret"`
- `TestParseRef_PathWithEncodedChars` — `vault://kv/data/team%20a` → `Path: "data/team a"` (verifies `net/url` decoded the path)
- `TestSecretRef_String_RoundTrip` — parse → String → parse, idempotent
- `TestParseRef_ErrorWrapping` — errors are wrappable with `errors.Is`

### Design notes

- **Query strings rejected.** Adding them later is non-breaking. Allowing them now and removing later would break configs.
- **Permissive about path content.** Slashes are fine. Encoded characters are decoded by `net/url`. Each provider's `Fetch` validates whether the path makes sense for its backend. The parser is a syntax check, not a semantic one.

## Section 4 — Keyring provider

```go
// internal/proxy/secrets/keyring/config.go
package keyring

import secrets "github.com/agentsh/agentsh/internal/proxy/secrets"

// Config configures the keyring provider.
//
// Currently empty: every keyring entry is identified entirely by
// its SecretRef (host = service, path = user). v2 may add fields
// like a default service prefix or a per-OS backend selector.
type Config struct{}

func (Config) providerConfig() {} // implements secrets.ProviderConfig

// Compile-time assertion that *Provider satisfies the interface.
var _ secrets.SecretProvider = (*Provider)(nil)
```

```go
// internal/proxy/secrets/keyring/provider.go
package keyring

import (
    "context"
    "errors"
    "fmt"
    "sync"
    "time"

    keyringlib "github.com/zalando/go-keyring"

    secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Provider is an OS-keyring-backed SecretProvider.
//
// On macOS this is the system Keychain, on Linux it's the
// Secret Service via libsecret/D-Bus, and on Windows it's
// Credential Manager.
//
// Concurrency: safe for concurrent Fetch and Close.
type Provider struct {
    mu     sync.Mutex
    closed bool
}

// New constructs a keyring Provider.
//
// New verifies the OS keyring backend is reachable by issuing
// a probe call. If the probe returns a "backend unavailable"
// error (D-Bus not running, Secret Service not registered,
// Keychain locked at a level we can't unlock from code), New
// returns ErrKeyringUnavailable.
//
// A probe that returns "not found" for the probe key counts
// as success — the backend is reachable, the probe key just
// doesn't exist.
func New(_ Config) (*Provider, error) {
    // Probe with a sentinel that should never exist. We expect
    // either nil (probe key happened to exist — fine) or
    // keyringlib.ErrNotFound. Any other error means the
    // backend itself is unreachable.
    _, err := keyringlib.Get("agentsh-probe", "agentsh-keyring-availability-probe")
    if err != nil && !errors.Is(err, keyringlib.ErrNotFound) {
        return nil, fmt.Errorf("%w: %s", secrets.ErrKeyringUnavailable, err)
    }
    return &Provider{}, nil
}

// Name returns "keyring".
func (p *Provider) Name() string { return "keyring" }

// Fetch retrieves a secret from the OS keyring.
//
// The SecretRef must have:
//   - Scheme == "keyring"
//   - Host    (interpreted as the keyring service name)
//   - Path    (interpreted as the keyring account/user)
//   - Field   empty (keyring entries are scalar; ErrFieldNotSupported otherwise)
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
    p.mu.Lock()
    if p.closed {
        p.mu.Unlock()
        return secrets.SecretValue{}, errors.New("keyring: provider closed")
    }
    p.mu.Unlock()

    if ref.Scheme != "keyring" {
        return secrets.SecretValue{}, fmt.Errorf("keyring: wrong scheme %q", ref.Scheme)
    }
    if ref.Host == "" {
        return secrets.SecretValue{}, fmt.Errorf("%w: keyring URI missing service (host)", secrets.ErrInvalidURI)
    }
    if ref.Path == "" {
        return secrets.SecretValue{}, fmt.Errorf("%w: keyring URI missing user (path)", secrets.ErrInvalidURI)
    }
    if ref.Field != "" {
        return secrets.SecretValue{}, fmt.Errorf("%w: keyring entries are scalar", secrets.ErrFieldNotSupported)
    }

    // Honor context cancellation by checking before the call.
    // The zalando library does not accept a context, so the call
    // itself is uninterruptible — best-effort respect for ctx.
    if err := ctx.Err(); err != nil {
        return secrets.SecretValue{}, err
    }

    val, err := keyringlib.Get(ref.Host, ref.Path)
    if err != nil {
        if errors.Is(err, keyringlib.ErrNotFound) {
            return secrets.SecretValue{}, fmt.Errorf("%w: %s", secrets.ErrNotFound, ref.String())
        }
        // Anything else from the library is treated as a transport
        // failure. We do not have a way to distinguish "auth
        // rejected" from "backend disappeared mid-session"; both
        // map to a wrapped error rather than ErrUnauthorized.
        return secrets.SecretValue{}, fmt.Errorf("keyring fetch %s: %w", ref.String(), err)
    }

    return secrets.SecretValue{
        Value:     []byte(val),
        FetchedAt: time.Now(),
    }, nil
}

// Close marks the provider closed. Subsequent Fetches return an
// error. Idempotent. The OS keyring itself has no connection
// state to release.
func (p *Provider) Close() error {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.closed = true
    return nil
}
```

### Behavioral choices

1. **Construction probe.** `New` issues one `keyringlib.Get` against a sentinel (service=`agentsh-probe`, user=`...availability-probe`). The library wraps the underlying OS error. We accept either `nil` or `ErrNotFound` and reject anything else as `ErrKeyringUnavailable`. This is the "fail loud at construction" behavior settled in brainstorming.
2. **No `ErrUnauthorized` mapping.** The zalando library doesn't expose an unauthorized-distinct error from any of its three backends. Treating unknown errors as transport failures is honest. A future provider with a clearer signal can return `ErrUnauthorized`.
3. **Context honored only at the boundaries.** The library's call signatures don't take a context. We check `ctx.Err()` before the call. We do NOT spawn a goroutine to race the call against ctx — that creates an orphan goroutine on cancel and the zalando call is fast enough that it isn't worth it.
4. **`closed` is a soft check.** A concurrent `Fetch` running when `Close` is called isn't aborted; the in-flight `Fetch` finishes, the next `Fetch` errors. Matches `sync.Once`-style cleanup semantics.
5. **No caching.** v1 doesn't need it for keyring (local, fast).

### Test coverage (`keyring/provider_test.go`)

All round-trip tests use `t.Skip("OS keyring not available on this host")` if `New` returns `ErrKeyringUnavailable`. URI-validation tests run unconditionally.

- `TestNew_HappyPath` — constructs successfully on a live keyring; skips otherwise.
- `TestFetch_RoundTrip` — writes via `keyringlib.Set`, fetches via `Provider.Fetch`, verifies equality, deletes in `t.Cleanup`.
- `TestFetch_NotFound` — fetches a non-existent key, expects `secrets.ErrNotFound` wrapped.
- `TestFetch_WrongScheme` — ref with `Scheme: "vault"`, expects error.
- `TestFetch_MissingHost` — empty host, expects `ErrInvalidURI`.
- `TestFetch_MissingPath` — empty path, expects `ErrInvalidURI`.
- `TestFetch_WithField` — ref with `Field: "x"`, expects `ErrFieldNotSupported`.
- `TestFetch_AfterClose` — Close, then Fetch, expects "provider closed" error.
- `TestFetch_ContextCanceled` — cancel ctx before Fetch, expects `context.Canceled`.
- `TestClose_Idempotent` — Close twice, no panic, no error.
- `TestProvider_ConcurrentFetch` — 8 goroutines fetching concurrently with `-race`, no data races.
- Compile-time check: `var _ secrets.SecretProvider = (*Provider)(nil)`.

### Test isolation

Round-trip tests use a unique service+account name per test run:

```go
account := fmt.Sprintf("agentsh-test-%s-%d", t.Name(), time.Now().UnixNano())
```

Cleaned up via `t.Cleanup(func() { _ = keyringlib.Delete(service, account) })`. Service name is also test-namespaced (`agentsh-test`), so a developer's actual `agentsh` keyring entries are never touched.

## Section 5 — MemoryProvider (test fake)

```go
// internal/proxy/secrets/secretstest/memory.go
//
// Package secretstest provides test doubles that implement the
// secrets.SecretProvider interface. Production code MUST NOT
// import this package.
package secretstest

import (
    "context"
    "sync"
    "time"

    secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// MemoryProvider is an in-memory SecretProvider for use in tests.
//
// It serves a fixed map of secrets keyed by the canonical URI
// form of the SecretRef (i.e. SecretRef.String()). Tests
// construct one with a map of seeded values, optionally add or
// remove entries during the test, and pass it where a real
// provider would go.
type MemoryProvider struct {
    name string

    mu      sync.RWMutex
    entries map[string][]byte // key: SecretRef.String()
    closed  bool
}

// NewMemoryProvider returns a MemoryProvider seeded with the
// given entries. The seed map is copied; later mutations to
// the caller's map do not affect the provider.
//
// name is returned by the provider's Name() method. Pass any
// non-empty string ("test", "memory", "fake-vault", ...).
func NewMemoryProvider(name string, seed map[string][]byte) *MemoryProvider {
    entries := make(map[string][]byte, len(seed))
    for k, v := range seed {
        cp := make([]byte, len(v))
        copy(cp, v)
        entries[k] = cp
    }
    return &MemoryProvider{name: name, entries: entries}
}

// Name returns the configured provider name.
func (m *MemoryProvider) Name() string { return m.name }

// Fetch returns the secret seeded under ref.String(), or
// secrets.ErrNotFound. Returns an error after Close has been
// called.
func (m *MemoryProvider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
    if err := ctx.Err(); err != nil {
        return secrets.SecretValue{}, err
    }
    m.mu.RLock()
    defer m.mu.RUnlock()
    if m.closed {
        return secrets.SecretValue{}, errClosed
    }
    val, ok := m.entries[ref.String()]
    if !ok {
        return secrets.SecretValue{}, secrets.ErrNotFound
    }
    cp := make([]byte, len(val))
    copy(cp, val)
    return secrets.SecretValue{
        Value:     cp,
        FetchedAt: time.Now(),
    }, nil
}

// Add inserts or replaces an entry. Test-only mutation hook.
func (m *MemoryProvider) Add(uri string, value []byte) error {
    ref, err := secrets.ParseRef(uri)
    if err != nil {
        return err
    }
    m.mu.Lock()
    defer m.mu.Unlock()
    cp := make([]byte, len(value))
    copy(cp, value)
    m.entries[ref.String()] = cp
    return nil
}

// Remove deletes an entry. Test-only mutation hook.
func (m *MemoryProvider) Remove(uri string) {
    ref, err := secrets.ParseRef(uri)
    if err != nil {
        return
    }
    m.mu.Lock()
    defer m.mu.Unlock()
    delete(m.entries, ref.String())
}

// Close marks the provider closed. Idempotent.
func (m *MemoryProvider) Close() error {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.closed = true
    return nil
}

var errClosed = stringError("secretstest: memory provider closed")

type stringError string

func (e stringError) Error() string { return string(e) }
```

### Behavioral contract

1. **Returned slices are copies.** The provider's internal map and the caller's `SecretValue.Value` never alias. A test can safely mutate or zero the returned value.
2. **Seeded slices are copied on construction.** Mutating the seed map after `NewMemoryProvider` does not affect the provider.
3. **`Add` validates the URI** through `ParseRef` so test code can't accidentally seed unparseable refs.
4. **No length-preservation enforcement.** That's `credsub.Table`'s job. The MemoryProvider serves whatever bytes you give it.
5. **No `Zero` of internal state on `Close`.** Test fakes don't pretend to be secure; the test process exits and the GC handles it.

### Test coverage (`memory_test.go`)

- `TestNewMemoryProvider_CopiesSeed` — mutate seed map after construction, fetch returns the original value.
- `TestFetch_HappyPath` — seed `keyring://agentsh/x` → `[]byte("foo")`, fetch returns `"foo"`.
- `TestFetch_NotFound` — empty seed, fetch returns `secrets.ErrNotFound`.
- `TestFetch_ReturnsCopy` — fetch, mutate the returned `Value`, fetch again, verify second result is unmutated.
- `TestFetch_AfterClose` — Close, then Fetch, expects `errClosed`.
- `TestAdd_ThenFetch` — add, fetch, verify.
- `TestAdd_InvalidURI` — add with `"not-a-uri"`, expects `ErrInvalidURI`.
- `TestAdd_Replace` — add same URI twice with different values, fetch returns the second.
- `TestRemove` — add then remove then fetch, expects `ErrNotFound`.
- `TestConcurrentAccess_NoRaces` — 8 readers + 1 writer over 200 iterations with `-race`.
- `TestName` — returns the constructor argument.
- Compile-time: `var _ secrets.SecretProvider = (*MemoryProvider)(nil)`.

### Why a separate `secretstest` package

- Plan 4+ tests (Vault provider's constructor needs a token chained from another provider), Plan 10's session-manager tests, and integration tests all need this fake. A `_test.go` file is only visible to tests in its own package.
- Putting it in `secretstest/` means it's importable from any test package in the repo, but the package doc explicitly says **production code must not import it**.

## Section 6 — Concurrency model and dependency policy

### Concurrency

| Type | Concurrency-safe? | Mechanism |
|---|---|---|
| `secrets.SecretRef` | Immutable after construction | by-value type |
| `secrets.SecretValue` | Caller-owned, single-owner expected | not synchronized; the design assumes one goroutine handles a fetched value |
| `secrets.ParseRef` | Yes | pure function |
| `keyring.Provider` | Yes | `sync.Mutex` for `closed` field |
| `secretstest.MemoryProvider` | Yes | `sync.RWMutex` over `entries` and `closed` |

The `SecretValue` deliberately has no mutex. It's a value passed from one goroutine to another by ownership transfer. Sharing a `SecretValue` across goroutines is a misuse — but the bytes are immutable in normal flow (only `Zero()` mutates them, and that's the terminal call).

### Dependency policy

- **New direct dependency:** `github.com/zalando/go-keyring` (Apache 2.0).
- **Expected transitive deps:**
  - On Linux: `github.com/godbus/dbus/v5` — to be verified during implementation; if it's not already in `go.sum` indirectly, it becomes a new transitive dep.
  - On macOS: cgo against the system `Security` framework — no Go module dep.
  - On Windows: `golang.org/x/sys/windows` (already in `go.sum`).
- Plan 3 will run `go mod tidy` and inspect the resulting `go.sum` delta in its own commit. The implementer must call out any unexpected transitive deps in their report; we may want to vendor or pin if they bring in surprising things.

### Cross-platform builds

The `keyring` package compiles on all three target OSes — that's the whole point of using the zalando library. We do NOT need build tags. The library handles per-OS dispatch internally with its own build-tagged files.

What we DO need to verify:
- `GOOS=linux go build ./...`
- `GOOS=darwin go build ./...`
- `GOOS=windows go build ./...`

`go test ./internal/proxy/secrets/...` only exercises the in-process keyring on the host OS. The CI matrix (Linux/macOS/Windows runners) catches per-OS regressions in the round-trip tests.

## Section 7 — Testing strategy

### Test categories

| Category | Files | Runs on | CI? |
|---|---|---|---|
| URI parser | `uri_test.go` | Pure Go, all OSes | Yes (every CI job) |
| Provider type contract | `provider_test.go` | Pure Go, all OSes | Yes |
| Errors | exercised throughout | Pure Go, all OSes | Yes |
| MemoryProvider | `secretstest/memory_test.go` | Pure Go, all OSes | Yes |
| Keyring URI validation | `keyring/provider_test.go` | Pure Go, all OSes | Yes |
| Keyring round-trip | `keyring/provider_test.go` | Needs OS keyring | macOS + Windows runners; Linux runner with Secret Service skips; headless Linux skips |
| Keyring race | `keyring/provider_test.go` | Needs OS keyring + `-race` | Same as round-trip |

### Skip discipline

The keyring round-trip tests use this pattern at the top of each test:

```go
func TestFetch_RoundTrip(t *testing.T) {
    p, err := keyring.New(keyring.Config{})
    if err != nil {
        if errors.Is(err, secrets.ErrKeyringUnavailable) {
            t.Skip("OS keyring not available on this host")
        }
        t.Fatalf("New() failed: %v", err)
    }
    t.Cleanup(func() { _ = p.Close() })
    // ...
}
```

This means:
- A developer running `go test ./...` on a Mac with Keychain unlocked: tests run.
- A developer running in a headless Linux container: tests skip with a clear reason. Suite still passes.
- CI Linux runner with no D-Bus: skips. CI macOS runner with Keychain access: runs. CI Windows runner with Wincred: runs.

Goal: **the test suite never fails because the environment is hostile**, but it also never silently passes when the environment is friendly. Skips are visible in test output.

### Shared `ProviderContract` test helper

Plan 3 includes one extra check: the MemoryProvider must satisfy the same interface contract as the real keyring provider. We verify this with a shared contract function in `internal/proxy/secrets/secretstest/contract.go`:

```go
// ProviderContract runs a baseline set of behavioral assertions
// against any SecretProvider. Each provider's test file calls it.
//
// It lives in secretstest (and is exported) so that subpackages
// like internal/proxy/secrets/keyring/ can import and call it
// without going through an exported helper in the parent package.
func ProviderContract(t *testing.T, name string, p secrets.SecretProvider) {
    t.Helper()
    t.Run(name+"/Name", func(t *testing.T) { /* non-empty */ })
    t.Run(name+"/FetchNotFound", func(t *testing.T) { /* well-known unset URI */ })
    t.Run(name+"/CloseIdempotent", func(t *testing.T) { /* call twice */ })
    t.Run(name+"/FetchAfterClose", func(t *testing.T) { /* expects error */ })
}
```

`secretstest/memory_test.go` calls `ProviderContract(t, "memory", NewMemoryProvider("memory", nil))` directly (same package). `keyring/provider_test.go` calls `secretstest.ProviderContract(t, "keyring", p)` after constructing a `keyring.Provider` (skipping if `New` returns `ErrKeyringUnavailable`). Both must pass the same baseline. This catches drift between the real and fake provider behaviors.

The helper deliberately lives in `secretstest/` (a non-`_test.go` file) rather than in `secrets/provider_test.go` because functions defined in `_test.go` files are only visible within their own package — the `keyring` subpackage could not call one defined in `secrets/provider_test.go`. Putting it in `secretstest/contract.go` is a tiny convention break (the package now exports test helpers via two files, `memory.go` and `contract.go`), but it's the cleanest way to share the helper across subpackages without exporting test scaffolding from the production `secrets` package itself.

### Verification matrix Plan 3 must pass before merge

- [ ] `go build ./...` — clean
- [ ] `GOOS=windows go build ./...` — clean
- [ ] `GOOS=darwin go build ./...` — clean
- [ ] `GOOS=linux go build ./...` — clean
- [ ] `go vet ./internal/proxy/secrets/...` — clean
- [ ] `go test ./internal/proxy/secrets/... -race -count=1` — all tests pass on the host
- [ ] `go test ./...` — full project suite passes (no regressions in unrelated packages)
- [ ] Round-trip tests skip cleanly when Secret Service is unavailable; run when available
- [ ] `go.mod` / `go.sum` diff reviewed: only zalando + necessary transitives
- [ ] Zero call sites outside `internal/proxy/secrets/` (verified by grep)
- [ ] `pkg/secrets` is unchanged (verified by `git diff main -- pkg/secrets/`)
- [ ] CI matrix passes (Linux/macOS/Windows builds + tests)
- [ ] `roborev review --reasoning maximum` on each commit, all medium-or-above findings fixed

## Section 8 — Task decomposition (preview for writing-plans)

This is a preview, not the implementation plan itself. The writing-plans skill will turn this into a TDD-shaped task list.

| # | Task | Files | LoC est. | Notes |
|---|---|---|---|---|
| 1 | Package skeleton + doc.go + sentinel errors | `secrets/doc.go`, `secrets/errors.go` | ~80 | TDD: errors_test verifies sentinels are distinct + wrappable |
| 2 | `SecretRef`, `SecretValue`, `ProviderConfig`, `SecretProvider` interface | `secrets/provider.go`, `secrets/provider_test.go` | ~150 | Includes `SecretValue.Zero` + test |
| 3 | URI parser happy path (single scheme) | `secrets/uri.go`, `secrets/uri_test.go` | ~80 | Red→green, just `keyring://` first |
| 4 | URI parser: all six schemes + error cases | extend uri.go + uri_test.go | ~100 | Add the supportedSchemes map, all the rejection tests |
| 5 | URI parser: round-trip `String()` method | extend uri.go + uri_test.go | ~40 | |
| 6 | Add zalando dependency | `go.mod`, `go.sum` | n/a | `go get github.com/zalando/go-keyring`; verify transitive deps |
| 7 | Keyring config + compile-time interface assertion | `keyring/doc.go`, `keyring/config.go` | ~30 | |
| 8 | Keyring `New` + availability probe + `ErrKeyringUnavailable` | `keyring/provider.go`, `keyring/provider_test.go` | ~80 | Test skips if no OS keyring |
| 9 | Keyring `Fetch` URI validation | extend keyring/provider.go + tests | ~100 | Pure-Go tests, no OS interaction |
| 10 | Keyring `Fetch` round-trip happy path + ErrNotFound | extend keyring/provider.go + tests | ~80 | Skip if no OS keyring |
| 11 | Keyring `Close` + after-close behavior | extend keyring/provider.go + tests | ~50 | |
| 12 | Keyring concurrent access race test | extend keyring/provider_test.go | ~50 | `-race` |
| 13 | MemoryProvider: skeleton + happy-path Fetch | `secretstest/doc.go`, `secretstest/memory.go`, `secretstest/memory_test.go` | ~120 | |
| 14 | MemoryProvider: Add/Remove/Close/copy semantics | extend memory.go + tests | ~80 | |
| 15 | MemoryProvider: concurrent access race test | extend memory_test.go | ~50 | |
| 16 | Shared `ProviderContract` helper in `secretstest/contract.go` + applied to both providers | `secretstest/contract.go`, `secretstest/contract_test.go`, extend `keyring/provider_test.go` and `memory_test.go` | ~120 | Helper is exported because it crosses package boundaries |
| 17 | Cross-compile + full-project verification | none modified | n/a | `GOOS=windows`, `GOOS=darwin`, `go test ./...` |

**Total: 17 tasks, ~1,240 LoC (including tests).** Comparable to Plan 2 (11 tasks / ~2,600 LoC dominated by tests). Plan 3 should be smaller because the URI parser and MemoryProvider don't have the cascading-rewrite-bug-class footguns that `credsub.Table` did.

## Section 9 — Implementer footguns

Three things that might trip the implementer:

1. **`go-keyring` doesn't take a `context.Context`.** The implementer will be tempted to wrap the call in a goroutine and `select` on `ctx.Done()`. Don't. Orphan goroutine, no real cancellation in the OS layer. Document and move on. Best-effort context honoring is checking `ctx.Err()` before the call.

2. **macOS Keychain prompts.** First write to a new service may prompt the user "agentsh wants to access your Keychain — Always Allow / Allow Once / Deny." On a developer machine this is fine; in CI the macOS runner has a pre-unlocked Keychain. Tests use a unique per-run service name so any one prompt doesn't carry across runs.

3. **Linux Secret Service availability is brittle.** `dbus-launch` may or may not be running. The construction probe is the right gate, but the implementer should NOT try to start D-Bus themselves — that's the operator's job. The error message should be actionable: "OS keyring unreachable: D-Bus session bus not running. On a desktop this normally launches automatically; in a headless environment, start `dbus-daemon --session` or use a different secret backend."

## Open questions

None. All design decisions were settled during brainstorming. The implementer should treat any new ambiguity as a bug in this spec and surface it before implementing.

## Post-plan checklist

After all 17 tasks complete:

- [ ] `internal/proxy/secrets/` exists with `provider.go`, `errors.go`, `uri.go`, `doc.go`, and tests.
- [ ] `internal/proxy/secrets/keyring/` exists with `provider.go`, `config.go`, `doc.go`, and tests.
- [ ] `internal/proxy/secrets/secretstest/` exists with `memory.go`, `contract.go`, `doc.go`, and tests.
- [ ] `SecretProvider` interface has `Name`, `Fetch`, `Close`. `SecretRef` has `Scheme`, `Host`, `Path`, `Field`, `Metadata`. `SecretValue` has `Value`, `TTL`, `LeaseID`, `Version`, `FetchedAt`, and a `Zero` method.
- [ ] `ParseRef` accepts all six v1 schemes and rejects everything else.
- [ ] `keyring.New` fails loud with `ErrKeyringUnavailable` on headless Linux.
- [ ] `MemoryProvider` round-trips in tests; returns copies.
- [ ] `ProviderContract` helper applied to both providers.
- [ ] `go.mod` adds `github.com/zalando/go-keyring`; transitive deps reviewed.
- [ ] `pkg/secrets` is unchanged.
- [ ] Zero call sites in `.go` files outside `internal/proxy/secrets/`.
- [ ] All cross-compiles clean. CI green.

## Predecessor / successor

- **Predecessor:** Plan 2 (`credsub.Table`) — merged.
- **Successor:** Plan 4 (Vault provider). Plan 4 will be the first plan to need the URI parser for non-keyring schemes and to need the auth-chaining resolver. Plan 4 will also be where the provider registry (or at least its first version) lands, since two providers is the point at which you actually need a registry.
