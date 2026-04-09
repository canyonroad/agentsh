# SecretProvider interface + keyring provider (Plan 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the `SecretProvider` interface, the URI parser for the six v1 secret schemes, a working OS keyring provider backed by `github.com/zalando/go-keyring`, and a `MemoryProvider` test fake in a sibling `secretstest` subpackage. Zero call sites outside the new packages.

**Architecture:** A new package `internal/proxy/secrets/` holds the interface, types, URI parser, and sentinel errors. Per-backend providers live in subpackages (`internal/proxy/secrets/keyring/` for this plan). A sibling `internal/proxy/secrets/secretstest/` package carries the `MemoryProvider` test double and the shared `ProviderContract` helper. Nothing in `internal/session/`, `internal/api/`, `cmd/`, `pkg/`, or the existing dormant `pkg/secrets/` is touched.

**Tech Stack:** Go stdlib (`context`, `errors`, `fmt`, `net/url`, `strings`, `sync`, `time`, `testing`) plus one new direct dependency: `github.com/zalando/go-keyring` (Apache 2.0, wraps Keychain / Secret Service / Credential Manager). Module path: `github.com/agentsh/agentsh/internal/proxy/secrets`.

**Scope boundary:** This plan lands pure infrastructure. No registry, no YAML loader, no auth chaining, no connection to `credsub.Table`, no session wiring. Later plans consume this API:
- Plan 4 (Vault provider) is the first non-keyring provider and the point where a registry becomes necessary.
- Plan 5 (AWS Secrets Manager) adds the second cloud provider.
- Plan 10 wires everything into `internal/session/` and into `credsub.Table`.

**Spec reference:** `docs/superpowers/specs/2026-04-08-plan-03-secret-provider-keyring-design.md`.

**Parent spec reference:** `docs/superpowers/specs/2026-04-07-external-secrets-design.md` (Sections 2, 5, 9).

---

## Architectural notes (read before starting tasks)

### Why `internal/proxy/secrets/` and not `pkg/secrets/`

There is already a `pkg/secrets/` package in the tree. **It is dormant dead code**: it has Vault and AWS implementations but zero callers inside the daemon. Plan 3 does not touch it. A separate cleanup PR after Plans 4–5 (which land Vault and AWS in the new location) will delete `pkg/secrets/`. Until then, both trees coexist. Do not import `pkg/secrets`. Do not "merge" them. They have different interface shapes and different intended consumers.

### Interface lives at the parent package

`SecretProvider` is defined in `internal/proxy/secrets/provider.go`, not in a `secretsapi` subpackage. Every provider subpackage (`keyring/`, future `vault/`, future `awssm/`) imports the parent. Putting the interface at the parent is what prevents an import cycle.

### Sealed `ProviderConfig` marker interface

`ProviderConfig` has one unexported method, `providerConfig()`. External packages cannot implement it by accident. The registry (to ship in a later plan) will type-switch on `ProviderConfig` to dispatch to the right constructor. Plan 3 has one implementation: `keyring.Config`.

### URI grammar

`scheme://host[/path][#field]`. Query strings and userinfo are rejected. The six v1 schemes are hard-coded in a closed set: `vault`, `aws-sm`, `gcp-sm`, `azure-kv`, `op`, `keyring`. Adding a scheme later is a one-line change + tests.

The parser does grammar validation only. Each provider's `Fetch` validates semantic fit for its backend (e.g., "keyring URIs must not have a field").

### `SecretValue.Zero` mirrors `credsub.Table.Zero`

Plan 10 will pull a `SecretValue` from a provider, hand its bytes to `credsub.Table.Add` (which copies them), and immediately call `SecretValue.Zero`. The ownership rule from Plan 2 extends here: the provider hands the caller a buffer the caller owns; the caller is responsible for zeroing it when done. This plan does not call `Zero` from anywhere except tests — the rule is documented but enforcement is a consumer's concern.

### Keyring construction probe

`keyring.New` issues one `keyringlib.Get("agentsh-probe", "agentsh-keyring-availability-probe")` call. We accept either `nil` or `keyringlib.ErrNotFound` and treat anything else as `ErrKeyringUnavailable`. This catches headless Linux (no running Secret Service), macOS Keychain access denied, and Windows Credential Manager unavailable, at construction time. Fail loud at `New`, not during `Fetch`.

### No context honoring inside zalando calls

`github.com/zalando/go-keyring`'s `Get`/`Set`/`Delete` functions do NOT accept a `context.Context`. The implementer will be tempted to wrap the call in a goroutine and `select` on `ctx.Done()`. **Don't.** That creates an orphan goroutine on cancel, and the library call is fast enough that the orphan matters. Best-effort context honoring is a single `ctx.Err()` check immediately before the library call.

### `secretstest/` is a sibling test-helper package

Following the stdlib convention (`httptest`, `iotest`, `fstest`), the package lives at `internal/proxy/secrets/secretstest/`. It exports `MemoryProvider` and `ProviderContract`. Production code must not import it; the package doc says so explicitly. The shared contract helper lives in `secretstest/contract.go` (a non-`_test.go` file) because test-package-only helpers in `secrets/provider_test.go` would be invisible to sibling packages like `keyring/`.

### Concurrency

All providers must be safe for concurrent `Fetch` and `Close`. `keyring.Provider` uses a `sync.Mutex` over a `closed` flag. `secretstest.MemoryProvider` uses a `sync.RWMutex` over an entries map. `SecretRef` is a value type and has no mutex. `SecretValue` is single-owner by convention; tests should not share one across goroutines.

### Dependency hygiene

Task 4 adds `github.com/zalando/go-keyring`. The implementer MUST inspect the `go.sum` delta and report any surprising transitive dependencies. On Linux the zalando library depends on `github.com/godbus/dbus/v5`; on macOS it uses cgo against the system `Security` framework (no Go module dep); on Windows it uses `golang.org/x/sys/windows` (already in the tree). Anything else is a surprise and needs to be called out before merging.

---

## File Structure

**Files created by this plan:**

- `internal/proxy/secrets/doc.go` — package-level doc comment.
- `internal/proxy/secrets/errors.go` — six sentinel errors.
- `internal/proxy/secrets/provider.go` — `SecretProvider` interface, `SecretRef`, `SecretValue` (with `Zero` method), `ProviderConfig` marker.
- `internal/proxy/secrets/provider_test.go` — tests for `SecretValue.Zero` and error wrapping invariants.
- `internal/proxy/secrets/uri.go` — `ParseRef` and `SecretRef.String`.
- `internal/proxy/secrets/uri_test.go` — URI parser unit tests.
- `internal/proxy/secrets/keyring/doc.go` — package doc.
- `internal/proxy/secrets/keyring/config.go` — `Config` struct and `ProviderConfig` marker implementation plus compile-time assertion.
- `internal/proxy/secrets/keyring/provider.go` — `Provider` type, `New`, `Name`, `Fetch`, `Close`.
- `internal/proxy/secrets/keyring/provider_test.go` — keyring unit tests (with skip-on-unavailable guards).
- `internal/proxy/secrets/secretstest/doc.go` — package doc and "production code must not import" warning.
- `internal/proxy/secrets/secretstest/memory.go` — `MemoryProvider` fake.
- `internal/proxy/secrets/secretstest/memory_test.go` — MemoryProvider unit tests.
- `internal/proxy/secrets/secretstest/contract.go` — `ProviderContract` shared test helper.
- `internal/proxy/secrets/secretstest/contract_test.go` — sanity test that the helper itself runs.

**Files modified by this plan:**

- `go.mod` — add `github.com/zalando/go-keyring`.
- `go.sum` — regenerated by `go mod tidy`.

**Files NOT modified (explicitly verify unchanged before merge):**

- Anything under `pkg/secrets/`.
- Anything under `internal/session/`, `internal/api/`, `cmd/`.
- Anything under `internal/proxy/credsub/` (Plan 2's package is independent).

---

## Task 1: Package skeleton, doc, and sentinel errors

**Files:**
- Create: `internal/proxy/secrets/doc.go`
- Create: `internal/proxy/secrets/errors.go`
- Create: `internal/proxy/secrets/errors_test.go`

- [ ] **Step 1: Create `doc.go` with the package doc comment**

Write to `internal/proxy/secrets/doc.go`:

```go
// Package secrets defines the SecretProvider interface that agentsh
// uses to fetch real credentials from external secret stores at
// session start, plus the URI grammar and sentinel errors shared by
// all provider implementations.
//
// Provider implementations live in subpackages, one per backend:
//
//   - internal/proxy/secrets/keyring — OS keyring (Keychain / Secret
//     Service / Credential Manager) via github.com/zalando/go-keyring.
//
// Future plans add vault, awssm, gcpsm, azurekv, and op subpackages.
// Every provider imports this package for the interface and types;
// this package imports none of them.
//
// Test doubles live in the sibling secretstest package. Production
// code must not import secretstest.
//
// The design is documented in
// docs/superpowers/specs/2026-04-08-plan-03-secret-provider-keyring-design.md
// and the parent migration spec
// docs/superpowers/specs/2026-04-07-external-secrets-design.md.
package secrets
```

- [ ] **Step 2: Write the failing sentinel-errors test**

Write to `internal/proxy/secrets/errors_test.go`:

```go
package secrets

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrNotFound,
		ErrUnauthorized,
		ErrInvalidURI,
		ErrUnsupportedScheme,
		ErrFieldNotSupported,
		ErrKeyringUnavailable,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel %d (%v) should not be errors.Is %d (%v)", i, a, j, b)
			}
		}
	}
}

func TestSentinelErrors_AreWrappable(t *testing.T) {
	sentinels := map[string]error{
		"ErrNotFound":           ErrNotFound,
		"ErrUnauthorized":       ErrUnauthorized,
		"ErrInvalidURI":         ErrInvalidURI,
		"ErrUnsupportedScheme":  ErrUnsupportedScheme,
		"ErrFieldNotSupported":  ErrFieldNotSupported,
		"ErrKeyringUnavailable": ErrKeyringUnavailable,
	}
	for name, sentinel := range sentinels {
		wrapped := fmt.Errorf("%w: context detail", sentinel)
		if !errors.Is(wrapped, sentinel) {
			t.Errorf("%s: wrapped error is not errors.Is the sentinel", name)
		}
	}
}

func TestSentinelErrors_MessagesStartWithPrefix(t *testing.T) {
	sentinels := []error{
		ErrNotFound,
		ErrUnauthorized,
		ErrInvalidURI,
		ErrUnsupportedScheme,
		ErrFieldNotSupported,
		ErrKeyringUnavailable,
	}
	const prefix = "secrets:"
	for _, s := range sentinels {
		msg := s.Error()
		if len(msg) < len(prefix) || msg[:len(prefix)] != prefix {
			t.Errorf("sentinel %q should start with %q", msg, prefix)
		}
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/proxy/secrets/... -run TestSentinelErrors -v`
Expected: FAIL with compile errors mentioning `undefined: ErrNotFound`, `undefined: ErrUnauthorized`, etc.

- [ ] **Step 4: Create `errors.go` with the sentinel definitions**

Write to `internal/proxy/secrets/errors.go`:

```go
package secrets

import "errors"

// ErrNotFound is returned when a Fetch targets a secret that does
// not exist in the backend. Callers should branch on
// errors.Is(err, ErrNotFound) to honor policy like on_missing.
var ErrNotFound = errors.New("secrets: not found")

// ErrUnauthorized is returned when the backend rejects the
// provider's own credentials (bad token, expired lease, etc.).
// Distinct from ErrKeyringUnavailable, which means the backend
// itself is unreachable.
var ErrUnauthorized = errors.New("secrets: unauthorized")

// ErrInvalidURI is returned by ParseRef when a URI is syntactically
// malformed (empty string, bad scheme delimiter, missing host,
// query string present, userinfo present). Also returned by a
// provider's Fetch when a SecretRef is missing required semantic
// pieces for that backend.
var ErrInvalidURI = errors.New("secrets: invalid URI")

// ErrUnsupportedScheme is returned by ParseRef when the URI scheme
// is syntactically valid but not one of the six v1 schemes (vault,
// aws-sm, gcp-sm, azure-kv, op, keyring).
var ErrUnsupportedScheme = errors.New("secrets: unsupported scheme")

// ErrFieldNotSupported is returned by a provider when a SecretRef
// carries a non-empty Field but the provider's backend stores
// scalar values only (e.g. OS keyring entries are single-valued,
// unlike Vault KV-v2 entries which are field-addressable).
var ErrFieldNotSupported = errors.New("secrets: field not supported")

// ErrKeyringUnavailable is returned by the keyring provider's New
// constructor when the OS keyring backend cannot be reached at all
// (D-Bus not running, Keychain access denied at the OS level,
// Windows Credential Manager subsystem unavailable). It is a hard
// error; the operator must either set up the keyring or use a
// different provider.
var ErrKeyringUnavailable = errors.New("secrets: keyring unavailable")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/proxy/secrets/... -run TestSentinelErrors -v`
Expected: PASS. Three test cases: `TestSentinelErrors_AreDistinct`, `TestSentinelErrors_AreWrappable`, `TestSentinelErrors_MessagesStartWithPrefix`.

- [ ] **Step 6: Verify `go vet` is clean**

Run: `go vet ./internal/proxy/secrets/...`
Expected: no output, exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/secrets/doc.go internal/proxy/secrets/errors.go internal/proxy/secrets/errors_test.go
git commit -m "feat(secrets): add package skeleton and sentinel errors"
```

---

## Task 2: Core types — SecretRef, SecretValue, ProviderConfig, and SecretProvider interface

**Files:**
- Create: `internal/proxy/secrets/provider.go`
- Create: `internal/proxy/secrets/provider_test.go`

- [ ] **Step 1: Write the failing test for `SecretValue.Zero`**

Write to `internal/proxy/secrets/provider_test.go`:

```go
package secrets

import (
	"bytes"
	"testing"
	"time"
)

func TestSecretValue_Zero_OverwritesAndClears(t *testing.T) {
	sv := SecretValue{
		Value:     []byte("hunter2"),
		TTL:       5 * time.Minute,
		LeaseID:   "lease-123",
		Version:   "v4",
		FetchedAt: time.Now(),
	}

	// Capture the underlying array so we can verify it's zeroed
	// even after sv.Value is cleared.
	original := sv.Value
	sv.Zero()

	// Underlying bytes must be zeroed.
	if !bytes.Equal(original, []byte{0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("Zero did not wipe underlying bytes: %v", original)
	}
	// Value slice must be nil.
	if sv.Value != nil {
		t.Errorf("Value slice not nil after Zero: %v", sv.Value)
	}
	// LeaseID and Version must be cleared.
	if sv.LeaseID != "" {
		t.Errorf("LeaseID not cleared: %q", sv.LeaseID)
	}
	if sv.Version != "" {
		t.Errorf("Version not cleared: %q", sv.Version)
	}
}

func TestSecretValue_Zero_Idempotent(t *testing.T) {
	sv := SecretValue{Value: []byte("abc")}
	sv.Zero()
	sv.Zero() // must not panic
	if sv.Value != nil {
		t.Errorf("second Zero modified Value: %v", sv.Value)
	}
}

func TestSecretValue_Zero_OnZeroValue(t *testing.T) {
	var sv SecretValue
	sv.Zero() // must not panic on zero-value SecretValue
}

// Compile-time check: ProviderConfig is a sealed interface. Any
// struct intended as a provider config must implement it by having
// a providerConfig() method. This test does not exercise runtime
// behavior — the compiler enforces it.
type testConfig struct{}

func (testConfig) providerConfig() {}

var _ ProviderConfig = testConfig{}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/secrets/... -run TestSecretValue -v`
Expected: FAIL with compile errors mentioning `undefined: SecretValue`, `undefined: ProviderConfig`.

- [ ] **Step 3: Create `provider.go` with core types and interface**

Write to `internal/proxy/secrets/provider.go`:

```go
package secrets

import (
	"context"
	"time"
)

// SecretProvider is implemented by every secret backend.
//
// The daemon constructs one provider per backend at session start,
// calls Fetch zero or more times, and calls Close exactly once at
// session end. Implementations MUST be safe for concurrent use by
// multiple goroutines.
type SecretProvider interface {
	// Name returns the provider's stable identifier used in audit
	// events and error messages (e.g. "keyring", "vault").
	Name() string

	// Fetch retrieves a single secret identified by ref.
	//
	// The returned SecretValue's Value buffer is owned by the
	// caller; the provider does not retain a reference. The
	// caller is responsible for calling SecretValue.Zero when
	// the value is no longer needed.
	//
	// Errors MUST be wrappable with errors.Is against the
	// sentinels in this package: ErrNotFound when the secret
	// does not exist, ErrUnauthorized when the backend rejects
	// the provider's credentials, ErrInvalidURI when the ref
	// is missing required semantic pieces for this backend,
	// ErrFieldNotSupported when the ref carries a Field the
	// backend cannot honor, or a wrapped transport error for
	// anything else.
	Fetch(ctx context.Context, ref SecretRef) (SecretValue, error)

	// Close releases any resources held by the provider. Safe to
	// call multiple times; subsequent calls are no-ops. After
	// Close returns, Fetch MUST return a non-nil error.
	Close() error
}

// SecretRef identifies one secret in one provider.
//
// Callers should construct SecretRef via ParseRef rather than
// building literals, except in tests. Going through ParseRef
// guarantees consistent validation.
type SecretRef struct {
	// Scheme is the URI scheme: "keyring", "vault", "aws-sm",
	// "gcp-sm", "azure-kv", or "op".
	Scheme string

	// Host is the URI host component. Interpreted per-provider:
	// for keyring it is the OS keyring service name; for vault
	// it is the mount point; etc.
	Host string

	// Path is the URI path with its leading slash trimmed.
	// Interpreted per-provider.
	Path string

	// Field is the optional URI fragment (everything after "#").
	// Empty if the URI had no fragment. Providers that cannot
	// honor a Field (e.g. keyring) return ErrFieldNotSupported
	// when it is non-empty.
	Field string

	// Metadata holds provider-specific hints. Reserved for v2;
	// v1 providers do not read it. Included now so adding it
	// later is not a public-API churn.
	Metadata map[string]string
}

// SecretValue is the result of a successful Fetch.
//
// The Value field holds the raw secret bytes. The caller owns
// this buffer and should call SecretValue.Zero when done.
type SecretValue struct {
	// Value is the secret material. Caller-owned.
	Value []byte

	// TTL is the remaining lifetime of the secret as reported by
	// the backend. Zero means no lease information is available
	// (not "expires immediately").
	TTL time.Duration

	// LeaseID is the backend-specific lease identifier. Empty if
	// the secret is not leased.
	LeaseID string

	// Version is the backend-specific version string. Empty if
	// the secret is not versioned.
	Version string

	// FetchedAt is the local wall-clock time the provider
	// retrieved the secret. Set by the provider.
	FetchedAt time.Time
}

// Zero overwrites the secret bytes with zeros and clears the
// lease and version fields. After Zero returns, the SecretValue
// holds no secret material. Idempotent; safe to call on a
// zero-value SecretValue.
func (sv *SecretValue) Zero() {
	for i := range sv.Value {
		sv.Value[i] = 0
	}
	sv.Value = nil
	sv.LeaseID = ""
	sv.Version = ""
}

// ProviderConfig is a sealed marker interface implemented by each
// provider's config struct (Config in the keyring package, and
// later VaultConfig, AWSSMConfig, etc.). The registry — to be
// added in a later plan — uses ProviderConfig to dispatch to the
// right constructor at policy-load time.
//
// The private method prevents external packages from implementing
// ProviderConfig by accident. Only types inside known provider
// packages can satisfy it.
type ProviderConfig interface {
	providerConfig()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/secrets/... -run TestSecretValue -v`
Expected: PASS. Three subtests: `TestSecretValue_Zero_OverwritesAndClears`, `TestSecretValue_Zero_Idempotent`, `TestSecretValue_Zero_OnZeroValue`.

- [ ] **Step 5: Verify full package builds and vets clean**

Run: `go build ./internal/proxy/secrets/... && go vet ./internal/proxy/secrets/...`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/secrets/provider.go internal/proxy/secrets/provider_test.go
git commit -m "feat(secrets): add SecretProvider interface, SecretRef, SecretValue types"
```

---

## Task 3: URI parser — all six schemes, error cases, and `String()` round-trip

**Files:**
- Create: `internal/proxy/secrets/uri.go`
- Create: `internal/proxy/secrets/uri_test.go`

- [ ] **Step 1: Write the full failing test suite for `ParseRef`**

Write to `internal/proxy/secrets/uri_test.go`:

```go
package secrets

import (
	"errors"
	"testing"
)

func TestParseRef_HappyPath_AllSchemes(t *testing.T) {
	cases := []struct {
		name   string
		uri    string
		want   SecretRef
	}{
		{
			name: "keyring",
			uri:  "keyring://agentsh/vault_token",
			want: SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault_token"},
		},
		{
			name: "vault with field",
			uri:  "vault://kv/data/github#token",
			want: SecretRef{Scheme: "vault", Host: "kv", Path: "data/github", Field: "token"},
		},
		{
			name: "aws-sm",
			uri:  "aws-sm://prod/api-keys/anthropic",
			want: SecretRef{Scheme: "aws-sm", Host: "prod", Path: "api-keys/anthropic"},
		},
		{
			name: "gcp-sm",
			uri:  "gcp-sm://projects/123/secrets/x/versions/latest",
			want: SecretRef{Scheme: "gcp-sm", Host: "projects", Path: "123/secrets/x/versions/latest"},
		},
		{
			name: "azure-kv",
			uri:  "azure-kv://corp-vault/anthropic-key",
			want: SecretRef{Scheme: "azure-kv", Host: "corp-vault", Path: "anthropic-key"},
		},
		{
			name: "op",
			uri:  "op://Personal/Stripe/credential",
			want: SecretRef{Scheme: "op", Host: "Personal", Path: "Stripe/credential"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRef(tc.uri)
			if err != nil {
				t.Fatalf("ParseRef(%q) returned error: %v", tc.uri, err)
			}
			if got.Scheme != tc.want.Scheme || got.Host != tc.want.Host ||
				got.Path != tc.want.Path || got.Field != tc.want.Field {
				t.Errorf("ParseRef(%q)\n got: %+v\nwant: %+v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestParseRef_EmptyString(t *testing.T) {
	_, err := ParseRef("")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef(\"\") = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_NoScheme(t *testing.T) {
	_, err := ParseRef("noscheme")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef(\"noscheme\") = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_UnsupportedScheme(t *testing.T) {
	cases := []string{
		"http://example.com/path",
		"file:///etc/passwd",
		"vault2://kv/x",
		"ftp://server/path",
	}
	for _, uri := range cases {
		t.Run(uri, func(t *testing.T) {
			_, err := ParseRef(uri)
			if !errors.Is(err, ErrUnsupportedScheme) {
				t.Errorf("ParseRef(%q) = %v, want wrapping ErrUnsupportedScheme", uri, err)
			}
		})
	}
}

func TestParseRef_NoHost(t *testing.T) {
	_, err := ParseRef("vault:///path")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef(\"vault:///path\") = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_QueryStringRejected(t *testing.T) {
	_, err := ParseRef("keyring://agentsh/token?version=2")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef with query = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_UserInfoRejected(t *testing.T) {
	_, err := ParseRef("keyring://user:pass@host/path")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef with userinfo = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_WithFragment(t *testing.T) {
	ref, err := ParseRef("vault://kv/data/github#token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Field != "token" {
		t.Errorf("Field = %q, want %q", ref.Field, "token")
	}
}

func TestParseRef_PathWithMultipleSlashes(t *testing.T) {
	ref, err := ParseRef("vault://kv/data/path/to/secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Path != "data/path/to/secret" {
		t.Errorf("Path = %q, want %q", ref.Path, "data/path/to/secret")
	}
}

func TestParseRef_PathWithEncodedChars(t *testing.T) {
	ref, err := ParseRef("vault://kv/data/team%20a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Path != "data/team a" {
		t.Errorf("Path = %q, want %q (net/url should have decoded %%20 to space)", ref.Path, "data/team a")
	}
}

func TestSecretRef_String_RoundTrip(t *testing.T) {
	cases := []string{
		"keyring://agentsh/vault_token",
		"vault://kv/data/github#token",
		"aws-sm://prod/api-keys/anthropic",
		"op://Personal/Stripe/credential",
	}
	for _, uri := range cases {
		t.Run(uri, func(t *testing.T) {
			ref, err := ParseRef(uri)
			if err != nil {
				t.Fatalf("ParseRef(%q) error: %v", uri, err)
			}
			got := ref.String()
			if got != uri {
				t.Errorf("String() = %q, want %q", got, uri)
			}
			// Parse the re-rendered URI and verify field-by-field
			// equality. SecretRef has a Metadata map[string]string
			// field which makes the struct not comparable with ==
			// (Go rejects struct equality when any field is a map);
			// compare fields individually instead.
			ref2, err := ParseRef(got)
			if err != nil {
				t.Fatalf("re-parse error: %v", err)
			}
			if ref2.Scheme != ref.Scheme || ref2.Host != ref.Host ||
				ref2.Path != ref.Path || ref2.Field != ref.Field {
				t.Errorf("round-trip changed the ref: %+v -> %+v", ref, ref2)
			}
		})
	}
}

func TestSecretRef_String_NoPath(t *testing.T) {
	ref := SecretRef{Scheme: "keyring", Host: "agentsh"}
	if got := ref.String(); got != "keyring://agentsh" {
		t.Errorf("String() = %q, want %q", got, "keyring://agentsh")
	}
}

func TestSecretRef_String_WithField(t *testing.T) {
	ref := SecretRef{Scheme: "vault", Host: "kv", Path: "data/x", Field: "token"}
	if got := ref.String(); got != "vault://kv/data/x#token" {
		t.Errorf("String() = %q, want %q", got, "vault://kv/data/x#token")
	}
}
```

**Note on `ref2`:** `SecretRef` has a `Metadata map[string]string` field which makes the struct NOT comparable with `==` at compile time (not a runtime panic — a build failure). The test above uses field-by-field comparison. Do not "simplify" it to `if ref2 != ref` — it will not compile.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/secrets/... -run TestParseRef -v`
Expected: FAIL with compile errors mentioning `undefined: ParseRef`.

- [ ] **Step 3: Create `uri.go` with `ParseRef` and `String`**

Write to `internal/proxy/secrets/uri.go`:

```go
package secrets

import (
	"fmt"
	"net/url"
	"strings"
)

// supportedSchemes is the closed set of v1 URI schemes. Anything
// outside this set is rejected with ErrUnsupportedScheme.
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
//	scheme://host[/path][#field]
//
// and returns a SecretRef. The fragment, if present, becomes
// SecretRef.Field. The path's leading slash is stripped.
//
// ParseRef does not validate per-provider semantics — it only
// validates the URI grammar and that the scheme is one of the six
// known schemes. Each provider validates its own SecretRef inside
// its Fetch implementation.
//
// Errors are always wrappable with errors.Is against ErrInvalidURI
// or ErrUnsupportedScheme.
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
// ParseRef(r.String()) round-trips for any SecretRef that ParseRef
// accepts.
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

- [ ] **Step 4: Run tests to verify they all pass**

Run: `go test ./internal/proxy/secrets/... -run TestParseRef -v`
Expected: PASS. All `TestParseRef_*` subtests pass.

Run: `go test ./internal/proxy/secrets/... -run TestSecretRef_String -v`
Expected: PASS. All `TestSecretRef_String*` subtests pass.

- [ ] **Step 5: Run the full secrets package test suite with race detector**

Run: `go test ./internal/proxy/secrets/... -race -count=1`
Expected: PASS. No data races (this package has no concurrency yet but `-race` is cheap insurance).

- [ ] **Step 6: Verify `go vet` still clean**

Run: `go vet ./internal/proxy/secrets/...`
Expected: no output, exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/secrets/uri.go internal/proxy/secrets/uri_test.go
git commit -m "feat(secrets): add URI parser for v1 secret schemes"
```

---

## Task 4: Add `zalando/go-keyring` dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Add the dependency via `go get`**

Run: `go get github.com/zalando/go-keyring@latest`
Expected: output like `go: added github.com/zalando/go-keyring vX.Y.Z`. May also add transitive deps (on Linux: `github.com/godbus/dbus/v5`).

- [ ] **Step 2: Run `go mod tidy`**

Run: `go mod tidy`
Expected: no output, exit 0. Normalizes `go.sum`.

- [ ] **Step 3: Inspect the `go.mod` diff**

Run: `git diff go.mod`
Expected: exactly one new line in the `require` block (or a new `require` block if one wasn't there):
```
github.com/zalando/go-keyring vX.Y.Z
```
If you see anything else — unrelated version bumps, new unrelated dependencies — STOP and report before continuing. Do NOT carry unrelated changes in this commit.

- [ ] **Step 4: Inspect the `go.sum` diff for transitive dependencies**

Run: `git diff go.sum | grep -E '^\+[^+]' | grep -oE '[^ ]+ v[0-9]' | sort -u`
Expected: lines mentioning `github.com/zalando/go-keyring` and possibly `github.com/godbus/dbus/v5` (Linux D-Bus client), `github.com/alessio/shellescape` (used by zalando internally), and existing `golang.org/x/sys`. Any other new module is a surprise. Record the list; you will reference it in the commit message.

- [ ] **Step 5: Verify the project still builds on the host OS**

Run: `go build ./...`
Expected: no output, exit 0.

- [ ] **Step 6: Verify the project cross-compiles for Windows**

Run: `GOOS=windows go build ./...`
Expected: no output, exit 0. If this fails, the zalando library may need a Windows-specific build tag that is not present — investigate before continuing.

- [ ] **Step 7: Verify the project cross-compiles for Darwin**

Run: `GOOS=darwin go build ./...`
Expected: no output, exit 0.

- [ ] **Step 8: Commit**

List the actual version and any unexpected transitive deps in the commit body. Example (substitute the real version you got from step 1):

```bash
git add go.mod go.sum
git commit -m "$(cat <<'EOF'
build: add github.com/zalando/go-keyring dependency

Direct dep for the keyring SecretProvider implementation in Plan 3.
Apache 2.0 license. Wraps macOS Keychain (cgo), Linux Secret Service
via D-Bus, and Windows Credential Manager.

New transitive deps (inspect go.sum):
  - github.com/godbus/dbus/v5  (Linux Secret Service client)
  - github.com/alessio/shellescape  (used internally by zalando)
EOF
)"
```

---

## Task 5: Keyring package skeleton — doc, Config, and `New` with availability probe

**Files:**
- Create: `internal/proxy/secrets/keyring/doc.go`
- Create: `internal/proxy/secrets/keyring/config.go`
- Create: `internal/proxy/secrets/keyring/provider.go`
- Create: `internal/proxy/secrets/keyring/provider_test.go`

- [ ] **Step 1: Create the package doc**

Write to `internal/proxy/secrets/keyring/doc.go`:

```go
// Package keyring implements secrets.SecretProvider using the OS
// keyring: macOS Keychain, Linux Secret Service (via libsecret and
// D-Bus), or Windows Credential Manager. It wraps
// github.com/zalando/go-keyring.
//
// Keyring URIs take the form
//
//	keyring://<service>/<user>
//
// where <service> is the OS keyring service name and <user> is the
// OS keyring account name. Keyring entries are scalar, so a
// SecretRef with a non-empty Field is rejected with
// secrets.ErrFieldNotSupported.
//
// The provider performs an availability probe at construction. If
// the OS keyring backend is unreachable (headless Linux without a
// running Secret Service, Windows Credential Manager subsystem
// down, macOS Keychain inaccessible), New returns
// secrets.ErrKeyringUnavailable. Operators must either set up the
// keyring or use a different provider — there is no "optional
// keyring" mode.
package keyring
```

- [ ] **Step 2: Create `config.go` with `Config` and the compile-time assertion**

Write to `internal/proxy/secrets/keyring/config.go`:

```go
package keyring

import secrets "github.com/agentsh/agentsh/internal/proxy/secrets"

// Config configures the keyring provider.
//
// Currently empty: every keyring entry is identified entirely by
// its SecretRef (host = service, path = user). A later plan may
// add fields like a default service prefix or a per-OS backend
// selector.
type Config struct{}

// providerConfig implements the sealed secrets.ProviderConfig
// marker interface.
func (Config) providerConfig() {}

// Compile-time assertions. These fail to build if Provider or
// Config ever drift away from the interfaces they're expected to
// satisfy.
var (
	_ secrets.ProviderConfig = Config{}
	_ secrets.SecretProvider = (*Provider)(nil)
)
```

- [ ] **Step 3: Write the failing test for `New`**

Write to `internal/proxy/secrets/keyring/provider_test.go`:

```go
package keyring

import (
	"errors"
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// skipIfUnavailable constructs a Provider and skips the test if
// the OS keyring backend is unreachable on this host. Used by
// every test that touches the real keyring.
func skipIfUnavailable(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Config{})
	if err != nil {
		if errors.Is(err, secrets.ErrKeyringUnavailable) {
			t.Skip("OS keyring not available on this host: " + err.Error())
		}
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestNew_HappyPath(t *testing.T) {
	p := skipIfUnavailable(t)
	if p == nil {
		t.Fatal("New returned nil Provider")
	}
}

func TestName_ReturnsKeyring(t *testing.T) {
	// Name is pure and does not touch the OS keyring. Construct
	// a zero-value Provider directly so this test is NOT skipped
	// on headless hosts.
	p := &Provider{}
	if got := p.Name(); got != "keyring" {
		t.Errorf("Name() = %q, want %q", got, "keyring")
	}
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `go test ./internal/proxy/secrets/keyring/... -run "TestNew_HappyPath|TestName_ReturnsKeyring" -v`
Expected: FAIL with compile errors mentioning `undefined: New`, `undefined: Provider`, `undefined: (*Provider).Close`, `undefined: (*Provider).Name`.

- [ ] **Step 5: Create the minimal `provider.go` with `Provider`, `New`, `Name`, `Close`, and a `Fetch` stub**

Write to `internal/proxy/secrets/keyring/provider.go`:

```go
package keyring

import (
	"context"
	"errors"
	"fmt"
	"sync"

	keyringlib "github.com/zalando/go-keyring"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Provider is an OS-keyring-backed secrets.SecretProvider.
//
// On macOS this uses the system Keychain (via cgo against the
// Security framework). On Linux it uses the Secret Service D-Bus
// API. On Windows it uses Credential Manager.
//
// Provider is safe for concurrent Fetch and Close.
type Provider struct {
	mu     sync.Mutex
	closed bool
}

// probeService is the keyring service name used by New's
// availability probe. Operators will never see this in a real
// keyring — it exists only to verify that keyring.Get can reach
// the backend at all.
const (
	probeService = "agentsh-probe"
	probeAccount = "agentsh-keyring-availability-probe"
)

// New constructs a keyring Provider.
//
// New verifies the OS keyring backend is reachable by issuing one
// probe Get. A probe that returns nil or keyringlib.ErrNotFound
// counts as success (the backend is reachable, the probe key just
// doesn't exist). Any other error means the backend itself is
// unreachable, and New returns a wrapped secrets.ErrKeyringUnavailable.
func New(_ Config) (*Provider, error) {
	_, err := keyringlib.Get(probeService, probeAccount)
	if err != nil && !errors.Is(err, keyringlib.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", secrets.ErrKeyringUnavailable, err)
	}
	return &Provider{}, nil
}

// Name returns "keyring". Used in audit events.
func (p *Provider) Name() string { return "keyring" }

// Close marks the provider closed. Subsequent Fetch calls return a
// non-nil error. Idempotent. The OS keyring has no per-connection
// state to release.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// Fetch is the stub implementation — Task 6 replaces the body with
// the real validation and round-trip logic. The signature matches
// secrets.SecretProvider so the compile-time assertion in
// config.go (var _ secrets.SecretProvider = (*Provider)(nil))
// passes from this task onward.
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	return secrets.SecretValue{}, errors.New("keyring: Fetch not yet implemented")
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/proxy/secrets/keyring/... -run "TestNew_HappyPath|TestName_ReturnsKeyring" -v`
Expected: `TestName_ReturnsKeyring` PASS. `TestNew_HappyPath` PASS on a host with OS keyring, SKIP on a headless host.

- [ ] **Step 7: Verify builds and vets clean on all platforms**

Run: `go build ./internal/proxy/secrets/keyring/... && go vet ./internal/proxy/secrets/keyring/...`
Expected: no output, exit 0.

Run: `GOOS=windows go build ./internal/proxy/secrets/keyring/...`
Expected: no output, exit 0.

Run: `GOOS=darwin go build ./internal/proxy/secrets/keyring/...`
Expected: no output, exit 0.

- [ ] **Step 8: Commit**

```bash
git add internal/proxy/secrets/keyring/doc.go internal/proxy/secrets/keyring/config.go internal/proxy/secrets/keyring/provider.go internal/proxy/secrets/keyring/provider_test.go
git commit -m "feat(secrets/keyring): add provider skeleton with availability probe"
```

---

## Task 6: Keyring `Fetch` — URI validation and round-trip

**Files:**
- Modify: `internal/proxy/secrets/keyring/provider.go`
- Modify: `internal/proxy/secrets/keyring/provider_test.go`

- [ ] **Step 1: Add failing tests for Fetch URI validation**

Append to `internal/proxy/secrets/keyring/provider_test.go`:

```go
import (
	"context"
	"fmt"
	"time"
)

// The imports above are additions — merge them into the existing
// import block at the top of the file rather than adding a second
// block.

func TestFetch_WrongScheme(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch with wrong scheme returned nil error")
	}
}

func TestFetch_MissingHost(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "keyring", Host: "", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch with empty host = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_MissingPath(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: ""}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch with empty path = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_WithField(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "x", Field: "token"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrFieldNotSupported) {
		t.Errorf("Fetch with field = %v, want wrapping ErrFieldNotSupported", err)
	}
}

func TestFetch_ContextCanceled(t *testing.T) {
	p := &Provider{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling Fetch
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "x"}
	_, err := p.Fetch(ctx, ref)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Fetch with canceled ctx = %v, want context.Canceled", err)
	}
}

// testServiceName returns a unique keyring service name per test
// run. Using a unique name per run prevents any one test from
// polluting a developer's real keyring or leaking entries between
// runs. The "agentsh-test" prefix makes the intent obvious if an
// entry does survive a crash.
func testServiceName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("agentsh-test-%s-%d", t.Name(), time.Now().UnixNano())
}

func TestFetch_RoundTrip(t *testing.T) {
	p := skipIfUnavailable(t)

	service := testServiceName(t)
	const account = "round-trip-user"
	const want = "super-secret-value"

	// Set the secret directly via the underlying library, outside
	// the Provider, so Fetch is exercised against a known-present
	// entry. Clean up in t.Cleanup so the developer's real
	// keyring is never left polluted even on test failure.
	if err := keyringlib.Set(service, account, want); err != nil {
		t.Fatalf("keyringlib.Set: %v", err)
	}
	t.Cleanup(func() { _ = keyringlib.Delete(service, account) })

	ref := secrets.SecretRef{Scheme: "keyring", Host: service, Path: account}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch(%+v) error: %v", ref, err)
	}
	if string(sv.Value) != want {
		t.Errorf("Fetch returned Value %q, want %q", sv.Value, want)
	}
	if sv.FetchedAt.IsZero() {
		t.Error("FetchedAt not set by Fetch")
	}
	// Caller owns the buffer — test ownership by mutating and
	// re-fetching. The second Fetch must return the original
	// bytes, not the mutation.
	sv.Value[0] = 'X'
	sv2, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("second Fetch error: %v", err)
	}
	if string(sv2.Value) != want {
		t.Errorf("mutating returned buffer affected provider state: got %q, want %q", sv2.Value, want)
	}
}

func TestFetch_NotFound(t *testing.T) {
	p := skipIfUnavailable(t)

	ref := secrets.SecretRef{
		Scheme: "keyring",
		Host:   testServiceName(t),
		Path:   "definitely-does-not-exist",
	}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch of missing key = %v, want wrapping ErrNotFound", err)
	}
}
```

**Note on `keyringlib` in the test file:** The round-trip test calls `keyringlib.Set` and `keyringlib.Delete` directly to seed and clean up keyring entries outside the Provider. The alias `keyringlib "github.com/zalando/go-keyring"` is already imported by `provider.go`; add it to the top of `provider_test.go` as well:

```go
keyringlib "github.com/zalando/go-keyring"
```

Merge it into the existing import block rather than starting a new one.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/secrets/keyring/... -run TestFetch -v`
Expected:
- `TestFetch_WrongScheme`, `TestFetch_MissingHost`, `TestFetch_MissingPath`, `TestFetch_WithField`, `TestFetch_ContextCanceled` all FAIL because the stub Fetch just returns "Fetch not yet implemented" — the error messages won't match the `errors.Is` checks.
- `TestFetch_RoundTrip`, `TestFetch_NotFound` FAIL for the same reason on hosts with a keyring, or SKIP on headless hosts.

- [ ] **Step 3: Replace the stub `Fetch` with the real implementation**

Open `internal/proxy/secrets/keyring/provider.go`. Replace the existing `Fetch` method (the Task 5 stub) with the full implementation. Also add `"time"` to the imports.

Final full file:

```go
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

// Provider is an OS-keyring-backed secrets.SecretProvider.
//
// On macOS this uses the system Keychain (via cgo against the
// Security framework). On Linux it uses the Secret Service D-Bus
// API. On Windows it uses Credential Manager.
//
// Provider is safe for concurrent Fetch and Close.
type Provider struct {
	mu     sync.Mutex
	closed bool
}

const (
	probeService = "agentsh-probe"
	probeAccount = "agentsh-keyring-availability-probe"
)

// New constructs a keyring Provider and verifies the OS keyring
// backend is reachable. See package doc for the failure modes.
func New(_ Config) (*Provider, error) {
	_, err := keyringlib.Get(probeService, probeAccount)
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
//   - Host    (the OS keyring service name)
//   - Path    (the OS keyring account name)
//   - Field   empty (keyring entries are scalar)
//
// Any other combination returns a wrapped ErrInvalidURI or
// ErrFieldNotSupported. A missing entry returns ErrNotFound.
// Anything else from the library is treated as a transport
// failure and wrapped verbatim.
//
// Fetch honors ctx only as a pre-call check. The zalando library
// does not accept a context, and spawning a goroutine to race the
// call against ctx would leak on cancel.
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return secrets.SecretValue{}, errors.New("keyring: provider closed")
	}

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

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	val, err := keyringlib.Get(ref.Host, ref.Path)
	if err != nil {
		if errors.Is(err, keyringlib.ErrNotFound) {
			return secrets.SecretValue{}, fmt.Errorf("%w: %s", secrets.ErrNotFound, ref.String())
		}
		// We cannot distinguish "auth rejected" from "backend
		// disappeared mid-session" from the zalando API, so we
		// do not synthesize ErrUnauthorized here. Wrap the raw
		// error so callers can see the original cause.
		return secrets.SecretValue{}, fmt.Errorf("keyring fetch %s: %w", ref.String(), err)
	}

	return secrets.SecretValue{
		Value:     []byte(val),
		FetchedAt: time.Now(),
	}, nil
}

// Close marks the provider closed. Subsequent Fetch calls return
// an error. Idempotent.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/secrets/keyring/... -run TestFetch -v`
Expected:
- Pure-Go URI-validation tests (`TestFetch_WrongScheme`, `TestFetch_MissingHost`, `TestFetch_MissingPath`, `TestFetch_WithField`, `TestFetch_ContextCanceled`): PASS on all hosts.
- Keyring-dependent tests (`TestFetch_RoundTrip`, `TestFetch_NotFound`): PASS on hosts with a keyring, SKIP otherwise.

- [ ] **Step 5: Run the full keyring test suite with the race detector**

Run: `go test ./internal/proxy/secrets/keyring/... -race -count=1`
Expected: PASS. No data races.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./internal/proxy/secrets/keyring/... && GOOS=darwin go build ./internal/proxy/secrets/keyring/...`
Expected: no output, exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/secrets/keyring/provider.go internal/proxy/secrets/keyring/provider_test.go
git commit -m "feat(secrets/keyring): implement Fetch with URI validation and round-trip"
```

---

## Task 7: Keyring `Close` semantics and concurrent-access race test

**Files:**
- Modify: `internal/proxy/secrets/keyring/provider_test.go`

- [ ] **Step 1: Write failing tests for Close idempotency, after-close Fetch, and concurrent access**

Append to `internal/proxy/secrets/keyring/provider_test.go`:

```go
import "sync"

// (merge "sync" into the existing import block at the top of the file)

func TestClose_Idempotent(t *testing.T) {
	p := &Provider{}
	if err := p.Close(); err != nil {
		t.Errorf("first Close error: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close error: %v", err)
	}
}

func TestFetch_AfterClose(t *testing.T) {
	p := &Provider{}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
}

func TestProvider_ConcurrentFetch_NoRaces(t *testing.T) {
	// This test skips on headless hosts. Without a reachable OS
	// keyring, each Fetch would block on the D-Bus timeout and
	// 800 sequential timeouts would take many minutes. On a host
	// with a keyring, each Get returns in milliseconds.
	p := skipIfUnavailable(t)
	// Use an intentionally absent key so Fetch always exercises
	// the "ErrNotFound" path. We care about the race detector,
	// not about the result.
	ref := secrets.SecretRef{
		Scheme: "keyring",
		Host:   testServiceName(t),
		Path:   "nonexistent-user",
	}

	var wg sync.WaitGroup
	const goroutines = 8
	const iterations = 100
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = p.Fetch(context.Background(), ref)
			}
		}()
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run tests to verify they pass**

`TestClose_Idempotent` and `TestFetch_AfterClose` do not touch the OS keyring — they exercise only the `closed` flag and should pass on every host. `TestProvider_ConcurrentFetch_NoRaces` calls `skipIfUnavailable` so it skips on headless hosts and only runs the race-detector sweep on hosts with a reachable keyring.

Run: `go test ./internal/proxy/secrets/keyring/... -run "TestClose_Idempotent|TestFetch_AfterClose|TestProvider_ConcurrentFetch_NoRaces" -race -v`
Expected: `TestClose_Idempotent` and `TestFetch_AfterClose` PASS unconditionally. `TestProvider_ConcurrentFetch_NoRaces` PASS on a host with a keyring, SKIP on headless. No data races.

- [ ] **Step 3: Run full keyring tests with race detector**

Run: `go test ./internal/proxy/secrets/keyring/... -race -count=1`
Expected: PASS. All tests either pass or skip.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/secrets/keyring/provider_test.go
git commit -m "test(secrets/keyring): add Close idempotency and concurrent-fetch race test"
```

---

## Task 8: MemoryProvider — secretstest package with Fetch, Add, Remove, Close

**Files:**
- Create: `internal/proxy/secrets/secretstest/doc.go`
- Create: `internal/proxy/secrets/secretstest/memory.go`
- Create: `internal/proxy/secrets/secretstest/memory_test.go`

- [ ] **Step 1: Create the package doc**

Write to `internal/proxy/secrets/secretstest/doc.go`:

```go
// Package secretstest provides test doubles for the
// secrets.SecretProvider interface.
//
// MemoryProvider is an in-memory fake that serves a fixed (but
// mutable) map of secrets keyed by the canonical URI form of the
// SecretRef. Tests construct one with a seed map, optionally add
// or remove entries during the test, and pass it where a real
// provider would go.
//
// ProviderContract runs the same baseline behavioral assertions
// against any SecretProvider. Provider implementations call it
// from their own test files to verify they honor the interface
// contract.
//
// # Production code MUST NOT import this package.
//
// The package name mirrors stdlib conventions like httptest and
// iotest. It ships under internal/proxy/secrets/ so the keyring
// package (and future provider packages) can import it from their
// _test.go files without going through the module boundary.
package secretstest
```

- [ ] **Step 2: Write the failing MemoryProvider test**

Write to `internal/proxy/secrets/secretstest/memory_test.go`:

```go
package secretstest

import (
	"context"
	"errors"
	"sync"
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

func TestNewMemoryProvider_CopiesSeed(t *testing.T) {
	seed := map[string][]byte{
		"keyring://agentsh/token": []byte("original"),
	}
	mp := NewMemoryProvider("test", seed)

	// Mutate the caller's seed map after construction.
	seed["keyring://agentsh/token"] = []byte("mutated")

	sv, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "agentsh", Path: "token",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "original" {
		t.Errorf("Fetch returned %q, want %q (seed was copied at construction)", sv.Value, "original")
	}
}

func TestFetch_HappyPath(t *testing.T) {
	mp := NewMemoryProvider("test", map[string][]byte{
		"keyring://agentsh/token": []byte("foo"),
	})
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "token"}
	sv, err := mp.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "foo" {
		t.Errorf("Value = %q, want %q", sv.Value, "foo")
	}
	if sv.FetchedAt.IsZero() {
		t.Error("FetchedAt not set")
	}
}

func TestFetch_NotFound(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "missing"}
	_, err := mp.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch of missing = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_ReturnsCopy(t *testing.T) {
	mp := NewMemoryProvider("test", map[string][]byte{
		"keyring://agentsh/token": []byte("immutable"),
	})
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "token"}

	sv1, err := mp.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	// Mutate the returned value.
	sv1.Value[0] = 'X'

	sv2, err := mp.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if string(sv2.Value) != "immutable" {
		t.Errorf("second Fetch = %q, want %q (first Fetch's mutation should not persist)", sv2.Value, "immutable")
	}
}

func TestFetch_AfterClose(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	if err := mp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "a", Path: "b",
	})
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
}

func TestAdd_ThenFetch(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	if err := mp.Add("keyring://agentsh/added", []byte("value")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	sv, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "agentsh", Path: "added",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "value" {
		t.Errorf("Value = %q, want %q", sv.Value, "value")
	}
}

func TestAdd_InvalidURI(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	err := mp.Add("not a valid uri", []byte("x"))
	if !errors.Is(err, secrets.ErrInvalidURI) && !errors.Is(err, secrets.ErrUnsupportedScheme) {
		t.Errorf("Add invalid URI = %v, want wrapping ErrInvalidURI or ErrUnsupportedScheme", err)
	}
}

func TestAdd_Replace(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	const uri = "keyring://agentsh/replaceable"
	if err := mp.Add(uri, []byte("first")); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := mp.Add(uri, []byte("second")); err != nil {
		t.Fatalf("second Add: %v", err)
	}
	sv, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "agentsh", Path: "replaceable",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "second" {
		t.Errorf("Value = %q, want %q", sv.Value, "second")
	}
}

func TestRemove(t *testing.T) {
	mp := NewMemoryProvider("test", map[string][]byte{
		"keyring://agentsh/removeme": []byte("present"),
	})
	mp.Remove("keyring://agentsh/removeme")
	_, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "agentsh", Path: "removeme",
	})
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch after Remove = %v, want wrapping ErrNotFound", err)
	}
}

func TestName(t *testing.T) {
	mp := NewMemoryProvider("my-fake", nil)
	if got := mp.Name(); got != "my-fake" {
		t.Errorf("Name() = %q, want %q", got, "my-fake")
	}
}

func TestClose_Idempotent(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	if err := mp.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := mp.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestConcurrentAccess_NoRaces(t *testing.T) {
	mp := NewMemoryProvider("test", map[string][]byte{
		"keyring://agentsh/seed": []byte("initial"),
	})

	var wg sync.WaitGroup
	const readers = 8
	const iterations = 200

	// Writer: continuously adds and removes its own URI.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = mp.Add("keyring://agentsh/writer", []byte("w"))
			mp.Remove("keyring://agentsh/writer")
		}
	}()

	// Readers: fetch the seeded URI.
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "seed"}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = mp.Fetch(context.Background(), ref)
			}
		}()
	}
	wg.Wait()
}

// Compile-time check: MemoryProvider implements SecretProvider.
var _ secrets.SecretProvider = (*MemoryProvider)(nil)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/proxy/secrets/secretstest/... -v`
Expected: FAIL with compile errors mentioning `undefined: NewMemoryProvider`, `undefined: MemoryProvider`.

- [ ] **Step 4: Create `memory.go` with the implementation**

Write to `internal/proxy/secrets/secretstest/memory.go`:

```go
package secretstest

import (
	"context"
	"errors"
	"sync"
	"time"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// MemoryProvider is an in-memory secrets.SecretProvider for use in
// tests. It serves a fixed map of secrets keyed by the canonical
// URI form of the SecretRef (SecretRef.String()).
//
// MemoryProvider is safe for concurrent Fetch, Add, Remove, and
// Close.
type MemoryProvider struct {
	name string

	mu      sync.RWMutex
	entries map[string][]byte
	closed  bool
}

// NewMemoryProvider returns a MemoryProvider seeded with the given
// entries. Keys in seed must be valid URIs that ParseRef accepts;
// seed values are COPIED so later mutations to the caller's map do
// not affect the provider.
//
// name is returned by Name(). Pass any non-empty string ("test",
// "memory", "fake-vault", ...).
//
// NewMemoryProvider panics on malformed seed keys — tests should
// know their seed up front. Use Add for runtime additions that
// need error returns.
func NewMemoryProvider(name string, seed map[string][]byte) *MemoryProvider {
	mp := &MemoryProvider{
		name:    name,
		entries: make(map[string][]byte, len(seed)),
	}
	for uri, value := range seed {
		ref, err := secrets.ParseRef(uri)
		if err != nil {
			panic("secretstest: NewMemoryProvider: invalid seed URI " + uri + ": " + err.Error())
		}
		cp := make([]byte, len(value))
		copy(cp, value)
		mp.entries[ref.String()] = cp
	}
	return mp
}

// Name returns the provider name passed to NewMemoryProvider.
func (m *MemoryProvider) Name() string { return m.name }

// Fetch returns the secret seeded under ref.String(), or
// secrets.ErrNotFound. After Close, Fetch returns errClosed.
//
// The returned SecretValue's Value buffer is a fresh copy. Tests
// may mutate it without affecting the provider's internal state.
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

// Add inserts or replaces an entry. The URI must be valid per
// secrets.ParseRef. The value is COPIED.
func (m *MemoryProvider) Add(uri string, value []byte) error {
	ref, err := secrets.ParseRef(uri)
	if err != nil {
		return err
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[ref.String()] = cp
	return nil
}

// Remove deletes an entry. Silently no-ops if the URI is malformed
// or the entry does not exist — tests often Remove "just in case"
// and should not have to check the URI first.
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

var errClosed = errors.New("secretstest: memory provider closed")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/proxy/secrets/secretstest/... -race -v`
Expected: PASS. All tests including `TestConcurrentAccess_NoRaces`. No data races.

- [ ] **Step 6: Verify builds and vets clean**

Run: `go build ./internal/proxy/secrets/... && go vet ./internal/proxy/secrets/...`
Expected: no output, exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/secrets/secretstest/doc.go internal/proxy/secrets/secretstest/memory.go internal/proxy/secrets/secretstest/memory_test.go
git commit -m "feat(secrets/secretstest): add MemoryProvider test fake"
```

---

## Task 9: Shared `ProviderContract` helper applied to both providers

**Files:**
- Create: `internal/proxy/secrets/secretstest/contract.go`
- Create: `internal/proxy/secrets/secretstest/contract_test.go`
- Modify: `internal/proxy/secrets/keyring/provider_test.go`
- Modify: `internal/proxy/secrets/secretstest/memory_test.go`

- [ ] **Step 1: Write the failing contract test inside `secretstest` itself**

The cleanest way to TDD the contract helper is to write the test that EXERCISES the helper (a test that calls it against a known-good MemoryProvider) BEFORE writing the helper.

Write to `internal/proxy/secrets/secretstest/contract_test.go`:

```go
package secretstest

import "testing"

func TestProviderContract_AppliedToMemoryProvider(t *testing.T) {
	mp := NewMemoryProvider("contract-target", nil)
	ProviderContract(t, "memory", mp)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/secrets/secretstest/... -run TestProviderContract -v`
Expected: FAIL with a compile error mentioning `undefined: ProviderContract`.

- [ ] **Step 3: Create `contract.go` with the `ProviderContract` helper**

Write to `internal/proxy/secrets/secretstest/contract.go`:

```go
package secretstest

import (
	"context"
	"errors"
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// ProviderContract runs a baseline set of behavioral assertions
// against any SecretProvider. Every provider implementation should
// call ProviderContract from its own test file to verify it honors
// the interface contract.
//
// The helper takes a freshly constructed provider and takes
// ownership of it: it calls Close on the provider via t.Cleanup.
// Callers must not call Close themselves after passing the
// provider to ProviderContract.
//
// The URI used to exercise Fetch (a well-known "never-exists"
// keyring URI) is chosen to be valid per ParseRef but extremely
// unlikely to hit any real secret: `keyring://agentsh-contract-probe/unset`.
// A real keyring provider that happened to have this entry set
// would fail the NotFound assertion — which is acceptable because
// the service name is obviously test-only. The keyring provider's
// test suite avoids this by scoping tests to a per-run unique
// service name.
func ProviderContract(t *testing.T, name string, p secrets.SecretProvider) {
	t.Helper()

	t.Cleanup(func() { _ = p.Close() })

	t.Run(name+"/Name", func(t *testing.T) {
		if got := p.Name(); got == "" {
			t.Error("Name() returned empty string")
		}
	})

	t.Run(name+"/FetchNotFound", func(t *testing.T) {
		ref := secrets.SecretRef{
			Scheme: "keyring",
			Host:   "agentsh-contract-probe",
			Path:   "unset",
		}
		_, err := p.Fetch(context.Background(), ref)
		if err == nil {
			t.Fatal("Fetch of unset ref returned nil error")
		}
		if !errors.Is(err, secrets.ErrNotFound) {
			t.Errorf("Fetch of unset ref = %v, want wrapping secrets.ErrNotFound", err)
		}
	})

	t.Run(name+"/CloseIdempotent", func(t *testing.T) {
		if err := p.Close(); err != nil {
			t.Errorf("first Close: %v", err)
		}
		if err := p.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	})

	t.Run(name+"/FetchAfterClose", func(t *testing.T) {
		// Close was called above; provider should be in a closed
		// state here because t.Run subtests run sequentially.
		ref := secrets.SecretRef{
			Scheme: "keyring",
			Host:   "agentsh-contract-probe",
			Path:   "unset",
		}
		_, err := p.Fetch(context.Background(), ref)
		if err == nil {
			t.Fatal("Fetch after Close returned nil error")
		}
	})
}
```

- [ ] **Step 4: Run the contract test inside `secretstest` to verify it passes**

Run: `go test ./internal/proxy/secrets/secretstest/... -run TestProviderContract -v`
Expected: PASS. Four subtests under `TestProviderContract_AppliedToMemoryProvider`: `memory/Name`, `memory/FetchNotFound`, `memory/CloseIdempotent`, `memory/FetchAfterClose`.

- [ ] **Step 5: Apply the contract to the keyring provider**

Open `internal/proxy/secrets/keyring/provider_test.go`. Add this test (and add `"github.com/agentsh/agentsh/internal/proxy/secrets/secretstest"` to the import block):

```go
func TestProviderContract_AppliedToKeyringProvider(t *testing.T) {
	p := skipIfUnavailable(t)

	// skipIfUnavailable already registered a Cleanup to Close p.
	// ProviderContract also Closes p inside its own Cleanup.
	// Close is idempotent, so both cleanups run safely.
	secretstest.ProviderContract(t, "keyring", p)
}
```

Also import:

```go
"github.com/agentsh/agentsh/internal/proxy/secrets/secretstest"
```

- [ ] **Step 6: Run the keyring contract test**

Run: `go test ./internal/proxy/secrets/keyring/... -run TestProviderContract -v`
Expected: on a host with OS keyring: PASS, with four subtests `keyring/Name`, `keyring/FetchNotFound`, `keyring/CloseIdempotent`, `keyring/FetchAfterClose`. On a headless host: SKIP (via `skipIfUnavailable`).

- [ ] **Step 7: Run the full secrets test suite with race detector**

Run: `go test ./internal/proxy/secrets/... -race -count=1`
Expected: PASS (or skipped keyring round-trip tests on headless hosts). No data races.

- [ ] **Step 8: Commit**

```bash
git add internal/proxy/secrets/secretstest/contract.go internal/proxy/secrets/secretstest/contract_test.go internal/proxy/secrets/keyring/provider_test.go
git commit -m "feat(secrets/secretstest): add ProviderContract helper and apply to keyring"
```

---

## Task 10: Cross-compile, full-project verification, and policy checks

**Files:** none modified in this task — it is a verification gate.

- [ ] **Step 1: Verify the full project builds on the host OS**

Run: `go build ./...`
Expected: no output, exit 0.

- [ ] **Step 2: Verify cross-compile for Linux, macOS, and Windows**

Run: `GOOS=linux go build ./...`
Expected: no output, exit 0.

Run: `GOOS=darwin go build ./...`
Expected: no output, exit 0.

Run: `GOOS=windows go build ./...`
Expected: no output, exit 0. If this fails on a macOS host because cgo isn't available for a darwin→windows build, that's a host quirk unrelated to this plan — document it and skip. The CI matrix will catch real cross-compile regressions.

- [ ] **Step 3: Run `go vet` on the entire project**

Run: `go vet ./...`
Expected: no output, exit 0.

- [ ] **Step 4: Run the full project test suite with race detector**

Run: `go test ./... -race -count=1`
Expected: PASS. Pre-existing test failures in unrelated packages (e.g., environment-dependent tests in `internal/ptrace/`) are acceptable IF they also fail on `main` — verify that on `main` before declaring them pre-existing. Plan 3 must introduce zero new failures.

- [ ] **Step 5: Verify `pkg/secrets` is unchanged**

Run: `git diff main -- pkg/secrets/`
Expected: empty output. Plan 3 explicitly does not touch the dormant `pkg/secrets/` tree.

- [ ] **Step 6: Verify zero imports of the new package from outside `internal/proxy/secrets/`**

Run: `grep -r "agentsh/internal/proxy/secrets" --include="*.go" . | grep -v "^./internal/proxy/secrets/" | grep -v "^./.claude/" || echo "clean"`
Expected: output is exactly `clean`. If any file outside `internal/proxy/secrets/` imports from it, that is a scope violation — investigate and remove before merging.

- [ ] **Step 7: Verify zero imports of the `secretstest` package from non-test files**

Run: `grep -rn "agentsh/internal/proxy/secrets/secretstest" --include="*.go" . | grep -v "_test.go" | grep -v "^./.claude/" || echo "clean"`
Expected: output is exactly `clean`. If any `.go` file (not `_test.go`) imports `secretstest`, that is a production-code-imports-test-helpers violation — fix before merging.

- [ ] **Step 8: Inspect the full `go.sum` delta one more time**

Run: `git diff main -- go.mod go.sum | head -80`
Expected: only lines touching `github.com/zalando/go-keyring` and its transitive deps identified in Task 4. No unrelated version bumps.

- [ ] **Step 9: Run a final `go test` focused on the new packages**

Run: `go test ./internal/proxy/secrets/... -race -count=1 -v`
Expected: PASS (with skipped keyring tests on headless hosts).

- [ ] **Step 10: Run `roborev review --reasoning maximum` on the branch** (per standing rule)

This is done via the `superpowers:requesting-code-review` skill or the `roborev-review-branch` slash command. Address every finding of severity MEDIUM or higher before opening the PR. Skip LOW-severity findings per user preference.

- [ ] **Step 11: Commit a (probably empty) verification marker, only if verification surfaced a small fix**

Most of the time Task 10 finds nothing to change and there is nothing to commit here. If it does find a small fix (e.g., a missing `t.Helper()`, a typo in a comment), commit it with:

```bash
git add <files>
git commit -m "chore(secrets): address Plan 3 verification findings"
```

If there are no verification-driven changes, skip this step entirely.

---

## Post-plan checklist (read before opening the PR)

Run through this list after Task 10 completes:

- [ ] `internal/proxy/secrets/` exists with `doc.go`, `errors.go`, `provider.go`, `uri.go`, `errors_test.go`, `provider_test.go`, `uri_test.go`.
- [ ] `internal/proxy/secrets/keyring/` exists with `doc.go`, `config.go`, `provider.go`, `provider_test.go`.
- [ ] `internal/proxy/secrets/secretstest/` exists with `doc.go`, `memory.go`, `memory_test.go`, `contract.go`, `contract_test.go`.
- [ ] `SecretProvider` has `Name`, `Fetch`, `Close`.
- [ ] `SecretRef` has `Scheme`, `Host`, `Path`, `Field`, `Metadata`.
- [ ] `SecretValue` has `Value`, `TTL`, `LeaseID`, `Version`, `FetchedAt`, and a `Zero` method.
- [ ] Six sentinel errors defined: `ErrNotFound`, `ErrUnauthorized`, `ErrInvalidURI`, `ErrUnsupportedScheme`, `ErrFieldNotSupported`, `ErrKeyringUnavailable`.
- [ ] `ParseRef` accepts all six v1 schemes and rejects everything else (empty string, no scheme, unsupported scheme, no host, query string, userinfo).
- [ ] `keyring.New` fails loud with `ErrKeyringUnavailable` on headless Linux.
- [ ] Keyring `Fetch` validates scheme, host, path, field, and context before touching the backend.
- [ ] `MemoryProvider` round-trips in tests; returns copies; seed map is copied.
- [ ] `secretstest.ProviderContract` is applied to both `MemoryProvider` and `keyring.Provider`.
- [ ] `go.mod` adds `github.com/zalando/go-keyring`; transitive deps reviewed and noted in the commit message.
- [ ] `pkg/secrets` is unchanged.
- [ ] Zero call sites in `.go` files outside `internal/proxy/secrets/`.
- [ ] `secretstest` is not imported from any non-`_test.go` file.
- [ ] `go build ./...`, `GOOS=linux go build ./...`, `GOOS=darwin go build ./...`, `GOOS=windows go build ./...` all clean.
- [ ] `go test ./... -race` passes (modulo pre-existing failures unrelated to this plan).
- [ ] `roborev review --reasoning maximum` findings of MEDIUM+ severity addressed.

---

## Implementer footguns (read before starting)

1. **`go-keyring` does not accept a `context.Context`.** Do not wrap the library call in a goroutine and `select` on `ctx.Done()` — that creates an orphan goroutine on cancel. Check `ctx.Err()` once before the call and be done with it.

2. **macOS Keychain prompts on first write.** On a developer machine, running the round-trip tests for the first time may show "agentsh wants to access your Keychain — Always Allow / Allow Once / Deny." Click Always Allow for test runs. CI macOS runners have a pre-unlocked Keychain so this does not apply there. Tests use per-run unique service names so one prompt does not carry across runs.

3. **Linux Secret Service availability is brittle.** `dbus-launch` may or may not be running. The construction probe is the right gate. Do NOT try to start D-Bus yourself — that is the operator's job. The error message for `ErrKeyringUnavailable` should be actionable enough that an operator knows to run `dbus-daemon --session` or pick a different backend, but Plan 3's scope ends at returning the error.

4. **The test helper lives in `secretstest`, not in `secrets`.** Functions defined in `secrets/provider_test.go` (a `_test.go` file) are not visible from the `keyring` subpackage. The `ProviderContract` helper MUST live in `secretstest/contract.go` (non-`_test.go`) so it can be imported from `keyring/provider_test.go`. This plan does it right; do not "helpfully" move it later.

5. **The sealed `ProviderConfig` marker interface uses a lowercase method.** If you make `providerConfig()` uppercase to silence a linter, you have broken the seal — any package can now implement it. Keep it lowercase.

6. **The URI parser rejects query strings by design.** `keyring://agentsh/token?version=2` returns `ErrInvalidURI`. A future version may accept a query string for some providers — that change is non-breaking. Accepting them now and removing support later WOULD be breaking.

7. **Every test file in every provider subpackage must use `skipIfUnavailable`-style skips for anything that touches the real OS keyring.** A developer running `go test ./...` on a headless CI box should see skips, not failures. `TestName_ReturnsKeyring` is explicitly the pattern for tests that do NOT touch the OS — do NOT use `skipIfUnavailable` for it.

8. **`secrets.SecretRef` has a `Metadata map[string]string` field which makes the struct NOT comparable with `==`.** This is a compile-time error in Go, not a runtime panic: `if ref1 != ref2` fails to build the moment a struct field is a map. `ParseRef` does not populate `Metadata` in this plan (it is reserved for v2), but you still cannot write `ref1 == ref2` or use `SecretRef` as a map key. Tests in this plan compare field-by-field (`ref1.Scheme != ref2.Scheme || ...`). If you introduce a new test with an `==` comparison on `SecretRef`, the build will break — rewrite to field-by-field.
