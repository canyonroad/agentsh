# Vault Provider + Provider Registry (Plan 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the provider registry (dependency-resolving construction of providers) and a Vault KV v2 SecretProvider, with auth chaining from keyring, token/AppRole/Kubernetes auth, and zero call sites in the daemon.

**Architecture:** A `Registry` type in `internal/proxy/secrets/` uses Kahn's topological sort to construct providers in dependency order, enabling auth chaining (e.g., Vault reads its token from the keyring provider). The Vault provider in `internal/proxy/secrets/vault/` wraps `hashicorp/vault/api` for KV v2 reads. Both `ProviderConfig` interface methods (`TypeName()`, `Dependencies()`) are added to the parent package.

**Tech Stack:** Go stdlib + `github.com/hashicorp/vault/api` (already in go.mod) + `github.com/hashicorp/vault/api/auth/approle` (new) + `github.com/hashicorp/vault/api/auth/kubernetes` (already in go.mod). Tests use `net/http/httptest` for mock Vault HTTP handlers.

**Spec reference:** `docs/superpowers/specs/2026-04-09-plan-04-vault-provider-registry-design.md`

**Parent spec reference:** `docs/superpowers/specs/2026-04-07-external-secrets-design.md` (Sections 2, 5, 7).

---

## Architectural notes (read before starting tasks)

### Import paths

Module path: `github.com/agentsh/agentsh`. The secrets parent package is imported as:

```go
secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
```

Vault subpackage: `github.com/agentsh/agentsh/internal/proxy/secrets/vault`.

### ProviderConfig interface evolution

Plan 3 shipped `ProviderConfig` with one unexported method (`providerConfig()`) and a `ProviderConfigMarker` embed helper. Plan 4 adds two exported methods:

- `TypeName() string` — NO default on marker. Each config must implement it. Compile-time enforcement.
- `Dependencies() []SecretRef` — default on marker returning `nil`. Providers with no auth chaining get this for free.

### Registry scheme mapping

The registry maps URI schemes to providers via `TypeName()`. When a config's `Dependencies()` returns refs, the registry looks up which config has a matching `TypeName()` for each ref's `Scheme`. This is how `vault.Config` with `TokenRef: keyring://...` creates an edge to the keyring provider.

### Vault KV v2 URI semantics

The `vault/api` KV v2 helper adds the `data/` prefix internally. So:
- URI `vault://kv/github#token` → `client.KVv2("kv").Get(ctx, "github")` → field `token`
- Host = mount name, Path = secret path within mount, Field = key in KV data map
- If path starts with `data/`, the provider strips it and logs a warning.

### httptest mock pattern for Vault

Tests create an `httptest.Server` with a `http.ServeMux` that handles Vault API paths. The `vault/api.Client` is configured with `api.Config{Address: server.URL}`. No TLS in tests — httptest serves plain HTTP and the vault client is configured to skip TLS verification.

### Concurrency model

Same pattern as keyring provider: `atomic.Bool` closed flag + `sync.RWMutex`. Fetch holds RLock, Close stores closed flag then acquires exclusive Lock. Test seam hooks for deterministic race testing.

### Vault `New()` takes `context.Context`

Unlike keyring (whose `New` is synchronous and fast), Vault's `New` needs to authenticate over HTTP, which requires a context for timeout/cancellation. The `ConstructorFunc` signature does NOT carry a context — instead, `NewRegistry` passes its own `ctx` argument to the constructor via a closure.

Correction: the `ConstructorFunc` should carry a context. Revise:

```go
type ConstructorFunc func(ctx context.Context, cfg ProviderConfig, resolver RefResolver) (SecretProvider, error)
```

This way each constructor can honor the registry's context for timeouts.

---

## File Structure

**Files created by this plan:**

- `internal/proxy/secrets/registry.go` — `RefResolver`, `ConstructorFunc`, `Registry`, `NewRegistry` (topo sort), `Provider`, `Fetch`, `Close`.
- `internal/proxy/secrets/registry_test.go` — dependency resolution, cycle detection, cleanup, dispatch tests.
- `internal/proxy/secrets/vault/doc.go` — package doc (OpenBao note, URI format).
- `internal/proxy/secrets/vault/config.go` — `Config`, `AuthConfig`, `TypeName`, `Dependencies`, compile-time assertions.
- `internal/proxy/secrets/vault/provider.go` — `Provider`, `New`, `Fetch`, `Close`.
- `internal/proxy/secrets/vault/provider_test.go` — httptest mock + contract tests.

**Files modified by this plan:**

- `internal/proxy/secrets/provider.go` — add `TypeName() string` and `Dependencies() []SecretRef` to `ProviderConfig` interface. Add default `Dependencies()` to `ProviderConfigMarker`.
- `internal/proxy/secrets/provider_test.go` — update `testConfig` to implement `TypeName()`.
- `internal/proxy/secrets/errors.go` — add `ErrCyclicDependency` sentinel.
- `internal/proxy/secrets/errors_test.go` — add `ErrCyclicDependency` to sentinel tests.
- `internal/proxy/secrets/doc.go` — mention vault subpackage and registry.
- `internal/proxy/secrets/keyring/config.go` — add `TypeName()` method.
- `go.mod` — add `github.com/hashicorp/vault/api/auth/approle`.
- `go.sum` — regenerated by `go mod tidy`.

**Files NOT modified (explicitly verify unchanged before merge):**

- Anything under `pkg/secrets/`.
- Anything under `internal/session/`, `internal/api/`, `cmd/`.
- Anything under `internal/proxy/credsub/`.

---

## Task 1: Interface changes and error sentinel

**Files:**
- Modify: `internal/proxy/secrets/errors.go`
- Modify: `internal/proxy/secrets/errors_test.go`
- Modify: `internal/proxy/secrets/provider.go`
- Modify: `internal/proxy/secrets/provider_test.go`
- Modify: `internal/proxy/secrets/keyring/config.go`

- [ ] **Step 1: Add `ErrCyclicDependency` to errors.go**

Add after the existing `ErrKeyringUnavailable` line in `internal/proxy/secrets/errors.go`:

```go
// ErrCyclicDependency is returned by NewRegistry when the provider
// dependency graph contains a cycle (e.g. provider A depends on B,
// B depends on A). The error message includes the cycle path.
var ErrCyclicDependency = errors.New("secrets: cyclic provider dependency")
```

- [ ] **Step 2: Update errors_test.go to include `ErrCyclicDependency`**

In `internal/proxy/secrets/errors_test.go`, add `ErrCyclicDependency` to all three test functions:

In `TestSentinelErrors_AreDistinct`, add to the `sentinels` slice:
```go
ErrCyclicDependency,
```

In `TestSentinelErrors_AreWrappable`, add to the `sentinels` map:
```go
"ErrCyclicDependency": ErrCyclicDependency,
```

In `TestSentinelErrors_MessagesStartWithPrefix`, add to the `sentinels` slice:
```go
ErrCyclicDependency,
```

- [ ] **Step 3: Run error tests**

Run: `cd /home/eran/work/agentsh && go test ./internal/proxy/secrets/ -run TestSentinel -v`

Expected: PASS — all sentinel tests pass with the new error.

- [ ] **Step 4: Add `TypeName()` and `Dependencies()` to `ProviderConfig` interface**

In `internal/proxy/secrets/provider.go`, replace the `ProviderConfig` interface definition:

```go
// ProviderConfig is the marker interface that every provider's
// config struct must satisfy. The registry type-switches on
// ProviderConfig to dispatch to the right constructor at
// policy-load time.
//
// TypeName returns the provider type name, which doubles as the
// URI scheme this provider handles (e.g. "vault", "keyring").
// Each config MUST implement TypeName explicitly — there is no
// default on ProviderConfigMarker.
//
// Dependencies returns the SecretRefs that must be resolved from
// other providers before this provider can be constructed (auth
// chaining). Providers with no dependencies inherit the default
// nil return from ProviderConfigMarker.
//
// Types outside package secrets satisfy ProviderConfig by
// embedding ProviderConfigMarker. Embedding is required because
// Go's unexported-method sealing does not work across package
// boundaries: an unexported method's identity is qualified by
// the declaring package, so a type in another package cannot
// directly implement a sealed interface from this one. Embedding
// ProviderConfigMarker gives the outer type a promoted
// providerConfig() method whose identity lives in package
// secrets, which is what satisfies the interface.
//
// The seal is strong-by-convention: anyone can embed
// ProviderConfigMarker, but doing so is a deliberate opt-in, and
// the registry only dispatches on config types it already knows
// about.
type ProviderConfig interface {
	providerConfig()
	TypeName() string
	Dependencies() []SecretRef
}
```

Add the default `Dependencies()` to `ProviderConfigMarker` (after the existing `providerConfig()` method):

```go
// Dependencies returns nil. Providers with no auth chaining
// inherit this default. Providers that need auth chaining (e.g.
// Vault with a keyring-backed token) override this method on
// their own Config type.
func (ProviderConfigMarker) Dependencies() []SecretRef { return nil }
```

- [ ] **Step 5: Update `testConfig` in provider_test.go**

In `internal/proxy/secrets/provider_test.go`, add `TypeName()` to the existing `testConfig`:

```go
type testConfig struct {
	ProviderConfigMarker
}

func (testConfig) TypeName() string { return "test" }
```

- [ ] **Step 6: Add `TypeName()` to `keyring.Config`**

In `internal/proxy/secrets/keyring/config.go`, add after the `Config` struct definition and before the compile-time assertions:

```go
// TypeName returns "keyring". Used by the registry to map
// keyring:// URI scheme refs to this provider.
func (Config) TypeName() string { return "keyring" }
```

- [ ] **Step 7: Build and test**

Run: `cd /home/eran/work/agentsh && go build ./internal/proxy/secrets/... && go test ./internal/proxy/secrets/ -v`

Expected: PASS — everything compiles and tests pass.

- [ ] **Step 8: Commit**

```bash
cd /home/eran/work/agentsh
git add internal/proxy/secrets/errors.go internal/proxy/secrets/errors_test.go internal/proxy/secrets/provider.go internal/proxy/secrets/provider_test.go internal/proxy/secrets/keyring/config.go
git commit -m "feat(secrets): add TypeName/Dependencies to ProviderConfig + ErrCyclicDependency (Plan 4)"
```

---

## Task 2: Provider Registry

**Files:**
- Create: `internal/proxy/secrets/registry.go`
- Create: `internal/proxy/secrets/registry_test.go`

- [ ] **Step 1: Write registry tests**

Create `internal/proxy/secrets/registry_test.go`:

```go
package secrets

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
)

// testProviderConfig is a minimal ProviderConfig for registry tests.
type testProviderConfig struct {
	ProviderConfigMarker
	typeName string
	deps     []SecretRef
}

func (c testProviderConfig) TypeName() string          { return c.typeName }
func (c testProviderConfig) Dependencies() []SecretRef { return c.deps }

// testProvider is a minimal SecretProvider for registry tests.
type testProvider struct {
	name     string
	closeCt  atomic.Int32
	fetchErr error
	fetchVal SecretValue
}

func (p *testProvider) Name() string { return p.name }
func (p *testProvider) Fetch(_ context.Context, _ SecretRef) (SecretValue, error) {
	if p.fetchErr != nil {
		return SecretValue{}, p.fetchErr
	}
	cp := make([]byte, len(p.fetchVal.Value))
	copy(cp, p.fetchVal.Value)
	return SecretValue{Value: cp, FetchedAt: p.fetchVal.FetchedAt}, nil
}
func (p *testProvider) Close() error {
	p.closeCt.Add(1)
	return nil
}

func TestNewRegistry_NoDependencies(t *testing.T) {
	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, cfg ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: cfg.TypeName()}, nil
		},
	}
	reg, err := NewRegistry(context.Background(), configs, constructors)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	p, ok := reg.Provider("kr")
	if !ok {
		t.Fatal("Provider('kr') not found")
	}
	if p.Name() != "keyring" {
		t.Errorf("Provider name = %q, want 'keyring'", p.Name())
	}
}

func TestNewRegistry_LinearChain(t *testing.T) {
	// vault depends on keyring via a token_ref
	tokenRef := SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	configs := map[string]ProviderConfig{
		"vault-prod": testProviderConfig{
			typeName: "vault",
			deps:     []SecretRef{tokenRef},
		},
		"kr": testProviderConfig{typeName: "keyring"},
	}

	var constructionOrder []string
	var resolvedToken []byte

	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, cfg ProviderConfig, _ RefResolver) (SecretProvider, error) {
			constructionOrder = append(constructionOrder, cfg.TypeName())
			return &testProvider{
				name:     "keyring",
				fetchVal: SecretValue{Value: []byte("real-vault-token")},
			}, nil
		},
		"vault": func(ctx context.Context, cfg ProviderConfig, resolver RefResolver) (SecretProvider, error) {
			constructionOrder = append(constructionOrder, cfg.TypeName())
			// Resolve the chained ref
			sv, err := resolver(ctx, tokenRef)
			if err != nil {
				return nil, fmt.Errorf("resolving token: %w", err)
			}
			resolvedToken = sv.Value
			return &testProvider{name: "vault"}, nil
		},
	}

	reg, err := NewRegistry(context.Background(), configs, constructors)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	// keyring must be constructed before vault
	if len(constructionOrder) != 2 {
		t.Fatalf("construction order length = %d, want 2", len(constructionOrder))
	}
	if constructionOrder[0] != "keyring" || constructionOrder[1] != "vault" {
		t.Errorf("construction order = %v, want [keyring vault]", constructionOrder)
	}
	if string(resolvedToken) != "real-vault-token" {
		t.Errorf("resolved token = %q, want 'real-vault-token'", resolvedToken)
	}
}

func TestNewRegistry_CycleDetected(t *testing.T) {
	configs := map[string]ProviderConfig{
		"a": testProviderConfig{
			typeName: "atype",
			deps:     []SecretRef{{Scheme: "btype"}},
		},
		"b": testProviderConfig{
			typeName: "btype",
			deps:     []SecretRef{{Scheme: "atype"}},
		},
	}
	constructors := map[string]ConstructorFunc{
		"atype": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: "a"}, nil
		},
		"btype": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: "b"}, nil
		},
	}

	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected ErrCyclicDependency, got nil")
	}
	if !errors.Is(err, ErrCyclicDependency) {
		t.Errorf("error = %v, want wrapping ErrCyclicDependency", err)
	}
}

func TestNewRegistry_SelfCycle(t *testing.T) {
	configs := map[string]ProviderConfig{
		"a": testProviderConfig{
			typeName: "atype",
			deps:     []SecretRef{{Scheme: "atype"}},
		},
	}
	constructors := map[string]ConstructorFunc{
		"atype": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: "a"}, nil
		},
	}

	_, err := NewRegistry(context.Background(), configs, constructors)
	if !errors.Is(err, ErrCyclicDependency) {
		t.Errorf("self-cycle: error = %v, want wrapping ErrCyclicDependency", err)
	}
}

func TestNewRegistry_MissingConstructor(t *testing.T) {
	configs := map[string]ProviderConfig{
		"v": testProviderConfig{typeName: "vault"},
	}
	constructors := map[string]ConstructorFunc{
		// no "vault" constructor
	}

	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error for missing constructor, got nil")
	}
}

func TestNewRegistry_ConstructorFailure_CleansUp(t *testing.T) {
	var krProvider testProvider

	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
		"v":  testProviderConfig{typeName: "vault", deps: []SecretRef{{Scheme: "keyring"}}},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			krProvider.name = "keyring"
			return &krProvider, nil
		},
		"vault": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return nil, fmt.Errorf("vault init failed")
		},
	}

	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// keyring must have been closed during cleanup
	if krProvider.closeCt.Load() != 1 {
		t.Errorf("keyring Close count = %d, want 1", krProvider.closeCt.Load())
	}
}

func TestNewRegistry_UnresolvedDependency(t *testing.T) {
	// vault depends on a scheme "op" that has no provider config
	configs := map[string]ProviderConfig{
		"v": testProviderConfig{typeName: "vault", deps: []SecretRef{{Scheme: "op"}}},
	}
	constructors := map[string]ConstructorFunc{
		"vault": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: "vault"}, nil
		},
	}

	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error for unresolved dep, got nil")
	}
}

func TestRegistry_Fetch_Dispatches(t *testing.T) {
	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{
				name:     "keyring",
				fetchVal: SecretValue{Value: []byte("secret-val")},
			}, nil
		},
	}
	reg, err := NewRegistry(context.Background(), configs, constructors)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	ref := SecretRef{Scheme: "keyring", Host: "svc", Path: "user"}
	sv, err := reg.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "secret-val" {
		t.Errorf("Fetch value = %q, want 'secret-val'", sv.Value)
	}
}

func TestRegistry_Fetch_UnknownScheme(t *testing.T) {
	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: "keyring"}, nil
		},
	}
	reg, err := NewRegistry(context.Background(), configs, constructors)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()

	ref := SecretRef{Scheme: "vault", Host: "kv", Path: "x"}
	_, err = reg.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch with unknown scheme should fail")
	}
}

func TestRegistry_Close_ClosesAll(t *testing.T) {
	var p1, p2 testProvider

	configs := map[string]ProviderConfig{
		"a": testProviderConfig{typeName: "atype"},
		"b": testProviderConfig{typeName: "btype"},
	}
	constructors := map[string]ConstructorFunc{
		"atype": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			p1.name = "a"
			return &p1, nil
		},
		"btype": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			p2.name = "b"
			return &p2, nil
		},
	}
	reg, err := NewRegistry(context.Background(), configs, constructors)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if p1.closeCt.Load() != 1 {
		t.Errorf("p1 Close count = %d, want 1", p1.closeCt.Load())
	}
	if p2.closeCt.Load() != 1 {
		t.Errorf("p2 Close count = %d, want 1", p2.closeCt.Load())
	}
}

func TestRegistry_Close_Idempotent(t *testing.T) {
	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: "keyring"}, nil
		},
	}
	reg, err := NewRegistry(context.Background(), configs, constructors)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := reg.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := reg.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/eran/work/agentsh && go test ./internal/proxy/secrets/ -run TestNewRegistry -v 2>&1 | head -20`

Expected: FAIL — `NewRegistry`, `ConstructorFunc`, `RefResolver` not defined.

- [ ] **Step 3: Implement registry.go**

Create `internal/proxy/secrets/registry.go`:

```go
package secrets

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// RefResolver lets a provider constructor fetch a secret from an
// already-constructed provider during auth chaining.
type RefResolver func(ctx context.Context, ref SecretRef) (SecretValue, error)

// ConstructorFunc builds a SecretProvider from its config. The
// resolver can fetch secrets from providers that have already been
// constructed (for auth chaining like vault's token_ref pointing
// at keyring://...).
type ConstructorFunc func(ctx context.Context, cfg ProviderConfig, resolver RefResolver) (SecretProvider, error)

// Registry holds constructed providers keyed by their config name.
// It is constructed by NewRegistry, which resolves auth-chaining
// dependencies via topological sort and builds providers in the
// right order.
type Registry struct {
	mu sync.Mutex

	// providers keyed by config name (e.g. "kr", "vault-prod").
	providers map[string]SecretProvider

	// schemeToName maps URI scheme → config name for Fetch dispatch.
	schemeToName map[string]string

	closed bool
}

// NewRegistry constructs all providers in dependency order.
//
// configs maps config names to their ProviderConfig. constructors
// maps provider type names (from TypeName()) to their constructor
// functions. Every config's TypeName() must have a matching entry
// in constructors.
//
// Dependencies are resolved via topological sort. Cyclic
// dependencies return ErrCyclicDependency. If any constructor
// fails, all already-constructed providers are closed before the
// error is returned.
func NewRegistry(ctx context.Context, configs map[string]ProviderConfig, constructors map[string]ConstructorFunc) (*Registry, error) {
	// Validate all configs have constructors.
	for name, cfg := range configs {
		if _, ok := constructors[cfg.TypeName()]; !ok {
			return nil, fmt.Errorf("no constructor registered for provider type %q (config %q)", cfg.TypeName(), name)
		}
	}

	// Build scheme → config-name map and check for duplicate schemes.
	schemeToName := make(map[string]string, len(configs))
	for name, cfg := range configs {
		scheme := cfg.TypeName()
		if existing, dup := schemeToName[scheme]; dup {
			return nil, fmt.Errorf("duplicate provider type %q: configs %q and %q", scheme, existing, name)
		}
		schemeToName[scheme] = name
	}

	// Build dependency graph: configName → list of configNames it depends on.
	graph := make(map[string][]string, len(configs))
	inDegree := make(map[string]int, len(configs))
	for name := range configs {
		graph[name] = nil
		inDegree[name] = 0
	}

	for name, cfg := range configs {
		for _, dep := range cfg.Dependencies() {
			depName, ok := schemeToName[dep.Scheme]
			if !ok {
				return nil, fmt.Errorf("config %q depends on scheme %q, but no provider handles that scheme", name, dep.Scheme)
			}
			graph[depName] = append(graph[depName], name)
			inDegree[name]++
		}
	}

	// Kahn's algorithm for topological sort.
	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}
	// Sort the initial queue for deterministic ordering.
	sort.Strings(queue)

	var order []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		order = append(order, cur)

		// Sort neighbors for deterministic ordering.
		neighbors := graph[cur]
		sort.Strings(neighbors)
		for _, next := range neighbors {
			inDegree[next]--
			if inDegree[next] == 0 {
				queue = append(queue, next)
			}
		}
	}

	if len(order) != len(configs) {
		// Cycle detected — find which configs are in the cycle.
		var inCycle []string
		for name, deg := range inDegree {
			if deg > 0 {
				inCycle = append(inCycle, name)
			}
		}
		sort.Strings(inCycle)
		return nil, fmt.Errorf("%w: %v", ErrCyclicDependency, inCycle)
	}

	// Construct providers in topological order.
	providers := make(map[string]SecretProvider, len(order))
	for _, name := range order {
		cfg := configs[name]
		ctor := constructors[cfg.TypeName()]

		// Build a resolver that can fetch from already-constructed providers.
		resolver := func(fetchCtx context.Context, ref SecretRef) (SecretValue, error) {
			provName, ok := schemeToName[ref.Scheme]
			if !ok {
				return SecretValue{}, fmt.Errorf("no provider handles scheme %q", ref.Scheme)
			}
			p, ok := providers[provName]
			if !ok {
				return SecretValue{}, fmt.Errorf("provider %q not yet constructed (dependency ordering bug)", provName)
			}
			return p.Fetch(fetchCtx, ref)
		}

		p, err := ctor(ctx, cfg, resolver)
		if err != nil {
			// Cleanup already-constructed providers.
			for _, constructed := range order[:len(providers)] {
				_ = providers[constructed].Close()
			}
			return nil, fmt.Errorf("constructing provider %q (type %q): %w", name, cfg.TypeName(), err)
		}
		providers[name] = p
	}

	return &Registry{
		providers:    providers,
		schemeToName: schemeToName,
	}, nil
}

// Provider returns a named provider, or false if not found.
func (r *Registry) Provider(name string) (SecretProvider, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.providers[name]
	return p, ok
}

// Fetch resolves a SecretRef by finding the provider that handles
// its scheme and delegating to that provider's Fetch.
func (r *Registry) Fetch(ctx context.Context, ref SecretRef) (SecretValue, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return SecretValue{}, fmt.Errorf("registry closed")
	}
	name, ok := r.schemeToName[ref.Scheme]
	if !ok {
		r.mu.Unlock()
		return SecretValue{}, fmt.Errorf("no provider handles scheme %q", ref.Scheme)
	}
	p := r.providers[name]
	r.mu.Unlock()
	return p.Fetch(ctx, ref)
}

// Close calls Close() on every provider. Safe to call multiple
// times; subsequent calls are no-ops.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var firstErr error
	for _, p := range r.providers {
		if err := p.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
```

- [ ] **Step 4: Run registry tests**

Run: `cd /home/eran/work/agentsh && go test ./internal/proxy/secrets/ -run "TestNewRegistry|TestRegistry_" -v`

Expected: PASS — all registry tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/eran/work/agentsh
git add internal/proxy/secrets/registry.go internal/proxy/secrets/registry_test.go
git commit -m "feat(secrets): provider registry with topo sort + auth chaining (Plan 4)"
```

---

## Task 3: Add `vault/api/auth/approle` dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Add the approle auth module**

Run: `cd /home/eran/work/agentsh && go get github.com/hashicorp/vault/api/auth/approle@latest`

- [ ] **Step 2: Tidy**

Run: `cd /home/eran/work/agentsh && go mod tidy`

- [ ] **Step 3: Inspect go.sum delta for surprises**

Run: `cd /home/eran/work/agentsh && git diff go.sum | head -40`

Verify that any new transitive dependencies are from the `hashicorp` ecosystem and not surprising third-party modules. The `auth/approle` module is small and shares transitive deps with the already-present `vault/api` and `vault/api/auth/kubernetes`.

- [ ] **Step 4: Commit**

```bash
cd /home/eran/work/agentsh
git add go.mod go.sum
git commit -m "deps: add hashicorp/vault/api/auth/approle (Plan 4)"
```

---

## Task 4: Vault package skeleton — doc.go and config.go

**Files:**
- Create: `internal/proxy/secrets/vault/doc.go`
- Create: `internal/proxy/secrets/vault/config.go`

- [ ] **Step 1: Create vault/doc.go**

Create `internal/proxy/secrets/vault/doc.go`:

```go
// Package vault implements secrets.SecretProvider using HashiCorp
// Vault's KV v2 secrets engine. It wraps github.com/hashicorp/vault/api.
//
// Vault URIs take the form
//
//	vault://<mount>/<path>[#<field>]
//
// where <mount> is the KV v2 mount name, <path> is the secret path
// within the mount, and the optional <field> selects one key from
// the KV data map.
//
// The vault/api KV v2 helper adds the "data/" prefix internally.
// If a URI path starts with "data/", the provider strips it and
// logs a warning (common mistake when copying from the raw Vault
// HTTP API).
//
// OpenBao is a wire-compatible Vault fork. This provider works
// with OpenBao by pointing Address at the OpenBao server. No code
// changes are needed.
//
// Supported auth methods: token, approle, kubernetes.
//
// Auth chaining is supported: bootstrap credentials (e.g. the
// Vault token) can be fetched from another provider via the
// RefResolver passed to New.
package vault
```

- [ ] **Step 2: Create vault/config.go**

Create `internal/proxy/secrets/vault/config.go`:

```go
package vault

import (
	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

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

// TypeName returns "vault". Used by the registry to map vault://
// URI scheme refs to this provider.
func (Config) TypeName() string { return "vault" }

// Dependencies returns all *Ref fields that need resolution from
// other providers before this provider can be constructed.
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

// SecretRef is an alias for secrets.SecretRef used in AuthConfig
// so callers do not need to import the parent package just for
// config construction.
type SecretRef = secrets.SecretRef

// AuthConfig configures how the provider authenticates to Vault.
type AuthConfig struct {
	// Method is the auth method: "token", "approle", or "kubernetes".
	Method string

	// Token auth. Exactly one of Token (literal) or TokenRef (chained)
	// must be set when Method == "token".
	Token    string
	TokenRef *SecretRef

	// AppRole auth. Each of RoleID/RoleIDRef and SecretID/SecretIDRef
	// is a literal-or-ref pair. Exactly one form per field must be set
	// when Method == "approle".
	RoleID      string
	RoleIDRef   *SecretRef
	SecretID    string
	SecretIDRef *SecretRef

	// Kubernetes auth.
	KubeRole      string // required when Method == "kubernetes"
	KubeMountPath string // default "kubernetes"
	KubeTokenPath string // default "/var/run/secrets/kubernetes.io/serviceaccount/token"
}

// Compile-time assertions. These fail to build if Config ever
// drifts away from the interfaces it's expected to satisfy.
var (
	_ secrets.ProviderConfig = Config{}
	_ secrets.SecretProvider = (*Provider)(nil)
)
```

Note: The `_ secrets.SecretProvider = (*Provider)(nil)` assertion will cause a build failure until Task 5 creates `Provider`. That is expected — do NOT remove this line. Task 5 will define `Provider` and the build will succeed then.

- [ ] **Step 3: Write config tests**

Create a temporary test to verify Config methods (these will be expanded in Task 5 once Provider exists). Add to the top of what will become `internal/proxy/secrets/vault/provider_test.go`:

```go
package vault

import (
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

func TestConfig_TypeName(t *testing.T) {
	c := Config{}
	if got := c.TypeName(); got != "vault" {
		t.Errorf("TypeName() = %q, want 'vault'", got)
	}
}

func TestConfig_Dependencies_Empty(t *testing.T) {
	c := Config{Auth: AuthConfig{Method: "token", Token: "literal"}}
	if deps := c.Dependencies(); len(deps) != 0 {
		t.Errorf("Dependencies() = %v, want empty", deps)
	}
}

func TestConfig_Dependencies_WithRefs(t *testing.T) {
	tokenRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	roleRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-role"}
	secretRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-secret"}

	c := Config{
		Auth: AuthConfig{
			Method:      "approle",
			RoleIDRef:   &roleRef,
			SecretIDRef: &secretRef,
			TokenRef:    &tokenRef, // unusual but legal to set for testing
		},
	}
	deps := c.Dependencies()
	if len(deps) != 3 {
		t.Fatalf("Dependencies() length = %d, want 3", len(deps))
	}
}
```

- [ ] **Step 4: Run config test (expect build failure for now)**

Run: `cd /home/eran/work/agentsh && go test ./internal/proxy/secrets/vault/ -run TestConfig -v 2>&1 | head -10`

Expected: Build failure mentioning `Provider` undefined. This is fine — the compile-time assertion in config.go references `Provider` which doesn't exist yet. Comment out the `_ secrets.SecretProvider = (*Provider)(nil)` line temporarily to verify config tests pass, then uncomment it.

Alternative: just verify the doc.go and config.go compile in isolation by temporarily commenting the `Provider` assertion:

Run: `cd /home/eran/work/agentsh && go vet ./internal/proxy/secrets/vault/ 2>&1 | head -10`

- [ ] **Step 5: Commit**

```bash
cd /home/eran/work/agentsh
git add internal/proxy/secrets/vault/doc.go internal/proxy/secrets/vault/config.go internal/proxy/secrets/vault/provider_test.go
git commit -m "feat(secrets/vault): package skeleton — doc.go, config.go, config tests (Plan 4)"
```

---

## Task 5: Vault provider — construction, Fetch, Close

**Files:**
- Create: `internal/proxy/secrets/vault/provider.go`
- Modify: `internal/proxy/secrets/vault/provider_test.go`

- [ ] **Step 1: Write httptest mock helper and happy-path test**

Add to `internal/proxy/secrets/vault/provider_test.go` (below the existing config tests):

```go
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/secretstest"
)

// mockVaultServer returns an httptest.Server that simulates Vault
// KV v2 endpoints. kvData maps "mount/path" → field → value.
func mockVaultServer(t *testing.T, token string, kvData map[string]map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Token lookup-self for connectivity check.
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"errors":["permission denied"]}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"id":"%s","ttl":3600}}`, token)
	})

	// Token revoke-self.
	mux.HandleFunc("/v1/auth/token/revoke-self", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// AppRole login.
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.RoleID == "" || body.SecretID == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"errors":["missing role_id or secret_id"]}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"auth":{"client_token":"%s","lease_duration":3600,"renewable":true}}`, token)
	})

	// Kubernetes login.
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Role string `json:"role"`
			JWT  string `json:"jwt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Role == "" || body.JWT == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"errors":["missing role or jwt"]}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"auth":{"client_token":"%s","lease_duration":3600,"renewable":true}}`, token)
	})

	// KV v2 read: /v1/{mount}/data/{path}
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"errors":["permission denied"]}`)
			return
		}

		// Parse /v1/{mount}/data/{path}
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		parts := strings.SplitN(path, "/data/", 2)
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"errors":["no handler for route"]}`)
			return
		}
		key := parts[0] + "/" + parts[1]

		fields, ok := kvData[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"errors":[]}`)
			return
		}

		// Build KV v2 response.
		dataMap := make(map[string]interface{})
		for k, v := range fields {
			dataMap[k] = v
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": dataMap,
				"metadata": map[string]interface{}{
					"version":      3,
					"created_time": "2026-04-09T10:00:00Z",
				},
			},
			"lease_id":       "",
			"lease_duration": 0,
			"renewable":      false,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// noopResolver is a RefResolver that always returns an error.
// Used when the Vault config has no chained refs.
func noopResolver(_ context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	return secrets.SecretValue{}, fmt.Errorf("noopResolver: unexpected resolve call for %s", ref.String())
}

func TestNew_TokenAuth_HappyPath(t *testing.T) {
	const testToken = "hvs.test-token-12345"
	srv := mockVaultServer(t, testToken, nil)

	cfg := Config{
		Address: srv.URL,
		Auth: AuthConfig{
			Method: "token",
			Token:  testToken,
		},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	if p.Name() != "vault" {
		t.Errorf("Name() = %q, want 'vault'", p.Name())
	}
}

func TestFetch_KVv2_WithField(t *testing.T) {
	const testToken = "hvs.test-token-12345"
	kvData := map[string]map[string]string{
		"kv/github": {"token": "ghp_real123", "endpoint": "https://api.github.com"},
	}
	srv := mockVaultServer(t, testToken, kvData)

	cfg := Config{
		Address: srv.URL,
		Auth:    AuthConfig{Method: "token", Token: testToken},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "github", Field: "token"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "ghp_real123" {
		t.Errorf("Fetch value = %q, want 'ghp_real123'", sv.Value)
	}
	if sv.Version != "3" {
		t.Errorf("Version = %q, want '3'", sv.Version)
	}
	if sv.FetchedAt.IsZero() {
		t.Error("FetchedAt not set")
	}
}

func TestFetch_KVv2_SingleFieldAutoResolve(t *testing.T) {
	const testToken = "hvs.test-token-12345"
	kvData := map[string]map[string]string{
		"secret/api-key": {"value": "sk-12345"},
	}
	srv := mockVaultServer(t, testToken, kvData)

	cfg := Config{
		Address: srv.URL,
		Auth:    AuthConfig{Method: "token", Token: testToken},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "secret", Path: "api-key"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "sk-12345" {
		t.Errorf("Fetch value = %q, want 'sk-12345'", sv.Value)
	}
}

func TestFetch_KVv2_MultiFieldNoFragment_Error(t *testing.T) {
	const testToken = "hvs.test-token-12345"
	kvData := map[string]map[string]string{
		"kv/multi": {"user": "admin", "pass": "secret"},
	}
	srv := mockVaultServer(t, testToken, kvData)

	cfg := Config{
		Address: srv.URL,
		Auth:    AuthConfig{Method: "token", Token: testToken},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "multi"}
	_, err = p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for multi-field without fragment")
	}
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("error = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_KVv2_MissingField(t *testing.T) {
	const testToken = "hvs.test-token-12345"
	kvData := map[string]map[string]string{
		"kv/github": {"token": "ghp_real123"},
	}
	srv := mockVaultServer(t, testToken, kvData)

	cfg := Config{
		Address: srv.URL,
		Auth:    AuthConfig{Method: "token", Token: testToken},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "github", Field: "nonexistent"}
	_, err = p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("missing field error = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_SecretNotFound(t *testing.T) {
	const testToken = "hvs.test-token-12345"
	srv := mockVaultServer(t, testToken, nil)

	cfg := Config{
		Address: srv.URL,
		Auth:    AuthConfig{Method: "token", Token: testToken},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "nonexistent", Field: "x"}
	_, err = p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("not found error = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_WrongScheme(t *testing.T) {
	p := &Provider{} // zero-value, not connected
	ref := secrets.SecretRef{Scheme: "keyring", Host: "kv", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("wrong scheme error = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_MissingHost(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "vault", Host: "", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("missing host error = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_MissingPath(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: ""}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("missing path error = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_ContextCanceled(t *testing.T) {
	p := &Provider{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "x"}
	_, err := p.Fetch(ctx, ref)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("canceled ctx error = %v, want context.Canceled", err)
	}
}

func TestFetch_AfterClose(t *testing.T) {
	const testToken = "hvs.test-token-12345"
	srv := mockVaultServer(t, testToken, nil)

	cfg := Config{
		Address: srv.URL,
		Auth:    AuthConfig{Method: "token", Token: testToken},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "x"}
	_, err = p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
}

func TestClose_Idempotent(t *testing.T) {
	const testToken = "hvs.test-token-12345"
	srv := mockVaultServer(t, testToken, nil)

	cfg := Config{
		Address: srv.URL,
		Auth:    AuthConfig{Method: "token", Token: testToken},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/eran/work/agentsh && go test ./internal/proxy/secrets/vault/ -run "TestNew_TokenAuth|TestFetch_|TestClose_" -v 2>&1 | head -10`

Expected: FAIL — `Provider` type and `New` function not defined.

- [ ] **Step 3: Implement vault/provider.go**

Create `internal/proxy/secrets/vault/provider.go`:

```go
package vault

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	approleauth "github.com/hashicorp/vault/api/auth/approle"
	kubeauth "github.com/hashicorp/vault/api/auth/kubernetes"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Provider is a Vault-backed secrets.SecretProvider.
//
// It reads KV v2 secrets using the hashicorp/vault/api client.
// Supported auth methods: token, approle, kubernetes.
//
// Provider is safe for concurrent Fetch and Close.
type Provider struct {
	mu     sync.RWMutex
	closed atomic.Bool
	client *vaultapi.Client

	// ownedToken is true when the provider created the token via
	// AppRole or Kubernetes auth. If true, Close revokes the token.
	ownedToken bool
}

// New constructs a Vault Provider.
//
// It validates the config, resolves any chained secret refs via the
// resolver, creates a vault/api.Client, authenticates, and verifies
// connectivity with a token self-lookup.
func New(ctx context.Context, cfg Config, resolver secrets.RefResolver) (*Provider, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Resolve chained refs.
	token, roleID, secretID, err := resolveAuthRefs(ctx, cfg.Auth, resolver)
	if err != nil {
		return nil, fmt.Errorf("resolving auth refs: %w", err)
	}

	// Create vault/api client.
	apiCfg := vaultapi.DefaultConfig()
	apiCfg.Address = cfg.Address
	apiCfg.Timeout = 30 * time.Second

	client, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	var ownedToken bool

	// Authenticate.
	switch cfg.Auth.Method {
	case "token":
		client.SetToken(token)
	case "approle":
		appRole, err := approleauth.NewAppRoleAuth(roleID, &approleauth.SecretID{FromString: secretID})
		if err != nil {
			return nil, fmt.Errorf("creating approle auth: %w", err)
		}
		authInfo, err := client.Auth().Login(ctx, appRole)
		if err != nil {
			return nil, fmt.Errorf("%w: approle login: %s", secrets.ErrUnauthorized, err)
		}
		if authInfo == nil || authInfo.Auth == nil {
			return nil, fmt.Errorf("%w: approle login returned no auth info", secrets.ErrUnauthorized)
		}
		ownedToken = true
	case "kubernetes":
		mountPath := cfg.Auth.KubeMountPath
		if mountPath == "" {
			mountPath = "kubernetes"
		}
		tokenPath := cfg.Auth.KubeTokenPath
		if tokenPath == "" {
			tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}
		kubeAuth, err := kubeauth.NewKubernetesAuth(
			cfg.Auth.KubeRole,
			kubeauth.WithServiceAccountTokenPath(tokenPath),
			kubeauth.WithMountPath(mountPath),
		)
		if err != nil {
			return nil, fmt.Errorf("creating kubernetes auth: %w", err)
		}
		authInfo, err := client.Auth().Login(ctx, kubeAuth)
		if err != nil {
			return nil, fmt.Errorf("%w: kubernetes login: %s", secrets.ErrUnauthorized, err)
		}
		if authInfo == nil || authInfo.Auth == nil {
			return nil, fmt.Errorf("%w: kubernetes login returned no auth info", secrets.ErrUnauthorized)
		}
		ownedToken = true
	}

	// Verify connectivity.
	_, err = client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: token self-lookup failed: %s", secrets.ErrUnauthorized, err)
	}

	return &Provider{
		client:     client,
		ownedToken: ownedToken,
	}, nil
}

// Name returns "vault".
func (p *Provider) Name() string { return "vault" }

// Fetch retrieves a secret from Vault KV v2.
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("vault provider closed")
	}
	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("vault provider closed")
	}

	// Validate ref.
	if ref.Scheme != "vault" {
		return secrets.SecretValue{}, fmt.Errorf("%w: wrong scheme %q", secrets.ErrInvalidURI, ref.Scheme)
	}
	if ref.Host == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: vault URI missing mount (host)", secrets.ErrInvalidURI)
	}
	if ref.Path == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: vault URI missing path", secrets.ErrInvalidURI)
	}

	// Strip accidental "data/" prefix with a warning.
	path := ref.Path
	if strings.HasPrefix(path, "data/") {
		log.Printf("WARNING: vault URI path %q starts with 'data/' — stripping (KV v2 helper adds it automatically)", path)
		path = strings.TrimPrefix(path, "data/")
	}

	// Read from KV v2.
	kvSecret, err := p.client.KVv2(ref.Host).Get(ctx, path)
	if err != nil {
		var respErr *vaultapi.ResponseError
		if errors.As(err, &respErr) {
			switch respErr.StatusCode {
			case http.StatusNotFound:
				return secrets.SecretValue{}, fmt.Errorf("%w: %s", secrets.ErrNotFound, ref.String())
			case http.StatusForbidden:
				return secrets.SecretValue{}, fmt.Errorf("%w: %s", secrets.ErrUnauthorized, ref.String())
			}
		}
		return secrets.SecretValue{}, fmt.Errorf("vault read %s: %w", ref.String(), err)
	}
	if kvSecret == nil || kvSecret.Data == nil {
		return secrets.SecretValue{}, fmt.Errorf("%w: %s returned nil data", secrets.ErrNotFound, ref.String())
	}

	// Extract field.
	var value []byte
	if ref.Field != "" {
		raw, ok := kvSecret.Data[ref.Field]
		if !ok {
			return secrets.SecretValue{}, fmt.Errorf("%w: field %q not found in %s", secrets.ErrNotFound, ref.Field, ref.String())
		}
		value = toBytes(raw)
	} else {
		switch len(kvSecret.Data) {
		case 0:
			return secrets.SecretValue{}, fmt.Errorf("%w: %s has no fields", secrets.ErrNotFound, ref.String())
		case 1:
			for _, raw := range kvSecret.Data {
				value = toBytes(raw)
			}
		default:
			var fields []string
			for k := range kvSecret.Data {
				fields = append(fields, k)
			}
			return secrets.SecretValue{}, fmt.Errorf("%w: %s has multiple fields (%s) — use #field to select one", secrets.ErrInvalidURI, ref.String(), strings.Join(fields, ", "))
		}
	}

	sv := secrets.SecretValue{
		Value:     value,
		FetchedAt: time.Now(),
	}

	// Extract version metadata.
	if kvSecret.VersionMetadata != nil {
		sv.Version = strconv.Itoa(kvSecret.VersionMetadata.Version)
	}

	// Extract lease info from raw secret.
	if kvSecret.Raw != nil {
		if kvSecret.Raw.LeaseDuration > 0 {
			sv.TTL = time.Duration(kvSecret.Raw.LeaseDuration) * time.Second
		}
		sv.LeaseID = kvSecret.Raw.LeaseID
	}

	return sv, nil
}

// Close marks the provider closed and optionally revokes the token.
func (p *Provider) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil // already closed
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil && p.ownedToken {
		// Best-effort token revocation for tokens we created.
		_ = p.client.Auth().Token().RevokeSelf("")
	}
	p.client = nil
	return nil
}

// validateConfig checks that the Config is well-formed.
func validateConfig(cfg Config) error {
	if cfg.Address == "" {
		return fmt.Errorf("vault: address required")
	}

	switch cfg.Auth.Method {
	case "token":
		hasLiteral := cfg.Auth.Token != ""
		hasRef := cfg.Auth.TokenRef != nil
		if hasLiteral == hasRef {
			if hasLiteral {
				return fmt.Errorf("vault: token auth: set Token or TokenRef, not both")
			}
			return fmt.Errorf("vault: token auth: Token or TokenRef required")
		}
	case "approle":
		hasRoleIDLiteral := cfg.Auth.RoleID != ""
		hasRoleIDRef := cfg.Auth.RoleIDRef != nil
		if hasRoleIDLiteral == hasRoleIDRef {
			if hasRoleIDLiteral {
				return fmt.Errorf("vault: approle auth: set RoleID or RoleIDRef, not both")
			}
			return fmt.Errorf("vault: approle auth: RoleID or RoleIDRef required")
		}
		hasSecretIDLiteral := cfg.Auth.SecretID != ""
		hasSecretIDRef := cfg.Auth.SecretIDRef != nil
		if hasSecretIDLiteral == hasSecretIDRef {
			if hasSecretIDLiteral {
				return fmt.Errorf("vault: approle auth: set SecretID or SecretIDRef, not both")
			}
			return fmt.Errorf("vault: approle auth: SecretID or SecretIDRef required")
		}
	case "kubernetes":
		if cfg.Auth.KubeRole == "" {
			return fmt.Errorf("vault: kubernetes auth: KubeRole required")
		}
	default:
		return fmt.Errorf("vault: unsupported auth method %q (expected token, approle, or kubernetes)", cfg.Auth.Method)
	}
	return nil
}

// resolveAuthRefs resolves chained secret refs and returns the
// literal values for token, roleID, and secretID. Resolved
// SecretValues are zeroed after extracting the string.
func resolveAuthRefs(ctx context.Context, auth AuthConfig, resolver secrets.RefResolver) (token, roleID, secretID string, err error) {
	switch auth.Method {
	case "token":
		if auth.TokenRef != nil {
			sv, err := resolver(ctx, *auth.TokenRef)
			if err != nil {
				return "", "", "", fmt.Errorf("resolving token_ref: %w", err)
			}
			token = string(sv.Value)
			sv.Zero()
		} else {
			token = auth.Token
		}
	case "approle":
		if auth.RoleIDRef != nil {
			sv, err := resolver(ctx, *auth.RoleIDRef)
			if err != nil {
				return "", "", "", fmt.Errorf("resolving role_id_ref: %w", err)
			}
			roleID = string(sv.Value)
			sv.Zero()
		} else {
			roleID = auth.RoleID
		}
		if auth.SecretIDRef != nil {
			sv, err := resolver(ctx, *auth.SecretIDRef)
			if err != nil {
				return "", "", "", fmt.Errorf("resolving secret_id_ref: %w", err)
			}
			secretID = string(sv.Value)
			sv.Zero()
		} else {
			secretID = auth.SecretID
		}
	case "kubernetes":
		// Kubernetes auth does not use chained refs — it reads the
		// SA token from the filesystem directly.
	}
	return token, roleID, secretID, nil
}

// toBytes converts an interface{} to []byte. String values are
// converted directly; other types are JSON-encoded.
func toBytes(v interface{}) []byte {
	switch val := v.(type) {
	case string:
		return []byte(val)
	case []byte:
		cp := make([]byte, len(val))
		copy(cp, val)
		return cp
	default:
		b, _ := json.Marshal(v)
		return b
	}
}
```

Note: Add `"encoding/json"`, `"errors"`, and `"net/http"` to the imports.

The final import block for `provider.go` should be:

```go
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	approleauth "github.com/hashicorp/vault/api/auth/approle"
	kubeauth "github.com/hashicorp/vault/api/auth/kubernetes"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)
```

- [ ] **Step 4: Fix the provider_test.go import block**

The test file needs a single unified import block at the top. Merge the two import blocks into one:

```go
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/secretstest"
)
```

Remove the earlier `import` block that only had `testing` and `secrets`.

- [ ] **Step 5: Run all vault tests**

Run: `cd /home/eran/work/agentsh && go test ./internal/proxy/secrets/vault/ -v -count=1`

Expected: PASS — all tests pass. The Vault error checking uses `errors.As(err, &vaultapi.ResponseError{})` to match HTTP status codes from the mock server. If the KV v2 helper wraps errors differently than expected, adjust the error type assertion in `Fetch`.

Fix any compilation issues. Common ones:
- `http.StatusNotFound` and `http.StatusForbidden` require `"net/http"` import in `provider.go`.
- `json.Marshal` requires `"encoding/json"` import in `provider.go`.
- `errors.As` requires `"errors"` import in `provider.go`.

- [ ] **Step 6: Run full secrets test suite**

Run: `cd /home/eran/work/agentsh && go test ./internal/proxy/secrets/... -v -count=1`

Expected: PASS — vault tests and existing keyring/credsub tests all pass.

- [ ] **Step 7: Commit**

```bash
cd /home/eran/work/agentsh
git add internal/proxy/secrets/vault/provider.go internal/proxy/secrets/vault/provider_test.go
git commit -m "feat(secrets/vault): Vault KV v2 provider — token/approle/k8s auth, field extraction (Plan 4)"
```

---

## Task 6: Auth chaining, config validation, and contract tests

**Files:**
- Modify: `internal/proxy/secrets/vault/provider_test.go`

- [ ] **Step 1: Write auth chaining test**

Add to `internal/proxy/secrets/vault/provider_test.go`:

```go
func TestNew_AuthChaining_TokenFromResolver(t *testing.T) {
	const testToken = "hvs.chained-token-67890"
	srv := mockVaultServer(t, testToken, nil)

	tokenRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	memProvider := secretstest.NewMemoryProvider("keyring", map[string][]byte{
		"keyring://agentsh/vault-token": []byte(testToken),
	})
	resolver := func(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
		return memProvider.Fetch(ctx, ref)
	}

	cfg := Config{
		Address: srv.URL,
		Auth: AuthConfig{
			Method:   "token",
			TokenRef: &tokenRef,
		},
	}
	p, err := New(context.Background(), cfg, resolver)
	if err != nil {
		t.Fatalf("New with chained token: %v", err)
	}
	defer p.Close()
}

func TestNew_AppRoleAuth(t *testing.T) {
	const testToken = "hvs.approle-token"
	srv := mockVaultServer(t, testToken, nil)

	cfg := Config{
		Address: srv.URL,
		Auth: AuthConfig{
			Method:   "approle",
			RoleID:   "my-role-id",
			SecretID: "my-secret-id",
		},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New with approle: %v", err)
	}
	defer p.Close()
}

func TestNew_AppRoleAuth_ChainedRefs(t *testing.T) {
	const testToken = "hvs.approle-chained"
	srv := mockVaultServer(t, testToken, nil)

	roleRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-role"}
	secretRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-secret"}
	memProvider := secretstest.NewMemoryProvider("keyring", map[string][]byte{
		"keyring://agentsh/vault-role":   []byte("my-role-id"),
		"keyring://agentsh/vault-secret": []byte("my-secret-id"),
	})
	resolver := func(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
		return memProvider.Fetch(ctx, ref)
	}

	cfg := Config{
		Address: srv.URL,
		Auth: AuthConfig{
			Method:      "approle",
			RoleIDRef:   &roleRef,
			SecretIDRef: &secretRef,
		},
	}
	p, err := New(context.Background(), cfg, resolver)
	if err != nil {
		t.Fatalf("New with chained approle: %v", err)
	}
	defer p.Close()
}
```

- [ ] **Step 2: Write config validation tests**

Add to `internal/proxy/secrets/vault/provider_test.go`:

```go
func TestNew_MissingAddress(t *testing.T) {
	cfg := Config{Auth: AuthConfig{Method: "token", Token: "x"}}
	_, err := New(context.Background(), cfg, noopResolver)
	if err == nil {
		t.Fatal("expected error for missing address")
	}
}

func TestNew_BadAuthMethod(t *testing.T) {
	cfg := Config{Address: "http://localhost", Auth: AuthConfig{Method: "ldap"}}
	_, err := New(context.Background(), cfg, noopResolver)
	if err == nil {
		t.Fatal("expected error for bad auth method")
	}
}

func TestNew_TokenAuth_BothLiteralAndRef(t *testing.T) {
	ref := secrets.SecretRef{Scheme: "keyring", Host: "a", Path: "b"}
	cfg := Config{
		Address: "http://localhost",
		Auth:    AuthConfig{Method: "token", Token: "x", TokenRef: &ref},
	}
	_, err := New(context.Background(), cfg, noopResolver)
	if err == nil {
		t.Fatal("expected error for both Token and TokenRef")
	}
}

func TestNew_TokenAuth_NeitherLiteralNorRef(t *testing.T) {
	cfg := Config{
		Address: "http://localhost",
		Auth:    AuthConfig{Method: "token"},
	}
	_, err := New(context.Background(), cfg, noopResolver)
	if err == nil {
		t.Fatal("expected error for neither Token nor TokenRef")
	}
}

func TestNew_AppRole_MissingSecretID(t *testing.T) {
	cfg := Config{
		Address: "http://localhost",
		Auth:    AuthConfig{Method: "approle", RoleID: "x"},
	}
	_, err := New(context.Background(), cfg, noopResolver)
	if err == nil {
		t.Fatal("expected error for missing SecretID")
	}
}

func TestNew_Kubernetes_MissingRole(t *testing.T) {
	cfg := Config{
		Address: "http://localhost",
		Auth:    AuthConfig{Method: "kubernetes"},
	}
	_, err := New(context.Background(), cfg, noopResolver)
	if err == nil {
		t.Fatal("expected error for missing KubeRole")
	}
}
```

- [ ] **Step 3: Write contract test**

Add to `internal/proxy/secrets/vault/provider_test.go`:

```go
func TestProviderContract_AppliedToVaultProvider(t *testing.T) {
	const testToken = "hvs.contract-test-token"
	srv := mockVaultServer(t, testToken, nil)

	cfg := Config{
		Address: srv.URL,
		Auth:    AuthConfig{Method: "token", Token: testToken},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	probeRef := secrets.SecretRef{
		Scheme: "vault",
		Host:   "kv",
		Path:   "definitely-does-not-exist-contract-probe",
		Field:  "x",
	}
	secretstest.ProviderContract(t, "vault", p, probeRef)
}
```

- [ ] **Step 4: Run all vault tests**

Run: `cd /home/eran/work/agentsh && go test ./internal/proxy/secrets/vault/ -v -count=1`

Expected: PASS — all tests including auth chaining, validation, and contract.

- [ ] **Step 5: Commit**

```bash
cd /home/eran/work/agentsh
git add internal/proxy/secrets/vault/provider_test.go
git commit -m "test(secrets/vault): auth chaining, config validation, contract tests (Plan 4)"
```

---

## Task 7: Update doc.go and final verification

**Files:**
- Modify: `internal/proxy/secrets/doc.go`

- [ ] **Step 1: Update secrets/doc.go to mention vault and registry**

Replace the content of `internal/proxy/secrets/doc.go`:

```go
// Package secrets defines the SecretProvider interface that agentsh
// uses to fetch real credentials from external secret stores at
// session start, plus the URI grammar, sentinel errors, and the
// provider Registry shared by all provider implementations.
//
// The Registry (registry.go) constructs providers in dependency
// order via topological sort, enabling auth chaining where one
// provider's bootstrap credentials come from another (e.g. Vault
// reads its token from the OS keyring).
//
// Provider implementations live in subpackages, one per backend:
//
//   - internal/proxy/secrets/keyring — OS keyring (Keychain / Secret
//     Service / Credential Manager) via github.com/zalando/go-keyring.
//   - internal/proxy/secrets/vault — HashiCorp Vault / OpenBao KV v2
//     via github.com/hashicorp/vault/api.
//
// Future plans add awssm, gcpsm, azurekv, and op subpackages.
// Every provider imports this package for the interface and types;
// this package imports none of them.
//
// Test doubles live in the sibling secretstest package. Production
// code must not import secretstest.
//
// The design is documented in
// docs/superpowers/specs/2026-04-09-plan-04-vault-provider-registry-design.md
// and the parent migration spec
// docs/superpowers/specs/2026-04-07-external-secrets-design.md.
package secrets
```

- [ ] **Step 2: Run full test suite**

Run: `cd /home/eran/work/agentsh && go test ./internal/proxy/secrets/... -v -count=1`

Expected: PASS — all packages (secrets, secrets/keyring, secrets/secretstest, secrets/vault) pass.

- [ ] **Step 3: Build all**

Run: `cd /home/eran/work/agentsh && go build ./...`

Expected: PASS.

- [ ] **Step 4: Cross-compile for Windows**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./...`

Expected: PASS. The vault/api library is pure Go. No cgo issues.

- [ ] **Step 5: Verify no changes to out-of-scope files**

Run: `cd /home/eran/work/agentsh && git diff --name-only HEAD~6` (or however many commits back Plan 4 started)

Verify that ONLY these paths were modified:
- `internal/proxy/secrets/` (errors.go, provider.go, provider_test.go, errors_test.go, doc.go, registry.go, registry_test.go)
- `internal/proxy/secrets/keyring/config.go`
- `internal/proxy/secrets/vault/` (new files)
- `go.mod`, `go.sum`

No changes to: `pkg/secrets/`, `internal/session/`, `internal/api/`, `cmd/`, `internal/proxy/credsub/`.

- [ ] **Step 6: Commit**

```bash
cd /home/eran/work/agentsh
git add internal/proxy/secrets/doc.go
git commit -m "docs(secrets): update package doc for vault provider and registry (Plan 4)"
```

- [ ] **Step 7: Run full project tests**

Run: `cd /home/eran/work/agentsh && go test ./... 2>&1 | tail -20`

Expected: PASS for all packages. If any existing tests break, investigate — Plan 4 should not affect anything outside `internal/proxy/secrets/`.
