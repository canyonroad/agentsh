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

func TestNewRegistry_NilProvider_ReturnsError(t *testing.T) {
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
		// Buggy constructor: returns (nil, nil).
		"vault": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return nil, nil
		},
	}

	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error for nil provider, got nil")
	}
	// The already-constructed keyring provider must have been cleaned up.
	if krProvider.closeCt.Load() != 1 {
		t.Errorf("keyring Close count = %d, want 1 (cleanup on nil provider)", krProvider.closeCt.Load())
	}
}

func TestNewRegistry_DuplicateTypeName(t *testing.T) {
	// Two configs sharing the same TypeName should be rejected.
	configs := map[string]ProviderConfig{
		"kr1": testProviderConfig{typeName: "keyring"},
		"kr2": testProviderConfig{typeName: "keyring"},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: "keyring"}, nil
		},
	}

	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error for duplicate TypeName, got nil")
	}
}

// orderTrackingProvider records its name into a shared slice on Close,
// allowing tests to assert teardown order.
type orderTrackingProvider struct {
	name       string
	closeOrder *[]string
}

func (p *orderTrackingProvider) Name() string { return p.name }
func (p *orderTrackingProvider) Fetch(_ context.Context, _ SecretRef) (SecretValue, error) {
	return SecretValue{}, nil
}
func (p *orderTrackingProvider) Close() error {
	*p.closeOrder = append(*p.closeOrder, p.name)
	return nil
}

func TestNewRegistry_TypedNilProvider_ReturnsError(t *testing.T) {
	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return (*testProvider)(nil), nil // typed-nil
		},
	}
	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error for typed-nil provider, got nil")
	}
}

func TestRegistry_Close_ReverseOrder(t *testing.T) {
	var closeOrder []string
	// keyring has no deps, vault depends on keyring.
	// construction: keyring first, vault second.
	// teardown should be: vault first, keyring second.
	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
		"v":  testProviderConfig{typeName: "vault", deps: []SecretRef{{Scheme: "keyring"}}},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &orderTrackingProvider{name: "keyring", closeOrder: &closeOrder}, nil
		},
		"vault": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &orderTrackingProvider{name: "vault", closeOrder: &closeOrder}, nil
		},
	}
	reg, err := NewRegistry(context.Background(), configs, constructors)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	reg.Close()
	// vault (dependent) should close before keyring (dependency)
	if len(closeOrder) != 2 || closeOrder[0] != "vault" || closeOrder[1] != "keyring" {
		t.Errorf("close order = %v, want [vault keyring]", closeOrder)
	}
}

func TestRegistry_Provider_AfterClose(t *testing.T) {
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
	reg.Close()

	_, ok := reg.Provider("kr")
	if ok {
		t.Error("Provider() returned true after Close")
	}
}

// mapProvider is a non-pointer typed-nil provider for testing the
// broadened nil guard (covers map, slice, func, chan kinds).
type mapProvider map[string]string

func (mapProvider) Name() string                                              { return "map" }
func (mapProvider) Fetch(_ context.Context, _ SecretRef) (SecretValue, error) { return SecretValue{}, nil }
func (mapProvider) Close() error                                              { return nil }

func TestNewRegistry_NonPointerTypedNilProvider_ReturnsError(t *testing.T) {
	configs := map[string]ProviderConfig{
		"m": testProviderConfig{typeName: "maptype"},
	}
	constructors := map[string]ConstructorFunc{
		"maptype": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return (mapProvider)(nil), nil // non-pointer typed-nil
		},
	}
	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error for non-pointer typed-nil provider, got nil")
	}
}

func TestNewRegistry_NilConfig(t *testing.T) {
	configs := map[string]ProviderConfig{
		"kr": nil,
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: "keyring"}, nil
		},
	}
	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestNewRegistry_NilConstructor(t *testing.T) {
	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": nil,
	}
	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error for nil constructor, got nil")
	}
}

func TestNewRegistry_EmptyTypeName(t *testing.T) {
	configs := map[string]ProviderConfig{
		"bad": testProviderConfig{typeName: ""},
	}
	constructors := map[string]ConstructorFunc{
		"": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{name: "bad"}, nil
		},
	}
	_, err := NewRegistry(context.Background(), configs, constructors)
	if err == nil {
		t.Fatal("expected error for empty TypeName, got nil")
	}
}

func TestNewRegistry_ResolverRejectsUndeclaredDependency(t *testing.T) {
	// vault declares no dependencies but tries to resolve from keyring.
	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
		"v":  testProviderConfig{typeName: "vault"}, // no deps declared
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{
				name:     "keyring",
				fetchVal: SecretValue{Value: []byte("token")},
			}, nil
		},
		"vault": func(ctx context.Context, _ ProviderConfig, resolver RefResolver) (SecretProvider, error) {
			// Try to resolve an undeclared dependency — should fail.
			_, err := resolver(ctx, SecretRef{Scheme: "keyring", Host: "a", Path: "b"})
			if err == nil {
				return nil, fmt.Errorf("resolver should have rejected undeclared dependency")
			}
			return &testProvider{name: "vault"}, nil
		},
	}
	reg, err := NewRegistry(context.Background(), configs, constructors)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()
}

func TestNewRegistry_ResolverRejectsSameSchemeWrongRef(t *testing.T) {
	// vault declares keyring://agentsh/vault-token but tries to resolve
	// keyring://agentsh/other-secret — same scheme, different ref.
	declaredRef := SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	wrongRef := SecretRef{Scheme: "keyring", Host: "agentsh", Path: "other-secret"}

	configs := map[string]ProviderConfig{
		"kr": testProviderConfig{typeName: "keyring"},
		"v":  testProviderConfig{typeName: "vault", deps: []SecretRef{declaredRef}},
	}
	constructors := map[string]ConstructorFunc{
		"keyring": func(_ context.Context, _ ProviderConfig, _ RefResolver) (SecretProvider, error) {
			return &testProvider{
				name:     "keyring",
				fetchVal: SecretValue{Value: []byte("token")},
			}, nil
		},
		"vault": func(ctx context.Context, _ ProviderConfig, resolver RefResolver) (SecretProvider, error) {
			// Resolving the declared ref should work.
			_, err := resolver(ctx, declaredRef)
			if err != nil {
				return nil, fmt.Errorf("declared ref should resolve: %w", err)
			}
			// Resolving a different ref on the same scheme should fail.
			_, err = resolver(ctx, wrongRef)
			if err == nil {
				return nil, fmt.Errorf("resolver should have rejected wrong ref on same scheme")
			}
			return &testProvider{name: "vault"}, nil
		},
	}
	reg, err := NewRegistry(context.Background(), configs, constructors)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer reg.Close()
}