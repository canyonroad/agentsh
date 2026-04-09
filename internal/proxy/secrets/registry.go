package secrets

import (
	"context"
	"fmt"
	"reflect"
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

	// order records construction order for deterministic reverse teardown.
	order []string

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
	// Validate inputs: no nil configs or constructors.
	for name, cfg := range configs {
		if cfg == nil || isNilInterface(cfg) {
			return nil, fmt.Errorf("nil config for %q", name)
		}
	}
	for typeName, ctor := range constructors {
		if ctor == nil {
			return nil, fmt.Errorf("nil constructor for type %q", typeName)
		}
	}

	// Validate all configs have constructors and non-empty type names.
	for name, cfg := range configs {
		if cfg.TypeName() == "" {
			return nil, fmt.Errorf("config %q has empty TypeName", name)
		}
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
		// Cycle detected. Kahn's algorithm leaves nodes with inDegree > 0
		// for both cycle members and downstream dependents. We report all
		// unresolvable configs without claiming which are cycle members.
		var blocked []string
		for name, deg := range inDegree {
			if deg > 0 {
				blocked = append(blocked, name)
			}
		}
		sort.Strings(blocked)
		return nil, fmt.Errorf("%w: unresolvable configs: %v", ErrCyclicDependency, blocked)
	}

	// Construct providers in topological order.
	providers := make(map[string]SecretProvider, len(order))
	for _, name := range order {
		cfg := configs[name]
		ctor := constructors[cfg.TypeName()]

		// Build a scoped resolver that only allows resolving exact declared dependencies.
		declaredRefs := make(map[string]bool, len(cfg.Dependencies()))
		for _, dep := range cfg.Dependencies() {
			declaredRefs[refKey(dep)] = true
		}
		resolver := func(fetchCtx context.Context, ref SecretRef) (SecretValue, error) {
			if !declaredRefs[refKey(ref)] {
				return SecretValue{}, fmt.Errorf("ref %s://%s/%s not declared in Dependencies() for config %q", ref.Scheme, ref.Host, ref.Path, name)
			}
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
			// Cleanup already-constructed providers in reverse order.
			for i := len(providers) - 1; i >= 0; i-- {
				_ = providers[order[i]].Close()
			}
			return nil, fmt.Errorf("constructing provider %q (type %q): %w", name, cfg.TypeName(), err)
		}
		if p == nil || isNilInterface(p) {
			// A constructor returning (nil, nil) or a typed-nil is a bug; fail loudly.
			for i := len(providers) - 1; i >= 0; i-- {
				_ = providers[order[i]].Close()
			}
			return nil, fmt.Errorf("constructor for provider %q (type %q) returned a nil provider", name, cfg.TypeName())
		}
		providers[name] = p
	}

	return &Registry{
		providers:    providers,
		order:        order,
		schemeToName: schemeToName,
	}, nil
}

// Provider returns a named provider, or false if the name is unknown
// or the registry has been closed.
func (r *Registry) Provider(name string) (SecretProvider, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, false
	}
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

// Close calls Close() on every provider in reverse construction order.
// Safe to call multiple times; subsequent calls are no-ops. The lock
// is released before calling provider Close methods so that concurrent
// Fetch calls observe the closed flag immediately rather than blocking
// on a slow provider teardown.
func (r *Registry) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	// Snapshot what we need, then release the lock.
	order := r.order
	providers := r.providers
	r.mu.Unlock()

	var firstErr error
	for i := len(order) - 1; i >= 0; i-- {
		name := order[i]
		if err := providers[name].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// isNilInterface reports whether v is an interface holding a typed-nil
// value (e.g. (*Provider)(nil) stored in a SecretProvider interface).
// It handles all nilable kinds: ptr, map, slice, func, chan, interface.
func isNilInterface(v interface{}) bool {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}

// refKey returns a canonical string for a SecretRef, used to match
// exact declared dependencies in the scoped resolver.
func refKey(ref SecretRef) string {
	return ref.Scheme + "://" + ref.Host + "/" + ref.Path + "#" + ref.Field
}