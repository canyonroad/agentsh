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
