package store

import (
	"context"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/pkg/types"
)

// IntegrityStore wraps an EventStore and adds integrity metadata to events.
type IntegrityStore struct {
	inner EventStore
	chain *audit.IntegrityChain
}

// NewIntegrityStore wraps an existing store with integrity chain.
func NewIntegrityStore(inner EventStore, chain *audit.IntegrityChain) *IntegrityStore {
	return &IntegrityStore{inner: inner, chain: chain}
}

// AppendEvent wraps event with integrity metadata before writing.
func (s *IntegrityStore) AppendEvent(ctx context.Context, ev types.Event) error {
	// The actual wrapping happens at JSON serialization time.
	// We need to intercept at the JSON level, not the typed level.
	// This will be integrated into the broker or serialization layer.
	return s.inner.AppendEvent(ctx, ev)
}

// QueryEvents delegates to the inner store.
func (s *IntegrityStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return s.inner.QueryEvents(ctx, q)
}

// Close closes the inner store.
func (s *IntegrityStore) Close() error {
	return s.inner.Close()
}

// Chain returns the integrity chain for state management.
func (s *IntegrityStore) Chain() *audit.IntegrityChain {
	return s.chain
}
