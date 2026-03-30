package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/pkg/types"
)

var _ EventStore = (*IntegrityStore)(nil)

// IntegrityStore wraps an EventStore and adds integrity metadata to events.
type IntegrityStore struct {
	inner EventStore
	chain *audit.IntegrityChain
}

// NewIntegrityStore wraps an existing store with integrity chain.
func NewIntegrityStore(inner EventStore, chain *audit.IntegrityChain) *IntegrityStore {
	return &IntegrityStore{inner: inner, chain: chain}
}

// AppendEvent marshals the event, wraps it with HMAC integrity metadata,
// and writes the signed bytes via RawWriter if the inner store supports it.
// Falls back to unsigned inner.AppendEvent otherwise.
func (s *IntegrityStore) AppendEvent(ctx context.Context, ev types.Event) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("integrity marshal: %w", err)
	}

	wrapped, err := s.chain.Wrap(payload)
	if err != nil {
		return fmt.Errorf("integrity wrap: %w", err)
	}

	if rw, ok := s.inner.(RawWriter); ok {
		return rw.WriteRaw(ctx, wrapped)
	}

	// Fallback: delegate unsigned
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
