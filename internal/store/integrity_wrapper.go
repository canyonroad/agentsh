package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/pkg/types"
)

var _ EventStore = (*IntegrityStore)(nil)

// IntegrityStore wraps an EventStore and adds integrity metadata to events.
type IntegrityStore struct {
	mu    sync.Mutex
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
	rw, ok := s.inner.(RawWriter)
	if !ok {
		// Inner store does not support raw writes; delegate unsigned
		// without advancing chain state.
		return s.inner.AppendEvent(ctx, ev)
	}

	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("integrity marshal: %w", err)
	}

	// Serialize wrap+write so chain state stays consistent with on-disk order.
	s.mu.Lock()
	prevState := s.chain.State()
	wrapped, err := s.chain.Wrap(payload)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("integrity wrap: %w", err)
	}

	if writeErr := rw.WriteRaw(ctx, wrapped); writeErr != nil {
		// Only roll back chain state if the write was fully rolled back
		// (no partial data on disk). A PartialWriteError means truncate
		// failed and data may be on disk — we must NOT restore.
		type partialWriter interface{ IsPartialWrite() bool }
		if pw, ok := writeErr.(partialWriter); !ok || !pw.IsPartialWrite() {
			s.chain.Restore(prevState.Sequence, prevState.PrevHash)
		}
		s.mu.Unlock()
		return writeErr
	}
	s.mu.Unlock()
	return nil
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
