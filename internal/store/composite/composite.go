package composite

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/pkg/types"
)

type Store struct {
	primary store.EventStore
	output  store.OutputStore
	others  []store.EventStore
}

func New(primary store.EventStore, output store.OutputStore, others ...store.EventStore) *Store {
	return &Store{primary: primary, output: output, others: others}
}

func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	var firstErr error
	if err := s.primary.AppendEvent(ctx, ev); err != nil && firstErr == nil {
		firstErr = err
	}
	for _, o := range s.others {
		if err := o.AppendEvent(ctx, ev); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Store) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return s.primary.QueryEvents(ctx, q)
}

func (s *Store) SaveOutput(ctx context.Context, sessionID, commandID string, stdout, stderr []byte, stdoutTotal, stderrTotal int64, stdoutTrunc, stderrTrunc bool) error {
	if s.output == nil {
		return fmt.Errorf("output store not configured")
	}
	return s.output.SaveOutput(ctx, sessionID, commandID, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc)
}

func (s *Store) ReadOutputChunk(ctx context.Context, commandID string, stream string, offset, limit int64) ([]byte, int64, bool, error) {
	if s.output == nil {
		return nil, 0, false, fmt.Errorf("output store not configured")
	}
	return s.output.ReadOutputChunk(ctx, commandID, stream, offset, limit)
}

func (s *Store) Close() error {
	var firstErr error
	if err := s.primary.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	for _, o := range s.others {
		if err := o.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

