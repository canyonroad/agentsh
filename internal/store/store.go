package store

import (
	"context"

	"github.com/agentsh/agentsh/pkg/types"
)

type EventStore interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error)
	Close() error
}

// RawWriter can write pre-serialized bytes as a single JSONL line.
type RawWriter interface {
	WriteRaw(ctx context.Context, data []byte) error
}

type OutputStore interface {
	SaveOutput(ctx context.Context, sessionID, commandID string, stdout, stderr []byte, stdoutTotal, stderrTotal int64, stdoutTrunc, stderrTrunc bool) error
	ReadOutputChunk(ctx context.Context, commandID string, stream string, offset, limit int64) (chunk []byte, total int64, truncated bool, err error)
}
