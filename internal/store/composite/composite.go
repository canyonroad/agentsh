package composite

import (
	"context"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/internal/store/sqlite"
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

// UpsertMCPToolFromEvent extracts MCP tool info from an mcp_tool_seen event
// and upserts it to the mcp_tools table.
func (s *Store) UpsertMCPToolFromEvent(ctx context.Context, ev types.Event) error {
	if ev.Type != "mcp_tool_seen" {
		return nil
	}

	// Type assert primary to sqlite.Store which has UpsertMCPTool
	sqliteStore, ok := s.primary.(*sqlite.Store)
	if !ok {
		// Primary store doesn't support MCP tool upsert, skip silently
		return nil
	}

	// Extract tool info from event Fields
	fields := ev.Fields
	if fields == nil {
		return nil
	}

	tool := sqlite.MCPTool{
		ServerID:    stringField(fields, "server_id"),
		ToolName:    stringField(fields, "tool_name"),
		ToolHash:    stringField(fields, "tool_hash"),
		Description: stringField(fields, "description"),
		MaxSeverity: stringField(fields, "max_severity"),
		LastSeen:    ev.Timestamp,
	}

	// Count detections if present
	if detections, ok := fields["detections"].([]any); ok {
		tool.DetectionCount = len(detections)
	}

	if tool.ServerID == "" || tool.ToolName == "" {
		return nil // Missing required fields
	}

	return sqliteStore.UpsertMCPTool(ctx, tool)
}

// stringField extracts a string field from a map, returning empty string if not found.
func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// timeField extracts a time field from a map, returning zero time if not found.
func timeField(m map[string]any, key string) time.Time {
	switch v := m[key].(type) {
	case time.Time:
		return v
	case string:
		t, _ := time.Parse(time.RFC3339Nano, v)
		return t
	}
	return time.Time{}
}
