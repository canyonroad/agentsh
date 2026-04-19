package composite

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
)

// Store fans an event out to a primary EventStore plus zero-or-more chained
// sinks while owning the shared sequence allocator that stamps ev.Chain.
//
// Concurrency model:
//
//   - mu is a sync.RWMutex held outermost in this package. AppendEvent takes
//     mu.RLock() for the duration of allocator.Next() AND the entire fanout
//     so concurrent appends do not serialize against each other but DO
//     serialize against the rotation paths.
//   - NextGeneration takes mu.Lock(): it cannot return until every in-flight
//     AppendEvent has completed its fanout, AND no new AppendEvent may begin
//     until the rotation finishes. This is what makes the spec's "all chained
//     sinks roll on the same logical event boundary" guarantee enforceable
//     rather than aspirational — without it, an in-flight AppendEvent could
//     stamp ev.Chain with the OLD generation while a sink that has already
//     rekeyed observes the NEW generation, exactly the backwards-generation
//     race SinkChain.Commit is designed to reject.
//   - State and Restore take mu.Lock() so the snapshot reflects a state that
//     no AppendEvent fanout is partway through and no NextGeneration is
//     partway through.
//
// The allocator carries its own internal mutex — that is fine because the
// allocator never calls back into the wrapper; lock order is always
// composite.mu (outer) → allocator.mu (inner).
//
// This matches the wrapper-level mutex discipline established for
// audit.IntegrityChain in commit 915251c7.
type Store struct {
	mu            sync.RWMutex
	primary       store.EventStore
	output        store.OutputStore
	others        []store.EventStore
	allocator     *audit.SequenceAllocator
	onAppendError func(error)
}

func New(primary store.EventStore, output store.OutputStore, others ...store.EventStore) *Store {
	return &Store{
		primary:   primary,
		output:    output,
		others:    others,
		allocator: audit.NewSequenceAllocator(),
	}
}

func (s *Store) SetAppendErrorHook(fn func(error)) {
	s.onAppendError = fn
}

// AppendEvent allocates the shared (sequence, generation), stamps a
// per-sink-fresh ev.Chain, and fans out to every configured sink.
//
// Pre-fanout sequence semantics: the shared sequence advances eagerly on
// every successful allocator.Next() call, regardless of whether any sink
// accepts the event. This matches the spec's TransportLoss semantics —
// the shared sequence reflects what the system PRODUCED, not what each
// sink DELIVERED. A sink that drops an event still observes a gap and
// must emit its own loss marker.
//
// If allocator.Next() itself fails (overflow), no sequence is consumed
// and the event is rejected before any sink sees it. The error is wrapped
// as *store.FatalIntegrityError with Op == "audit sequence allocate" and
// delivered through the onAppendError hook so the daemon's fatal-audit
// watcher observes it (matching the convention used elsewhere in this
// package; see internal/store/integrity_wrapper.go).
//
// Holds mu.RLock() for the entire stamp+fanout duration so NextGeneration
// (which takes mu.Lock()) cannot interleave: any rotation that begins
// after this AppendEvent started will block until this fanout completes,
// guaranteeing the stamped ev.Chain.Generation is the generation in
// effect at allocation time and that the same generation is observed by
// every sink in this fanout.
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seq, gen, err := s.allocator.Next()
	if err != nil {
		fatalErr := &store.FatalIntegrityError{Op: "audit sequence allocate", Err: err}
		if s.onAppendError != nil {
			s.onAppendError(fatalErr)
		}
		return fatalErr
	}

	// stampForSink returns ev with a FRESH *ChainState pointer so no two
	// sinks ever alias the same ChainState. This is the per-sink-copy
	// guarantee that prevents one sink's mutation from corrupting another.
	stampForSink := func() types.Event {
		stamped := ev
		stamped.Chain = &types.ChainState{Sequence: uint64(seq), Generation: gen}
		return stamped
	}

	var firstErr error
	var hookErr error
	if s.primary != nil {
		if err := s.primary.AppendEvent(ctx, stampForSink()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if hookErr == nil {
				hookErr = err
			}
			var fatal *store.FatalIntegrityError
			if errors.As(err, &fatal) {
				hookErr = fatal
			}
		}
	}
	for _, o := range s.others {
		if err := o.AppendEvent(ctx, stampForSink()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if hookErr == nil {
				hookErr = err
			}
			var fatal *store.FatalIntegrityError
			if errors.As(err, &fatal) {
				hookErr = fatal
			}
		}
	}
	if hookErr != nil && s.onAppendError != nil {
		s.onAppendError(hookErr)
	}
	return firstErr
}

// NextGeneration advances the shared sequence generation. The next
// AppendEvent stamps ev.Chain with (Sequence:0, Generation:newGen).
// Used by the composite owner when the chain key rotates.
//
// Acquires mu.Lock() so the rotation cannot interleave with any in-flight
// AppendEvent fanout: this method blocks until every concurrent
// AppendEvent (which holds mu.RLock()) has completed, AND no new
// AppendEvent may begin until this method returns. After return, every
// subsequent AppendEvent stamps the new generation; there is no window
// where a stamped (seq, oldGen) event can race against sink rekeying.
//
// Returns ErrGenerationOverflow on uint32 wrap; the allocator is not
// modified in that case (see audit.SequenceAllocator.NextGeneration).
func (s *Store) NextGeneration() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allocator.NextGeneration()
}

// State returns the allocator's current (sequence, generation) for
// persistence. Acquires mu.Lock() so the snapshot is taken while no
// AppendEvent is mid-fanout and no NextGeneration is in progress —
// the returned state is a consistent view of where the chain is.
func (s *Store) State() audit.AllocatorState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allocator.State()
}

// Restore rehydrates the allocator state after restart. Returns an error
// wrapping audit.ErrInvalidAllocatorState on rejected input; the wrapper
// is not modified in that case (delegated guarantee from
// SequenceAllocator.Restore).
//
// Acquires mu.Lock() so Restore is serialized with both AppendEvent
// fanout and NextGeneration. Phase 0 only adds the API; daemon wiring
// for persist+restore across process restarts is out of scope.
func (s *Store) Restore(state audit.AllocatorState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allocator.Restore(state)
}

func (s *Store) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	if s.primary == nil {
		return nil, nil
	}
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
	if s.primary != nil {
		if err := s.primary.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
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

// ListMCPTools delegates to the primary SQLite store to query MCP tools.
func (s *Store) ListMCPTools(ctx context.Context, filter sqlite.MCPToolFilter) ([]sqlite.MCPTool, error) {
	sqliteStore, ok := s.primary.(*sqlite.Store)
	if !ok {
		return nil, fmt.Errorf("MCP queries not supported by primary store")
	}
	return sqliteStore.ListMCPTools(ctx, filter)
}

// ListMCPServers delegates to the primary SQLite store to query MCP server summaries.
func (s *Store) ListMCPServers(ctx context.Context) ([]sqlite.MCPServerSummary, error) {
	sqliteStore, ok := s.primary.(*sqlite.Store)
	if !ok {
		return nil, fmt.Errorf("MCP queries not supported by primary store")
	}
	return sqliteStore.ListMCPServers(ctx)
}
