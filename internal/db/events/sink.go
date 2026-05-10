package events

import (
	"context"
	"sync"
)

// Sink is the event emission surface for the DB proxy. Implementations may
// fan out to a real audit pipeline (production), to nothing (tests that do
// not care about events), or to an in-memory buffer (unit tests asserting
// emission). Sinks must be safe for concurrent use.
//
// Errors from Emit* are advisory: the proxy logs them at warn but does not
// fail the connection. Spec §8 is silent on emission durability; Plan 04a
// adopts best-effort semantics, leaving durability concerns to the audit-
// pipeline implementation a later plan provides.
type Sink interface {
	EmitStatement(ctx context.Context, ev DBEvent) error
	EmitLifecycle(ctx context.Context, ev LifecycleEvent) error
}

// NopSink discards every event. Useful when the proxy is wired into a
// runtime that does not care about audit (tests of unrelated code).
type NopSink struct{}

func (NopSink) EmitStatement(context.Context, DBEvent) error      { return nil }
func (NopSink) EmitLifecycle(context.Context, LifecycleEvent) error { return nil }

// SyncSink buffers every emitted event in memory. Tests call DrainStatements
// or DrainLifecycle to inspect what was emitted. Concurrent use is safe.
//
// Drain* returns the buffered events in emission order and resets the buffer.
// The returned slice is owned by the caller; subsequent Emit calls do not
// write into it. Callers must not append to the returned slice.
type SyncSink struct {
	mu        sync.Mutex
	stmt      []DBEvent
	lifecycle []LifecycleEvent
}

func (s *SyncSink) EmitStatement(ctx context.Context, ev DBEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.stmt = append(s.stmt, ev)
	s.mu.Unlock()
	return nil
}

func (s *SyncSink) EmitLifecycle(ctx context.Context, ev LifecycleEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.lifecycle = append(s.lifecycle, ev)
	s.mu.Unlock()
	return nil
}

func (s *SyncSink) DrainStatements() []DBEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stmt
	s.stmt = nil
	return out
}

func (s *SyncSink) DrainLifecycle() []LifecycleEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.lifecycle
	s.lifecycle = nil
	return out
}
