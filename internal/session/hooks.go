package session

import (
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/pkg/types"
)

// LifecycleHooks provides callbacks for session lifecycle events.
type LifecycleHooks struct {
	// OnBeforeStart is called before session starts.
	// Return an error to prevent session from starting.
	OnBeforeStart func(session *Session) error

	// OnStart is called when session enters running state.
	OnStart func(session *Session)

	// OnOperation is called on every intercepted operation (high frequency).
	OnOperation func(session *Session, event *platform.IOEvent)

	// OnBlocked is called when an operation is blocked by policy.
	OnBlocked func(session *Session, event *platform.IOEvent)

	// OnApprovalNeeded is called when manual approval is required.
	OnApprovalNeeded func(session *Session, op *platform.InterceptedOperation)

	// OnApprovalResolved is called when an approval request is resolved.
	OnApprovalResolved func(session *Session, op *platform.InterceptedOperation, approved bool)

	// OnHeartbeat is called periodically for stats collection.
	OnHeartbeat func(session *Session)

	// OnPause is called when session is pausing.
	OnPause func(session *Session)

	// OnResume is called when session is resuming.
	OnResume func(session *Session)

	// OnBeforeEnd is called before session terminates.
	OnBeforeEnd func(session *Session)

	// OnEnd is called after session ends.
	OnEnd func(session *Session, result types.SessionResult)

	// OnError is called on crash/error.
	OnError func(session *Session, err error)

	// OnCheckpoint is called when a checkpoint is created.
	OnCheckpoint func(session *Session, checkpoint *Checkpoint)

	// OnStatsUpdate is called when session stats are updated.
	OnStatsUpdate func(session *Session, stats *types.SessionStats)
}

// DefaultHooks returns lifecycle hooks with no-op implementations.
func DefaultHooks() *LifecycleHooks {
	return &LifecycleHooks{}
}

// Merge combines two LifecycleHooks, calling both callbacks in order.
func (h *LifecycleHooks) Merge(other *LifecycleHooks) *LifecycleHooks {
	if other == nil {
		return h
	}
	if h == nil {
		return other
	}

	return &LifecycleHooks{
		OnBeforeStart: chainBeforeStart(h.OnBeforeStart, other.OnBeforeStart),
		OnStart:       chain(h.OnStart, other.OnStart),
		OnOperation:   chainIOEvent(h.OnOperation, other.OnOperation),
		OnBlocked:     chainIOEvent(h.OnBlocked, other.OnBlocked),
		OnApprovalNeeded: chainApproval(h.OnApprovalNeeded, other.OnApprovalNeeded),
		OnApprovalResolved: chainApprovalResolved(h.OnApprovalResolved, other.OnApprovalResolved),
		OnHeartbeat:   chain(h.OnHeartbeat, other.OnHeartbeat),
		OnPause:       chain(h.OnPause, other.OnPause),
		OnResume:      chain(h.OnResume, other.OnResume),
		OnBeforeEnd:   chain(h.OnBeforeEnd, other.OnBeforeEnd),
		OnEnd:         chainEnd(h.OnEnd, other.OnEnd),
		OnError:       chainError(h.OnError, other.OnError),
		OnCheckpoint:  chainCheckpoint(h.OnCheckpoint, other.OnCheckpoint),
		OnStatsUpdate: chainStats(h.OnStatsUpdate, other.OnStatsUpdate),
	}
}

// Helper functions for chaining callbacks

func chainBeforeStart(a, b func(*Session) error) func(*Session) error {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *Session) error {
		if err := a(s); err != nil {
			return err
		}
		return b(s)
	}
}

func chain(a, b func(*Session)) func(*Session) {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *Session) {
		a(s)
		b(s)
	}
}

func chainIOEvent(a, b func(*Session, *platform.IOEvent)) func(*Session, *platform.IOEvent) {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *Session, e *platform.IOEvent) {
		a(s, e)
		b(s, e)
	}
}

func chainApproval(a, b func(*Session, *platform.InterceptedOperation)) func(*Session, *platform.InterceptedOperation) {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *Session, op *platform.InterceptedOperation) {
		a(s, op)
		b(s, op)
	}
}

func chainApprovalResolved(a, b func(*Session, *platform.InterceptedOperation, bool)) func(*Session, *platform.InterceptedOperation, bool) {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *Session, op *platform.InterceptedOperation, approved bool) {
		a(s, op, approved)
		b(s, op, approved)
	}
}

func chainEnd(a, b func(*Session, types.SessionResult)) func(*Session, types.SessionResult) {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *Session, r types.SessionResult) {
		a(s, r)
		b(s, r)
	}
}

func chainError(a, b func(*Session, error)) func(*Session, error) {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *Session, err error) {
		a(s, err)
		b(s, err)
	}
}

func chainCheckpoint(a, b func(*Session, *Checkpoint)) func(*Session, *Checkpoint) {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *Session, cp *Checkpoint) {
		a(s, cp)
		b(s, cp)
	}
}

func chainStats(a, b func(*Session, *types.SessionStats)) func(*Session, *types.SessionStats) {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *Session, stats *types.SessionStats) {
		a(s, stats)
		b(s, stats)
	}
}
