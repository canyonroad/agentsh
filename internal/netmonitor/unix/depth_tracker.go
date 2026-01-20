// internal/netmonitor/unix/depth_tracker.go
package unix

import "sync"

// ExecveState holds depth and session info for a PID.
type ExecveState struct {
	Depth     int
	SessionID string
}

// DepthTracker tracks execution depth per PID.
type DepthTracker struct {
	mu    sync.RWMutex
	state map[int]ExecveState
}

// NewDepthTracker creates a new depth tracker.
func NewDepthTracker() *DepthTracker {
	return &DepthTracker{
		state: make(map[int]ExecveState),
	}
}

// RegisterSession registers the root process of a session.
// The root is registered at depth -1 so that the first command (direct)
// executed from it will be at depth 0, matching policy semantics where
// 0 = direct (user-typed) and 1+ = nested (script-spawned).
func (dt *DepthTracker) RegisterSession(pid int, sessionID string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	dt.state[pid] = ExecveState{
		Depth:     -1, // First child will be depth 0 (direct)
		SessionID: sessionID,
	}
}

// RecordExecve records a new process, inheriting depth+1 from parent.
// If the PID already has state (e.g., from RegisterSession or re-exec),
// it preserves the session ID when the parent is unknown.
func (dt *DepthTracker) RecordExecve(pid int, parentPID int) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	parentState, ok := dt.state[parentPID]
	if !ok {
		// Unknown parent - check if PID already has state (re-exec case)
		// Preserve existing session ID if present
		existing, hasExisting := dt.state[pid]
		if hasExisting {
			// Re-exec: preserve session ID and depth from existing state
			dt.state[pid] = ExecveState{
				Depth:     existing.Depth,
				SessionID: existing.SessionID,
			}
		} else {
			// Truly unknown - start at depth 0
			dt.state[pid] = ExecveState{
				Depth:     0,
				SessionID: "",
			}
		}
		return
	}

	dt.state[pid] = ExecveState{
		Depth:     parentState.Depth + 1,
		SessionID: parentState.SessionID,
	}
}

// Get returns the state for a PID.
func (dt *DepthTracker) Get(pid int) (ExecveState, bool) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	state, ok := dt.state[pid]
	return state, ok
}

// Cleanup removes a PID from tracking.
func (dt *DepthTracker) Cleanup(pid int) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	delete(dt.state, pid)
}

// CleanupSession removes all PIDs for a session.
func (dt *DepthTracker) CleanupSession(sessionID string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	for pid, state := range dt.state {
		if state.SessionID == sessionID {
			delete(dt.state, pid)
		}
	}
}
