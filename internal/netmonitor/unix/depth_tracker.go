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

// RegisterSession registers the root process of a session at depth 0.
func (dt *DepthTracker) RegisterSession(pid int, sessionID string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	dt.state[pid] = ExecveState{
		Depth:     0,
		SessionID: sessionID,
	}
}

// RecordExecve records a new process, inheriting depth+1 from parent.
func (dt *DepthTracker) RecordExecve(pid int, parentPID int) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	parentState, ok := dt.state[parentPID]
	if !ok {
		// Unknown parent - start at depth 0
		dt.state[pid] = ExecveState{
			Depth:     0,
			SessionID: "",
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
