// internal/platform/darwin/policysock/sessions.go
//go:build darwin

package policysock

import (
	"sync"
)

const maxParentWalkDepth = 10

// SessionTracker tracks which processes belong to which sessions.
type SessionTracker struct {
	mu sync.RWMutex

	// pid -> sessionID (direct registration or cached from parent walk)
	pidToSession map[int32]string

	// pid -> parent pid (for parent walk)
	pidToParent map[int32]int32

	// sessionID -> set of pids (for cleanup on session end)
	sessionToPids map[string]map[int32]struct{}

	// sessionID -> root PID (first PID registered for the session)
	sessionRootPID map[string]int32
}

// NewSessionTracker creates a new session tracker.
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		pidToSession:   make(map[int32]string),
		pidToParent:    make(map[int32]int32),
		sessionToPids:  make(map[string]map[int32]struct{}),
		sessionRootPID: make(map[string]int32),
	}
}

// RegisterProcess adds a process to a session.
func (t *SessionTracker) RegisterProcess(sessionID string, pid, ppid int32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pidToSession[pid] = sessionID
	if ppid > 0 {
		t.pidToParent[pid] = ppid
	}

	if t.sessionToPids[sessionID] == nil {
		t.sessionToPids[sessionID] = make(map[int32]struct{})
	}
	t.sessionToPids[sessionID][pid] = struct{}{}

	// Track root PID (first PID registered for this session)
	if _, exists := t.sessionRootPID[sessionID]; !exists {
		t.sessionRootPID[sessionID] = pid
	}
}

// SetParent records a parent-child relationship (from fork events).
func (t *SessionTracker) SetParent(pid, ppid int32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pidToParent[pid] = ppid
}

// UnregisterProcess removes a process (on exit).
func (t *SessionTracker) UnregisterProcess(pid int32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	sessionID := t.pidToSession[pid]
	delete(t.pidToSession, pid)
	delete(t.pidToParent, pid)

	if sessionID != "" && t.sessionToPids[sessionID] != nil {
		delete(t.sessionToPids[sessionID], pid)
	}
}

// EndSession removes all processes for a session.
func (t *SessionTracker) EndSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	pids := t.sessionToPids[sessionID]
	for pid := range pids {
		delete(t.pidToSession, pid)
		delete(t.pidToParent, pid)
	}
	delete(t.sessionToPids, sessionID)
}

// SessionForPID returns the session ID for a process, walking parents if needed.
func (t *SessionTracker) SessionForPID(pid int32) string {
	// Use write lock for entire operation to avoid race condition between
	// releasing read lock and acquiring write lock for caching.
	t.mu.Lock()
	defer t.mu.Unlock()

	// Fast path: direct lookup
	if sessionID, ok := t.pidToSession[pid]; ok {
		return sessionID
	}

	// Slow path: walk parent chain
	current := pid
	visited := make([]int32, 0, maxParentWalkDepth)
	visitedSet := make(map[int32]struct{}, maxParentWalkDepth)

	for i := 0; i < maxParentWalkDepth; i++ {
		ppid, ok := t.pidToParent[current]
		if !ok || ppid <= 0 {
			break
		}

		// Cycle detection: break if we've seen this parent before
		if _, seen := visitedSet[ppid]; seen {
			break
		}

		visited = append(visited, current)
		visitedSet[current] = struct{}{}

		if sessionID, ok := t.pidToSession[ppid]; ok {
			// Cache the result for all visited pids
			for _, v := range visited {
				t.pidToSession[v] = sessionID
				if t.sessionToPids[sessionID] == nil {
					t.sessionToPids[sessionID] = make(map[int32]struct{})
				}
				t.sessionToPids[sessionID][v] = struct{}{}
			}
			return sessionID
		}

		current = ppid
	}

	return ""
}

// LatestSession returns the most recently registered session ID and its root PID.
// Returns empty string and 0 if no sessions are registered.
func (t *SessionTracker) LatestSession() (sessionID string, rootPID int32) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for sid, pid := range t.sessionRootPID {
		sessionID = sid
		rootPID = pid
	}
	return
}

// RootPIDForSession returns the root PID for a session ID.
func (t *SessionTracker) RootPIDForSession(sessionID string) int32 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessionRootPID[sessionID]
}

// RegisterSession implements SessionRegistrar by registering the root PID
// for a session. This is called when the system extension registers a session.
func (t *SessionTracker) RegisterSession(rootPID int32, sessionID string) {
	t.RegisterProcess(sessionID, rootPID, 0)
}

// UnregisterSession implements SessionRegistrar by ending the session
// associated with the given root PID.
func (t *SessionTracker) UnregisterSession(rootPID int32) {
	t.mu.Lock()
	sessionID := t.pidToSession[rootPID]
	t.mu.Unlock()

	if sessionID != "" {
		t.EndSession(sessionID)
	}
}

// MutePath implements SessionRegistrar. It is a no-op in the daemon; the
// actual es_mute_path call must happen in the system extension process.
func (t *SessionTracker) MutePath(_ string) {}

// Compile-time interface checks
var _ SessionResolver = (*SessionTracker)(nil)
var _ SessionRegistrar = (*SessionTracker)(nil)
