// internal/platform/darwin/xpc/version.go
package xpc

import "sync"

// SessionVersions tracks per-session monotonic version counters.
// Incremented on any policy change; the Swift SysExt uses version
// to detect stale caches.
type SessionVersions struct {
	mu       sync.Mutex
	versions map[string]uint64
}

func NewSessionVersions() *SessionVersions {
	return &SessionVersions{versions: make(map[string]uint64)}
}

func (sv *SessionVersions) Register(sessionID string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.versions[sessionID] = 1
}

func (sv *SessionVersions) Unregister(sessionID string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	delete(sv.versions, sessionID)
}

// IncrementAll bumps version for all active sessions.
// Called on any policy change.
func (sv *SessionVersions) IncrementAll() {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	for id := range sv.versions {
		sv.versions[id]++
	}
}

func (sv *SessionVersions) Get(sessionID string) uint64 {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	return sv.versions[sessionID]
}
