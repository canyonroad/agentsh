//go:build !windows

// internal/signal/registry.go
package signal

import (
	"sync"
)

// PIDRegistry tracks process membership in a session.
type PIDRegistry struct {
	mu            sync.RWMutex
	sessionID     string
	supervisorPID int

	// pid -> parent pid
	parents map[int]int
	// pid -> command name
	commands map[int]string
	// pid -> child pids
	children map[int][]int
}

// NewPIDRegistry creates a new registry for a session.
func NewPIDRegistry(sessionID string, supervisorPID int) *PIDRegistry {
	return &PIDRegistry{
		sessionID:     sessionID,
		supervisorPID: supervisorPID,
		parents:       make(map[int]int),
		commands:      make(map[int]string),
		children:      make(map[int][]int),
	}
}

// Register adds a process to the session.
func (r *PIDRegistry) Register(pid, parentPID int, command string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.parents[pid] = parentPID
	r.commands[pid] = command
	r.children[parentPID] = append(r.children[parentPID], pid)
}

// Unregister removes a process from the session.
func (r *PIDRegistry) Unregister(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	parentPID := r.parents[pid]
	delete(r.parents, pid)
	delete(r.commands, pid)

	// Remove from parent's children
	if children, ok := r.children[parentPID]; ok {
		for i, child := range children {
			if child == pid {
				r.children[parentPID] = append(children[:i], children[i+1:]...)
				break
			}
		}
	}
	delete(r.children, pid)
}

// InSession checks if a PID is part of this session.
func (r *PIDRegistry) InSession(pid int) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if pid == r.supervisorPID {
		return true
	}
	_, ok := r.parents[pid]
	return ok
}

// ClassifyTarget determines the relationship between source and target PIDs.
func (r *PIDRegistry) ClassifyTarget(sourcePID, targetPID int) *TargetContext {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ctx := &TargetContext{
		SourcePID: sourcePID,
		TargetPID: targetPID,
		TargetCmd: r.commands[targetPID],
		InSession: r.inSessionLocked(targetPID),
		SameUser:  true, // TODO: check actual user
	}

	// Self
	if sourcePID == targetPID {
		return ctx
	}

	// Parent (supervisor or direct parent)
	if targetPID == r.supervisorPID {
		ctx.IsParent = true
		return ctx
	}
	if r.parents[sourcePID] == targetPID {
		ctx.IsParent = true
		return ctx
	}

	// Direct child
	if r.parents[targetPID] == sourcePID {
		ctx.IsChild = true
		ctx.IsDescendant = true
		return ctx
	}

	// Descendant (grandchild, etc.)
	if r.isDescendantLocked(sourcePID, targetPID) {
		ctx.IsDescendant = true
		return ctx
	}

	// Sibling (same parent)
	if r.parents[sourcePID] == r.parents[targetPID] && r.parents[sourcePID] != 0 {
		ctx.IsSibling = true
		return ctx
	}

	return ctx
}

func (r *PIDRegistry) inSessionLocked(pid int) bool {
	if pid == r.supervisorPID {
		return true
	}
	_, ok := r.parents[pid]
	return ok
}

func (r *PIDRegistry) isDescendantLocked(ancestorPID, pid int) bool {
	current := pid
	for {
		parent, ok := r.parents[current]
		if !ok {
			return false
		}
		if parent == ancestorPID {
			return true
		}
		current = parent
	}
}

// SupervisorPID returns the supervisor PID.
func (r *PIDRegistry) SupervisorPID() int {
	return r.supervisorPID
}

// SessionID returns the session ID.
func (r *PIDRegistry) SessionID() string {
	return r.sessionID
}
