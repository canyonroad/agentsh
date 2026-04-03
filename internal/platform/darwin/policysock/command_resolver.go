//go:build darwin

package policysock

import "sync"

// CommandResolver maps process PIDs to command IDs.
// Thread-safe for concurrent reads and writes.
type CommandResolver struct {
	mu   sync.RWMutex
	pids map[int32]string // PID -> command_id
}

// NewCommandResolver creates a new empty resolver.
func NewCommandResolver() *CommandResolver {
	return &CommandResolver{pids: make(map[int32]string)}
}

// RegisterCommand associates a PID with a command ID.
// Called by the exec handler after cmd.Start().
func (cr *CommandResolver) RegisterCommand(pid int32, commandID string) {
	cr.mu.Lock()
	cr.pids[pid] = commandID
	cr.mu.Unlock()
}

// RegisterFork associates a child PID with the same command ID as its parent.
// If the parent PID is unknown, the child is not registered.
func (cr *CommandResolver) RegisterFork(parentPID, childPID int32) {
	cr.mu.Lock()
	if cmdID, ok := cr.pids[parentPID]; ok {
		cr.pids[childPID] = cmdID
	}
	cr.mu.Unlock()
}

// UnregisterPID removes a PID from the resolver.
func (cr *CommandResolver) UnregisterPID(pid int32) {
	cr.mu.Lock()
	delete(cr.pids, pid)
	cr.mu.Unlock()
}

// CommandForPID returns the command ID for a PID, or empty string if unknown.
func (cr *CommandResolver) CommandForPID(pid int32) string {
	cr.mu.RLock()
	cmdID := cr.pids[pid]
	cr.mu.RUnlock()
	return cmdID
}
