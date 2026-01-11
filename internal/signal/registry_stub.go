//go:build windows

package signal

// PIDRegistry tracks processes in a session for signal classification.
type PIDRegistry struct{}

// NewPIDRegistry creates a new PID registry.
func NewPIDRegistry(sessionID string, supervisorPID int) *PIDRegistry {
	return nil
}

// NewPIDRegistryWithUID creates a new PID registry with UID tracking.
func NewPIDRegistryWithUID(sessionID string, supervisorPID, supervisorUID int) *PIDRegistry {
	return nil
}

// Register registers a process in the registry.
func (r *PIDRegistry) Register(pid, parentPID int, command string) {}

// RegisterWithUID registers a process with UID in the registry.
func (r *PIDRegistry) RegisterWithUID(pid, parentPID int, command string, uid int) {}

// Unregister removes a process from the registry.
func (r *PIDRegistry) Unregister(pid int) {}

// InSession returns whether a PID is in the session.
func (r *PIDRegistry) InSession(pid int) bool {
	return false
}

// ClassifyTarget classifies the target of a signal.
func (r *PIDRegistry) ClassifyTarget(sourcePID, targetPID int) *TargetContext {
	return nil
}

// SupervisorPID returns the supervisor's PID.
func (r *PIDRegistry) SupervisorPID() int {
	return 0
}

// SessionID returns the session ID.
func (r *PIDRegistry) SessionID() string {
	return ""
}
