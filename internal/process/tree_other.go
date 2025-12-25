//go:build !linux && !darwin && !windows

package process

import (
	"context"
	"fmt"
	"os"
)

// NoopProcessTracker is a no-op implementation for unsupported platforms.
type NoopProcessTracker struct {
	rootPID int
}

func newPlatformTracker() ProcessTracker {
	return &NoopProcessTracker{}
}

// Track implements ProcessTracker.
func (t *NoopProcessTracker) Track(pid int) error {
	t.rootPID = pid
	return fmt.Errorf("process tracking not supported on this platform")
}

// ListPIDs implements ProcessTracker.
func (t *NoopProcessTracker) ListPIDs() []int {
	if t.rootPID != 0 {
		return []int{t.rootPID}
	}
	return nil
}

// Contains implements ProcessTracker.
func (t *NoopProcessTracker) Contains(pid int) bool {
	return pid == t.rootPID
}

// KillAll implements ProcessTracker.
func (t *NoopProcessTracker) KillAll(signal os.Signal) error {
	return fmt.Errorf("process tracking not supported on this platform")
}

// Wait implements ProcessTracker.
func (t *NoopProcessTracker) Wait(ctx context.Context) error {
	return fmt.Errorf("process tracking not supported on this platform")
}

// Info implements ProcessTracker.
func (t *NoopProcessTracker) Info(pid int) (*ProcessInfo, error) {
	return nil, fmt.Errorf("process tracking not supported on this platform")
}

// OnSpawn implements ProcessTracker.
func (t *NoopProcessTracker) OnSpawn(cb func(pid, ppid int)) {}

// OnExit implements ProcessTracker.
func (t *NoopProcessTracker) OnExit(cb func(pid, exitCode int)) {}

// Stop implements ProcessTracker.
func (t *NoopProcessTracker) Stop() error {
	return nil
}

// Capabilities returns tracker capabilities.
func (t *NoopProcessTracker) Capabilities() TrackerCapabilities {
	return TrackerCapabilities{}
}

var _ ProcessTracker = (*NoopProcessTracker)(nil)
