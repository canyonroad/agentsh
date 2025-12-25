package session

import (
	"context"
	"sync"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

// ShutdownConfig configures graceful shutdown behavior.
type ShutdownConfig struct {
	// ApprovalTimeout is how long to wait for pending approvals
	ApprovalTimeout time.Duration

	// GracePeriod is how long to wait for graceful exit after SIGTERM
	GracePeriod time.Duration

	// DrainTimeout is how long to wait for pending operations to complete
	DrainTimeout time.Duration
}

// DefaultShutdownConfig returns sensible defaults for shutdown.
func DefaultShutdownConfig() ShutdownConfig {
	return ShutdownConfig{
		ApprovalTimeout: 30 * time.Second,
		GracePeriod:     10 * time.Second,
		DrainTimeout:    5 * time.Second,
	}
}

// ShutdownReason indicates why a session is being shut down.
type ShutdownReason string

const (
	ShutdownReasonNormal   ShutdownReason = "normal"   // Normal completion
	ShutdownReasonTimeout  ShutdownReason = "timeout"  // Session timeout
	ShutdownReasonManual   ShutdownReason = "manual"   // Manual shutdown request
	ShutdownReasonPolicy   ShutdownReason = "policy"   // Policy violation
	ShutdownReasonError    ShutdownReason = "error"    // Error/crash
	ShutdownReasonResource ShutdownReason = "resource" // Resource limit exceeded
)

// SessionShutdown manages graceful shutdown of a session.
type SessionShutdown struct {
	session *Session
	config  ShutdownConfig
	hooks   *LifecycleHooks

	mu           sync.Mutex
	drainMode    bool
	pendingOps   int
	pendingCond  *sync.Cond
	shutdownOnce sync.Once
}

// NewSessionShutdown creates a shutdown manager for the session.
func NewSessionShutdown(session *Session, config ShutdownConfig, hooks *LifecycleHooks) *SessionShutdown {
	sd := &SessionShutdown{
		session: session,
		config:  config,
		hooks:   hooks,
	}
	sd.pendingCond = sync.NewCond(&sd.mu)
	return sd
}

// SetDrainMode enables or disables drain mode.
// In drain mode, new operations are rejected.
func (sd *SessionShutdown) SetDrainMode(enabled bool) {
	sd.mu.Lock()
	sd.drainMode = enabled
	sd.mu.Unlock()
}

// IsDraining returns true if the session is draining.
func (sd *SessionShutdown) IsDraining() bool {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	return sd.drainMode
}

// BeginOperation marks the start of an operation.
// Returns false if the session is draining and not accepting new operations.
func (sd *SessionShutdown) BeginOperation() bool {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	if sd.drainMode {
		return false
	}
	sd.pendingOps++
	return true
}

// EndOperation marks the end of an operation.
func (sd *SessionShutdown) EndOperation() {
	sd.mu.Lock()
	sd.pendingOps--
	if sd.pendingOps <= 0 {
		sd.pendingCond.Broadcast()
	}
	sd.mu.Unlock()
}

// WaitPending waits for all pending operations to complete.
func (sd *SessionShutdown) WaitPending(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		sd.mu.Lock()
		for sd.pendingOps > 0 {
			sd.pendingCond.Wait()
		}
		sd.mu.Unlock()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown performs a graceful shutdown of the session.
func (sd *SessionShutdown) Shutdown(ctx context.Context, reason ShutdownReason) error {
	var err error
	sd.shutdownOnce.Do(func() {
		err = sd.doShutdown(ctx, reason)
	})
	return err
}

func (sd *SessionShutdown) doShutdown(ctx context.Context, reason ShutdownReason) error {
	// 1. Set state to terminating
	sd.session.mu.Lock()
	sd.session.State = types.SessionStateTerminating
	sd.session.mu.Unlock()

	// Call OnBeforeEnd hook
	if sd.hooks != nil && sd.hooks.OnBeforeEnd != nil {
		sd.hooks.OnBeforeEnd(sd.session)
	}

	// 2. Stop accepting new operations (drain mode)
	sd.SetDrainMode(true)

	// 3. Wait for pending approvals (with timeout)
	if sd.config.ApprovalTimeout > 0 {
		approvalCtx, cancel := context.WithTimeout(ctx, sd.config.ApprovalTimeout)
		sd.waitPendingApprovals(approvalCtx)
		cancel()
	}

	// 4. Wait for pending operations to drain
	if sd.config.DrainTimeout > 0 {
		drainCtx, cancel := context.WithTimeout(ctx, sd.config.DrainTimeout)
		sd.WaitPending(drainCtx)
		cancel()
	}

	// 5. Signal the process
	finalState := types.SessionStateCompleted
	sd.session.mu.Lock()
	pid := sd.session.currentProcPID
	sd.session.mu.Unlock()

	if pid > 0 {
		// Send SIGTERM first
		if err := signalProcess(pid, syscall.SIGTERM); err == nil {
			// Wait for graceful exit
			exitCtx, cancel := context.WithTimeout(ctx, sd.config.GracePeriod)
			if !sd.waitProcessExit(exitCtx, pid) {
				// Force kill
				signalProcess(pid, syscall.SIGKILL)
				finalState = types.SessionStateKilled
			}
			cancel()
		}
	}

	// 6. Determine final state based on reason
	switch reason {
	case ShutdownReasonTimeout:
		finalState = types.SessionStateTimedOut
	case ShutdownReasonError:
		finalState = types.SessionStateFailed
	case ShutdownReasonPolicy, ShutdownReasonResource:
		finalState = types.SessionStateKilled
	}

	// 7. Update session state
	sd.session.mu.Lock()
	sd.session.State = finalState
	now := time.Now().UTC()
	sd.session.endedAt = &now
	stats := sd.session.stats
	createdAt := sd.session.CreatedAt
	sd.session.mu.Unlock()

	// 8. Cleanup resources
	sd.session.cleanup()

	// 9. Call OnEnd hook
	if sd.hooks != nil && sd.hooks.OnEnd != nil {
		result := types.SessionResult{
			Duration: now.Sub(createdAt),
			Stats:    stats,
		}
		if finalState == types.SessionStateFailed || finalState == types.SessionStateKilled {
			result.ExitCode = 1
		}
		sd.hooks.OnEnd(sd.session, result)
	}

	return nil
}

// waitPendingApprovals waits for pending approval requests to be resolved.
func (sd *SessionShutdown) waitPendingApprovals(ctx context.Context) {
	// This would integrate with an approval manager
	// For now, just wait for context
	<-ctx.Done()
}

// waitProcessExit waits for a process to exit.
func (sd *SessionShutdown) waitProcessExit(ctx context.Context, pid int) bool {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if !processExists(pid) {
				return true
			}
		}
	}
}

// signalProcess sends a signal to a process.
func signalProcess(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

// processExists checks if a process is still running.
func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}
