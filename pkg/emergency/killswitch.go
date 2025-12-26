package emergency

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Session represents a manageable session.
type Session interface {
	ID() string
	Kill(reason string) error
}

// SessionManager manages sessions.
type SessionManager interface {
	ListAll() []Session
	Disable() error
	Enable() error
	IsDisabled() bool
}

// KillSwitch provides emergency termination of all sessions.
type KillSwitch struct {
	activated  atomic.Bool
	sessionMgr SessionManager
	notifier   Notifier
	auditLog   AuditLogger
	mu         sync.Mutex
	state      *KillSwitchState
}

// KillSwitchState represents the kill switch state.
type KillSwitchState struct {
	Activated        bool      `json:"activated"`
	ActivatedAt      time.Time `json:"activated_at,omitempty"`
	ActivatedBy      string    `json:"activated_by,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	SessionsKilled   int       `json:"sessions_killed"`
	NotifyChannels   []string  `json:"-"`
}

// KillSwitchConfig configures the kill switch.
type KillSwitchConfig struct {
	NotifyChannels []string `yaml:"notify_channels" json:"notify_channels"`
}

// NewKillSwitch creates a new kill switch.
func NewKillSwitch(sessionMgr SessionManager, notifier Notifier, auditLog AuditLogger) *KillSwitch {
	return &KillSwitch{
		sessionMgr: sessionMgr,
		notifier:   notifier,
		auditLog:   auditLog,
	}
}

// KillAllRequest is a request to kill all sessions.
type KillAllRequest struct {
	Reason         string   `json:"reason"`
	Actor          string   `json:"actor"`
	NotifyChannels []string `json:"notify_channels,omitempty"`
}

// KillAllResult is the result of killing all sessions.
type KillAllResult struct {
	SessionsKilled int       `json:"sessions_killed"`
	ActivatedAt    time.Time `json:"activated_at"`
	Message        string    `json:"message"`
}

// Activate activates the kill switch, terminating all sessions.
func (k *KillSwitch) Activate(ctx context.Context, req KillAllRequest) (*KillAllResult, error) {
	if !k.activated.CompareAndSwap(false, true) {
		return nil, ErrAlreadyActivated
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	now := time.Now()

	// Get all sessions
	var sessions []Session
	if k.sessionMgr != nil {
		sessions = k.sessionMgr.ListAll()
	}

	// Kill all sessions
	killed := 0
	for _, session := range sessions {
		if err := session.Kill("kill_switch: " + req.Reason); err == nil {
			killed++
		}
	}

	// Disable new sessions
	if k.sessionMgr != nil {
		k.sessionMgr.Disable()
	}

	k.state = &KillSwitchState{
		Activated:      true,
		ActivatedAt:    now,
		ActivatedBy:    req.Actor,
		Reason:         req.Reason,
		SessionsKilled: killed,
		NotifyChannels: req.NotifyChannels,
	}

	// Log activation
	if k.auditLog != nil {
		k.auditLog.LogBreakGlassActivation(
			fmt.Sprintf("killswitch_%s", now.Format("20060102_150405")),
			req.Actor,
			req.Reason,
			0,
		)
	}

	// Send alerts
	if k.notifier != nil && len(req.NotifyChannels) > 0 {
		msg := fmt.Sprintf("🚨 KILL SWITCH ACTIVATED\nReason: %s\nActivated by: %s\nSessions killed: %d\nNew sessions: DISABLED",
			req.Reason, req.Actor, killed)
		k.notifier.Notify(ctx, req.NotifyChannels, msg)
	}

	return &KillAllResult{
		SessionsKilled: killed,
		ActivatedAt:    now,
		Message:        fmt.Sprintf("Kill switch activated. %d sessions terminated. New sessions disabled.", killed),
	}, nil
}

// Reset resets the kill switch, allowing new sessions.
func (k *KillSwitch) Reset(ctx context.Context, actor string) error {
	if !k.activated.Load() {
		return fmt.Errorf("kill switch is not activated")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	// Re-enable sessions
	if k.sessionMgr != nil {
		if err := k.sessionMgr.Enable(); err != nil {
			return fmt.Errorf("enabling sessions: %w", err)
		}
	}

	// Send notification
	if k.notifier != nil && k.state != nil && len(k.state.NotifyChannels) > 0 {
		msg := fmt.Sprintf("✓ Kill switch reset by %s\nNew sessions: ENABLED", actor)
		k.notifier.Notify(ctx, k.state.NotifyChannels, msg)
	}

	k.state.Activated = false
	k.activated.Store(false)

	return nil
}

// Status returns the current kill switch status.
func (k *KillSwitch) Status() *KillSwitchState {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.state == nil {
		return &KillSwitchState{Activated: false}
	}

	return &KillSwitchState{
		Activated:      k.state.Activated,
		ActivatedAt:    k.state.ActivatedAt,
		ActivatedBy:    k.state.ActivatedBy,
		Reason:         k.state.Reason,
		SessionsKilled: k.state.SessionsKilled,
	}
}

// IsActivated returns whether the kill switch is currently activated.
func (k *KillSwitch) IsActivated() bool {
	return k.activated.Load()
}

// ErrAlreadyActivated is returned when the kill switch is already activated.
var ErrAlreadyActivated = fmt.Errorf("kill switch already activated")
