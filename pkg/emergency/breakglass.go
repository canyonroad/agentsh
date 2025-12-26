package emergency

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// BreakGlass manages emergency policy bypass.
type BreakGlass struct {
	config     BreakGlassConfig
	state      *BreakGlassState
	mu         sync.RWMutex
	notifier   Notifier
	auditLog   AuditLogger
	mfaVerifier MFAVerifier
}

// BreakGlassConfig configures the break-glass system.
type BreakGlassConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	AuthorizedUsers []string      `yaml:"authorized_users" json:"authorized_users"`
	RequireMFA      bool          `yaml:"require_mfa" json:"require_mfa"`
	MaxDuration     time.Duration `yaml:"max_duration" json:"max_duration"`
	RequireReason   bool          `yaml:"require_reason" json:"require_reason"`
	NotifyChannels  []string      `yaml:"notify_channels" json:"notify_channels"`
	AutoExpire      bool          `yaml:"auto_expire" json:"auto_expire"`
	Permissions     Permissions   `yaml:"permissions" json:"permissions"`
}

// Permissions defines what's allowed during break-glass.
type Permissions struct {
	AllowAllFiles      bool `yaml:"allow_all_files" json:"allow_all_files"`
	AllowAllNetwork    bool `yaml:"allow_all_network" json:"allow_all_network"`
	AllowSensitiveEnv  bool `yaml:"allow_sensitive_env" json:"allow_sensitive_env"`
	LogEverything      bool `yaml:"log_everything" json:"log_everything"`
}

// BreakGlassState represents the current break-glass state.
type BreakGlassState struct {
	Active      bool      `json:"active"`
	AuditID     string    `json:"audit_id"`
	ActivatedAt time.Time `json:"activated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	ActivatedBy string    `json:"activated_by"`
	Reason      string    `json:"reason"`
	Operations  int64     `json:"operations"`
}

// ActivateRequest is a request to activate break-glass.
type ActivateRequest struct {
	User     string        `json:"user"`
	Reason   string        `json:"reason"`
	Duration time.Duration `json:"duration"`
	MFAToken string        `json:"mfa_token,omitempty"`
}

// ActivateResult is the result of activating break-glass.
type ActivateResult struct {
	AuditID     string    `json:"audit_id"`
	ActivatedAt time.Time `json:"activated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Message     string    `json:"message"`
}

// Notifier sends notifications.
type Notifier interface {
	Notify(ctx context.Context, channels []string, message string) error
}

// AuditLogger logs audit events.
type AuditLogger interface {
	LogBreakGlassActivation(auditID, user, reason string, duration time.Duration)
	LogBreakGlassDeactivation(auditID, user string, operationCount int64)
	LogBreakGlassOperation(auditID, opType, details string)
}

// MFAVerifier verifies MFA tokens.
type MFAVerifier interface {
	Verify(user, token string) (bool, error)
}

// NewBreakGlass creates a new break-glass manager.
func NewBreakGlass(config BreakGlassConfig, notifier Notifier, auditLog AuditLogger, mfa MFAVerifier) *BreakGlass {
	return &BreakGlass{
		config:      config,
		notifier:    notifier,
		auditLog:    auditLog,
		mfaVerifier: mfa,
	}
}

// Activate activates break-glass mode.
func (b *BreakGlass) Activate(ctx context.Context, req ActivateRequest) (*ActivateResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.config.Enabled {
		return nil, fmt.Errorf("break-glass is not enabled")
	}

	if b.state != nil && b.state.Active {
		return nil, fmt.Errorf("break-glass already active (audit_id: %s)", b.state.AuditID)
	}

	// Check if user is authorized
	if !b.isAuthorized(req.User) {
		return nil, fmt.Errorf("user %q is not authorized for break-glass", req.User)
	}

	// Require reason if configured
	if b.config.RequireReason && req.Reason == "" {
		return nil, fmt.Errorf("reason is required for break-glass activation")
	}

	// Verify MFA if required
	if b.config.RequireMFA {
		if req.MFAToken == "" {
			return nil, fmt.Errorf("MFA token is required")
		}
		if b.mfaVerifier != nil {
			valid, err := b.mfaVerifier.Verify(req.User, req.MFAToken)
			if err != nil {
				return nil, fmt.Errorf("MFA verification failed: %w", err)
			}
			if !valid {
				return nil, fmt.Errorf("invalid MFA token")
			}
		}
	}

	// Validate duration
	duration := req.Duration
	if duration == 0 {
		duration = 30 * time.Minute // Default
	}
	if b.config.MaxDuration > 0 && duration > b.config.MaxDuration {
		duration = b.config.MaxDuration
	}

	// Generate audit ID
	auditID := generateAuditID()

	now := time.Now()
	b.state = &BreakGlassState{
		Active:      true,
		AuditID:     auditID,
		ActivatedAt: now,
		ExpiresAt:   now.Add(duration),
		ActivatedBy: req.User,
		Reason:      req.Reason,
		Operations:  0,
	}

	// Log activation
	if b.auditLog != nil {
		b.auditLog.LogBreakGlassActivation(auditID, req.User, req.Reason, duration)
	}

	// Send notifications
	if b.notifier != nil && len(b.config.NotifyChannels) > 0 {
		msg := fmt.Sprintf("⚠️ BREAK-GLASS ACTIVATED\nUser: %s\nReason: %s\nDuration: %s\nAudit ID: %s",
			req.User, req.Reason, duration, auditID)
		b.notifier.Notify(ctx, b.config.NotifyChannels, msg)
	}

	// Start auto-expire if configured
	if b.config.AutoExpire {
		go b.autoExpire(auditID, duration)
	}

	return &ActivateResult{
		AuditID:     auditID,
		ActivatedAt: now,
		ExpiresAt:   now.Add(duration),
		Message:     "Break-glass activated. All policies suspended. All operations will be logged.",
	}, nil
}

// Deactivate deactivates break-glass mode.
func (b *BreakGlass) Deactivate(ctx context.Context, user string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == nil || !b.state.Active {
		return fmt.Errorf("break-glass is not active")
	}

	auditID := b.state.AuditID
	opCount := b.state.Operations

	b.state.Active = false

	// Log deactivation
	if b.auditLog != nil {
		b.auditLog.LogBreakGlassDeactivation(auditID, user, opCount)
	}

	// Send notifications
	if b.notifier != nil && len(b.config.NotifyChannels) > 0 {
		msg := fmt.Sprintf("✓ Break-glass deactivated\nDeactivated by: %s\nOperations during activation: %d\nAudit ID: %s",
			user, opCount, auditID)
		b.notifier.Notify(ctx, b.config.NotifyChannels, msg)
	}

	return nil
}

// Status returns the current break-glass status.
func (b *BreakGlass) Status() *BreakGlassState {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.state == nil {
		return &BreakGlassState{Active: false}
	}

	// Check if expired
	if b.state.Active && time.Now().After(b.state.ExpiresAt) {
		return &BreakGlassState{Active: false}
	}

	// Return a copy
	return &BreakGlassState{
		Active:      b.state.Active,
		AuditID:     b.state.AuditID,
		ActivatedAt: b.state.ActivatedAt,
		ExpiresAt:   b.state.ExpiresAt,
		ActivatedBy: b.state.ActivatedBy,
		Reason:      b.state.Reason,
		Operations:  b.state.Operations,
	}
}

// IsActive returns whether break-glass is currently active.
func (b *BreakGlass) IsActive() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.state == nil || !b.state.Active {
		return false
	}

	// Check expiration
	if time.Now().After(b.state.ExpiresAt) {
		return false
	}

	return true
}

// Remaining returns the time remaining for break-glass.
func (b *BreakGlass) Remaining() time.Duration {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.state == nil || !b.state.Active {
		return 0
	}

	remaining := time.Until(b.state.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// RecordOperation records an operation during break-glass.
func (b *BreakGlass) RecordOperation(opType, details string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == nil || !b.state.Active {
		return
	}

	b.state.Operations++

	if b.config.Permissions.LogEverything && b.auditLog != nil {
		b.auditLog.LogBreakGlassOperation(b.state.AuditID, opType, details)
	}
}

// ShouldBypass returns whether the given operation should bypass policy.
func (b *BreakGlass) ShouldBypass(opType string) bool {
	if !b.IsActive() {
		return false
	}

	b.mu.RLock()
	perms := b.config.Permissions
	b.mu.RUnlock()

	switch opType {
	case "file_read", "file_write", "file_create", "file_delete":
		return perms.AllowAllFiles
	case "net_connect", "dns_query":
		return perms.AllowAllNetwork
	case "env_read":
		return perms.AllowSensitiveEnv
	default:
		return perms.AllowAllFiles && perms.AllowAllNetwork
	}
}

// isAuthorized checks if a user is authorized for break-glass.
func (b *BreakGlass) isAuthorized(user string) bool {
	for _, authorized := range b.config.AuthorizedUsers {
		if authorized == user {
			return true
		}
	}
	return false
}

// autoExpire automatically deactivates break-glass after duration.
func (b *BreakGlass) autoExpire(auditID string, duration time.Duration) {
	time.Sleep(duration)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Verify this is still the same activation
	if b.state != nil && b.state.Active && b.state.AuditID == auditID {
		b.state.Active = false

		if b.auditLog != nil {
			b.auditLog.LogBreakGlassDeactivation(auditID, "system:auto_expire", b.state.Operations)
		}

		if b.notifier != nil && len(b.config.NotifyChannels) > 0 {
			msg := fmt.Sprintf("⏱️ Break-glass auto-expired\nAudit ID: %s\nOperations: %d",
				auditID, b.state.Operations)
			b.notifier.Notify(context.Background(), b.config.NotifyChannels, msg)
		}
	}
}

// generateAuditID generates a unique audit ID.
func generateAuditID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return fmt.Sprintf("bg_%s_%s",
		time.Now().Format("20060102_150405"),
		hex.EncodeToString(bytes))
}

// DefaultConfig returns a default break-glass configuration.
func DefaultConfig() BreakGlassConfig {
	return BreakGlassConfig{
		Enabled:        false,
		RequireMFA:     true,
		MaxDuration:    time.Hour,
		RequireReason:  true,
		AutoExpire:     true,
		Permissions: Permissions{
			AllowAllFiles:     true,
			AllowAllNetwork:   true,
			AllowSensitiveEnv: false,
			LogEverything:     true,
		},
	}
}
