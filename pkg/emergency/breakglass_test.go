package emergency

import (
	"context"
	"sync"
	"testing"
	"time"
)

type mockNotifier struct {
	mu       sync.Mutex
	messages []string
}

func (m *mockNotifier) Notify(ctx context.Context, channels []string, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, message)
	return nil
}

func (m *mockNotifier) Messages() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.messages...)
}

type mockAuditLogger struct {
	mu         sync.Mutex
	activations []string
}

func (m *mockAuditLogger) LogBreakGlassActivation(auditID, user, reason string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activations = append(m.activations, auditID)
}

func (m *mockAuditLogger) LogBreakGlassDeactivation(auditID, user string, opCount int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
}

func (m *mockAuditLogger) LogBreakGlassOperation(auditID, opType, details string) {
	m.mu.Lock()
	defer m.mu.Unlock()
}

type mockMFAVerifier struct {
	valid bool
}

func (m *mockMFAVerifier) Verify(user, token string) (bool, error) {
	return m.valid, nil
}

func TestNewBreakGlass(t *testing.T) {
	config := DefaultConfig()
	bg := NewBreakGlass(config, nil, nil, nil)
	if bg == nil {
		t.Fatal("expected non-nil BreakGlass")
	}
}

func TestBreakGlass_Activate(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.RequireReason = false

	notifier := &mockNotifier{}
	auditLog := &mockAuditLogger{}

	bg := NewBreakGlass(config, notifier, auditLog, nil)

	ctx := context.Background()
	result, err := bg.Activate(ctx, ActivateRequest{
		User:     "admin@example.com",
		Reason:   "Test activation",
		Duration: 30 * time.Minute,
	})

	if err != nil {
		t.Fatalf("Activate error: %v", err)
	}

	if result.AuditID == "" {
		t.Error("expected audit ID")
	}

	if !bg.IsActive() {
		t.Error("break-glass should be active")
	}
}

func TestBreakGlass_Activate_NotEnabled(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = false

	bg := NewBreakGlass(config, nil, nil, nil)

	ctx := context.Background()
	_, err := bg.Activate(ctx, ActivateRequest{User: "user"})

	if err == nil {
		t.Error("should error when not enabled")
	}
}

func TestBreakGlass_Activate_Unauthorized(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false

	bg := NewBreakGlass(config, nil, nil, nil)

	ctx := context.Background()
	_, err := bg.Activate(ctx, ActivateRequest{User: "unauthorized@example.com"})

	if err == nil {
		t.Error("should error for unauthorized user")
	}
}

func TestBreakGlass_Activate_RequiresMFA(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = true
	config.RequireReason = false

	mfa := &mockMFAVerifier{valid: true}
	bg := NewBreakGlass(config, nil, nil, mfa)

	ctx := context.Background()

	// Without token
	_, err := bg.Activate(ctx, ActivateRequest{User: "admin@example.com"})
	if err == nil {
		t.Error("should require MFA token")
	}

	// With invalid token
	mfa.valid = false
	_, err = bg.Activate(ctx, ActivateRequest{
		User:     "admin@example.com",
		MFAToken: "invalid",
	})
	if err == nil {
		t.Error("should reject invalid MFA")
	}

	// With valid token
	mfa.valid = true
	_, err = bg.Activate(ctx, ActivateRequest{
		User:     "admin@example.com",
		MFAToken: "valid",
	})
	if err != nil {
		t.Errorf("should accept valid MFA: %v", err)
	}
}

func TestBreakGlass_Activate_RequiresReason(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.RequireReason = true

	bg := NewBreakGlass(config, nil, nil, nil)

	ctx := context.Background()
	_, err := bg.Activate(ctx, ActivateRequest{User: "admin@example.com"})

	if err == nil {
		t.Error("should require reason")
	}

	_, err = bg.Activate(ctx, ActivateRequest{
		User:   "admin@example.com",
		Reason: "Production incident",
	})
	if err != nil {
		t.Errorf("should accept with reason: %v", err)
	}
}

func TestBreakGlass_Activate_MaxDuration(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.RequireReason = false
	config.MaxDuration = 30 * time.Minute

	bg := NewBreakGlass(config, nil, nil, nil)

	ctx := context.Background()
	result, err := bg.Activate(ctx, ActivateRequest{
		User:     "admin@example.com",
		Duration: 2 * time.Hour, // Exceeds max
	})

	if err != nil {
		t.Fatalf("Activate error: %v", err)
	}

	// Should be capped at max duration
	duration := result.ExpiresAt.Sub(result.ActivatedAt)
	if duration > 31*time.Minute {
		t.Errorf("duration should be capped at max: %v", duration)
	}
}

func TestBreakGlass_Activate_AlreadyActive(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.RequireReason = false

	bg := NewBreakGlass(config, nil, nil, nil)

	ctx := context.Background()
	bg.Activate(ctx, ActivateRequest{User: "admin@example.com"})

	// Try to activate again
	_, err := bg.Activate(ctx, ActivateRequest{User: "admin@example.com"})
	if err == nil {
		t.Error("should error when already active")
	}
}

func TestBreakGlass_Deactivate(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.RequireReason = false

	bg := NewBreakGlass(config, nil, nil, nil)

	ctx := context.Background()
	bg.Activate(ctx, ActivateRequest{User: "admin@example.com"})

	if err := bg.Deactivate(ctx, "admin@example.com"); err != nil {
		t.Errorf("Deactivate error: %v", err)
	}

	if bg.IsActive() {
		t.Error("break-glass should not be active")
	}
}

func TestBreakGlass_Deactivate_NotActive(t *testing.T) {
	config := DefaultConfig()
	bg := NewBreakGlass(config, nil, nil, nil)

	ctx := context.Background()
	err := bg.Deactivate(ctx, "user")

	if err == nil {
		t.Error("should error when not active")
	}
}

func TestBreakGlass_Status(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.RequireReason = false

	bg := NewBreakGlass(config, nil, nil, nil)

	// Initial status
	status := bg.Status()
	if status.Active {
		t.Error("should not be active initially")
	}

	// After activation
	ctx := context.Background()
	bg.Activate(ctx, ActivateRequest{
		User:   "admin@example.com",
		Reason: "test",
	})

	status = bg.Status()
	if !status.Active {
		t.Error("should be active after activation")
	}
	if status.ActivatedBy != "admin@example.com" {
		t.Errorf("ActivatedBy = %q, want admin@example.com", status.ActivatedBy)
	}
}

func TestBreakGlass_Remaining(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.RequireReason = false

	bg := NewBreakGlass(config, nil, nil, nil)

	// No remaining when not active
	if bg.Remaining() != 0 {
		t.Error("Remaining should be 0 when not active")
	}

	ctx := context.Background()
	bg.Activate(ctx, ActivateRequest{
		User:     "admin@example.com",
		Duration: 30 * time.Minute,
	})

	remaining := bg.Remaining()
	if remaining < 29*time.Minute || remaining > 30*time.Minute {
		t.Errorf("Remaining = %v, expected ~30m", remaining)
	}
}

func TestBreakGlass_RecordOperation(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.RequireReason = false

	bg := NewBreakGlass(config, nil, nil, nil)

	ctx := context.Background()
	bg.Activate(ctx, ActivateRequest{User: "admin@example.com"})

	bg.RecordOperation("file_read", "/etc/passwd")
	bg.RecordOperation("file_read", "/etc/shadow")

	status := bg.Status()
	if status.Operations != 2 {
		t.Errorf("Operations = %d, want 2", status.Operations)
	}
}

func TestBreakGlass_ShouldBypass(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.RequireReason = false
	config.Permissions.AllowAllFiles = true
	config.Permissions.AllowAllNetwork = true
	config.Permissions.AllowSensitiveEnv = false

	bg := NewBreakGlass(config, nil, nil, nil)

	// Not active - should not bypass
	if bg.ShouldBypass("file_read") {
		t.Error("should not bypass when not active")
	}

	ctx := context.Background()
	bg.Activate(ctx, ActivateRequest{User: "admin@example.com"})

	// Should bypass files and network
	if !bg.ShouldBypass("file_read") {
		t.Error("should bypass file_read")
	}
	if !bg.ShouldBypass("net_connect") {
		t.Error("should bypass net_connect")
	}

	// Should not bypass sensitive env
	if bg.ShouldBypass("env_read") {
		t.Error("should not bypass env_read with AllowSensitiveEnv=false")
	}
}

func TestBreakGlass_Notifications(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = true
	config.AuthorizedUsers = []string{"admin@example.com"}
	config.RequireMFA = false
	config.NotifyChannels = []string{"#alerts"}

	notifier := &mockNotifier{}
	bg := NewBreakGlass(config, notifier, nil, nil)

	ctx := context.Background()
	bg.Activate(ctx, ActivateRequest{User: "admin@example.com", Reason: "test"})

	messages := notifier.Messages()
	if len(messages) != 1 {
		t.Errorf("expected 1 notification, got %d", len(messages))
	}
}
