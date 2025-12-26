package emergency

import (
	"context"
	"sync"
	"testing"
)

type mockSession struct {
	id     string
	killed bool
}

func (m *mockSession) ID() string {
	return m.id
}

func (m *mockSession) Kill(reason string) error {
	m.killed = true
	return nil
}

type mockSessionManager struct {
	mu       sync.Mutex
	sessions []*mockSession
	disabled bool
}

func (m *mockSessionManager) ListAll() []Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]Session, len(m.sessions))
	for i, s := range m.sessions {
		result[i] = s
	}
	return result
}

func (m *mockSessionManager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disabled = true
	return nil
}

func (m *mockSessionManager) Enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disabled = false
	return nil
}

func (m *mockSessionManager) IsDisabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disabled
}

func TestNewKillSwitch(t *testing.T) {
	ks := NewKillSwitch(nil, nil, nil)
	if ks == nil {
		t.Fatal("expected non-nil KillSwitch")
	}
}

func TestKillSwitch_Activate(t *testing.T) {
	sessions := []*mockSession{
		{id: "sess-1"},
		{id: "sess-2"},
		{id: "sess-3"},
	}

	sessionMgr := &mockSessionManager{sessions: sessions}
	notifier := &mockNotifier{}

	ks := NewKillSwitch(sessionMgr, notifier, nil)

	ctx := context.Background()
	result, err := ks.Activate(ctx, KillAllRequest{
		Reason:         "Emergency",
		Actor:          "admin",
		NotifyChannels: []string{"#alerts"},
	})

	if err != nil {
		t.Fatalf("Activate error: %v", err)
	}

	if result.SessionsKilled != 3 {
		t.Errorf("SessionsKilled = %d, want 3", result.SessionsKilled)
	}

	// Check sessions were killed
	for _, s := range sessions {
		if !s.killed {
			t.Errorf("session %s should be killed", s.id)
		}
	}

	// Check sessions disabled
	if !sessionMgr.IsDisabled() {
		t.Error("sessions should be disabled")
	}

	if !ks.IsActivated() {
		t.Error("kill switch should be activated")
	}
}

func TestKillSwitch_Activate_AlreadyActivated(t *testing.T) {
	ks := NewKillSwitch(nil, nil, nil)

	ctx := context.Background()
	ks.Activate(ctx, KillAllRequest{Reason: "test", Actor: "admin"})

	// Try again
	_, err := ks.Activate(ctx, KillAllRequest{Reason: "test2", Actor: "admin"})
	if err != ErrAlreadyActivated {
		t.Errorf("expected ErrAlreadyActivated, got %v", err)
	}
}

func TestKillSwitch_Reset(t *testing.T) {
	sessionMgr := &mockSessionManager{}
	notifier := &mockNotifier{}

	ks := NewKillSwitch(sessionMgr, notifier, nil)

	ctx := context.Background()
	ks.Activate(ctx, KillAllRequest{
		Reason:         "test",
		Actor:          "admin",
		NotifyChannels: []string{"#alerts"},
	})

	if err := ks.Reset(ctx, "admin"); err != nil {
		t.Errorf("Reset error: %v", err)
	}

	if ks.IsActivated() {
		t.Error("kill switch should not be activated after reset")
	}

	if sessionMgr.IsDisabled() {
		t.Error("sessions should be enabled after reset")
	}
}

func TestKillSwitch_Reset_NotActivated(t *testing.T) {
	ks := NewKillSwitch(nil, nil, nil)

	ctx := context.Background()
	err := ks.Reset(ctx, "admin")

	if err == nil {
		t.Error("should error when not activated")
	}
}

func TestKillSwitch_Status(t *testing.T) {
	ks := NewKillSwitch(nil, nil, nil)

	// Initial status
	status := ks.Status()
	if status.Activated {
		t.Error("should not be activated initially")
	}

	// After activation
	ctx := context.Background()
	ks.Activate(ctx, KillAllRequest{Reason: "test", Actor: "admin"})

	status = ks.Status()
	if !status.Activated {
		t.Error("should be activated")
	}
	if status.ActivatedBy != "admin" {
		t.Errorf("ActivatedBy = %q, want admin", status.ActivatedBy)
	}
	if status.Reason != "test" {
		t.Errorf("Reason = %q, want test", status.Reason)
	}
}

func TestKillSwitch_IsActivated(t *testing.T) {
	ks := NewKillSwitch(nil, nil, nil)

	if ks.IsActivated() {
		t.Error("should not be activated initially")
	}

	ctx := context.Background()
	ks.Activate(ctx, KillAllRequest{Reason: "test", Actor: "admin"})

	if !ks.IsActivated() {
		t.Error("should be activated")
	}
}

func TestKillSwitch_Notifications(t *testing.T) {
	notifier := &mockNotifier{}
	ks := NewKillSwitch(nil, notifier, nil)

	ctx := context.Background()
	ks.Activate(ctx, KillAllRequest{
		Reason:         "test",
		Actor:          "admin",
		NotifyChannels: []string{"#alerts"},
	})

	messages := notifier.Messages()
	if len(messages) != 1 {
		t.Errorf("expected 1 notification, got %d", len(messages))
	}
}
