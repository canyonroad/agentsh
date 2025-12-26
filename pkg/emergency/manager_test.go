package emergency

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil, nil, nil)

	if m == nil {
		t.Fatal("expected non-nil Manager")
	}

	if m.BreakGlass() == nil {
		t.Error("BreakGlass() should not be nil")
	}

	if m.KillSwitch() == nil {
		t.Error("KillSwitch() should not be nil")
	}
}

func TestManager_Status(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil, nil, nil)

	status := m.Status()

	if status.Emergency {
		t.Error("Emergency should be false initially")
	}

	if status.BreakGlass == nil {
		t.Error("BreakGlass status should not be nil")
	}

	if status.KillSwitch == nil {
		t.Error("KillSwitch status should not be nil")
	}
}

func TestManager_IsEmergencyActive(t *testing.T) {
	config := DefaultManagerConfig()
	config.BreakGlass.Enabled = true
	config.BreakGlass.AuthorizedUsers = []string{"admin"}
	config.BreakGlass.RequireMFA = false
	config.BreakGlass.RequireReason = false

	m := NewManager(config, nil, nil, nil, nil)

	if m.IsEmergencyActive() {
		t.Error("should not be active initially")
	}

	// Activate break-glass
	ctx := context.Background()
	m.BreakGlass().Activate(ctx, ActivateRequest{User: "admin"})

	if !m.IsEmergencyActive() {
		t.Error("should be active after break-glass activation")
	}
}

func TestManager_HealthCheck(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil, nil, nil)

	// Healthy initially
	if err := m.HealthCheck(); err != nil {
		t.Errorf("HealthCheck should pass: %v", err)
	}

	// Activate kill switch
	ctx := context.Background()
	m.KillSwitch().Activate(ctx, KillAllRequest{Reason: "test", Actor: "admin"})

	// Should fail health check
	if err := m.HealthCheck(); err == nil {
		t.Error("HealthCheck should fail when kill switch activated")
	}
}

func TestManager_HTTPHandler_Status(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil, nil, nil)
	handler := m.HTTPHandler()

	req := httptest.NewRequest("GET", "/emergency/status", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var status EmergencyStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if status.Emergency {
		t.Error("emergency should be false")
	}
}

func TestManager_HTTPHandler_BreakGlassActivate(t *testing.T) {
	config := DefaultManagerConfig()
	config.BreakGlass.Enabled = true
	config.BreakGlass.AuthorizedUsers = []string{"admin@example.com"}
	config.BreakGlass.RequireMFA = false

	m := NewManager(config, nil, nil, nil, nil)
	handler := m.HTTPHandler()

	body := []byte(`{"user": "admin@example.com", "reason": "test", "duration": 1800000000000}`)
	req := httptest.NewRequest("POST", "/emergency/break-glass/activate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var result ActivateResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if result.AuditID == "" {
		t.Error("expected audit ID")
	}
}

func TestManager_HTTPHandler_BreakGlassActivate_Unauthorized(t *testing.T) {
	config := DefaultManagerConfig()
	config.BreakGlass.Enabled = true
	config.BreakGlass.AuthorizedUsers = []string{"admin@example.com"}
	config.BreakGlass.RequireMFA = false

	m := NewManager(config, nil, nil, nil, nil)
	handler := m.HTTPHandler()

	body := []byte(`{"user": "unauthorized@example.com"}`)
	req := httptest.NewRequest("POST", "/emergency/break-glass/activate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestManager_HTTPHandler_BreakGlassDeactivate(t *testing.T) {
	config := DefaultManagerConfig()
	config.BreakGlass.Enabled = true
	config.BreakGlass.AuthorizedUsers = []string{"admin@example.com"}
	config.BreakGlass.RequireMFA = false
	config.BreakGlass.RequireReason = false

	m := NewManager(config, nil, nil, nil, nil)
	handler := m.HTTPHandler()

	// First activate
	ctx := context.Background()
	m.BreakGlass().Activate(ctx, ActivateRequest{User: "admin@example.com"})

	// Then deactivate via HTTP
	body := []byte(`{"user": "admin@example.com"}`)
	req := httptest.NewRequest("POST", "/emergency/break-glass/deactivate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if m.BreakGlass().IsActive() {
		t.Error("break-glass should not be active")
	}
}

func TestManager_HTTPHandler_KillSwitchActivate(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil, nil, nil)
	handler := m.HTTPHandler()

	body := []byte(`{"reason": "test", "actor": "admin"}`)
	req := httptest.NewRequest("POST", "/emergency/kill-switch/activate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if !m.KillSwitch().IsActivated() {
		t.Error("kill switch should be activated")
	}
}

func TestManager_HTTPHandler_KillSwitchReset(t *testing.T) {
	config := DefaultManagerConfig()
	sessionMgr := &mockSessionManager{}
	m := NewManager(config, sessionMgr, nil, nil, nil)
	handler := m.HTTPHandler()

	// Activate first
	ctx := context.Background()
	m.KillSwitch().Activate(ctx, KillAllRequest{Reason: "test", Actor: "admin"})

	// Reset via HTTP
	body := []byte(`{"actor": "admin"}`)
	req := httptest.NewRequest("POST", "/emergency/kill-switch/reset", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if m.KillSwitch().IsActivated() {
		t.Error("kill switch should not be activated")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m 30s"},
		{65 * time.Minute, "1h 5m"},
	}

	for _, tt := range tests {
		got := FormatDuration(tt.d)
		if got != tt.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestDefaultManagerConfig(t *testing.T) {
	config := DefaultManagerConfig()

	if config.BreakGlass.Enabled {
		t.Error("break-glass should be disabled by default")
	}

	if !config.BreakGlass.RequireMFA {
		t.Error("MFA should be required by default")
	}

	if !config.BreakGlass.AutoExpire {
		t.Error("auto-expire should be enabled by default")
	}
}
