package emergency

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Manager coordinates emergency systems.
type Manager struct {
	breakGlass *BreakGlass
	killSwitch *KillSwitch
}

// ManagerConfig configures the emergency manager.
type ManagerConfig struct {
	BreakGlass BreakGlassConfig `yaml:"break_glass" json:"break_glass"`
	KillSwitch KillSwitchConfig `yaml:"kill_switch" json:"kill_switch"`
}

// NewManager creates a new emergency manager.
func NewManager(
	config ManagerConfig,
	sessionMgr SessionManager,
	notifier Notifier,
	auditLog AuditLogger,
	mfa MFAVerifier,
) *Manager {
	return &Manager{
		breakGlass: NewBreakGlass(config.BreakGlass, notifier, auditLog, mfa),
		killSwitch: NewKillSwitch(sessionMgr, notifier, auditLog),
	}
}

// BreakGlass returns the break-glass manager.
func (m *Manager) BreakGlass() *BreakGlass {
	return m.breakGlass
}

// KillSwitch returns the kill switch.
func (m *Manager) KillSwitch() *KillSwitch {
	return m.killSwitch
}

// Status returns the overall emergency status.
type EmergencyStatus struct {
	BreakGlass *BreakGlassState  `json:"break_glass"`
	KillSwitch *KillSwitchState  `json:"kill_switch"`
	Emergency  bool              `json:"emergency"`
}

// Status returns the current emergency status.
func (m *Manager) Status() EmergencyStatus {
	bgState := m.breakGlass.Status()
	ksState := m.killSwitch.Status()

	return EmergencyStatus{
		BreakGlass: bgState,
		KillSwitch: ksState,
		Emergency:  bgState.Active || ksState.Activated,
	}
}

// IsEmergencyActive returns whether any emergency mode is active.
func (m *Manager) IsEmergencyActive() bool {
	return m.breakGlass.IsActive() || m.killSwitch.IsActivated()
}

// HTTPHandler returns an HTTP handler for emergency operations.
func (m *Manager) HTTPHandler() http.Handler {
	mux := http.NewServeMux()

	// GET /emergency/status
	mux.HandleFunc("GET /emergency/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.Status())
	})

	// POST /emergency/break-glass/activate
	mux.HandleFunc("POST /emergency/break-glass/activate", func(w http.ResponseWriter, r *http.Request) {
		var req ActivateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		result, err := m.breakGlass.Activate(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// POST /emergency/break-glass/deactivate
	mux.HandleFunc("POST /emergency/break-glass/deactivate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			User string `json:"user"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if err := m.breakGlass.Deactivate(r.Context(), req.User); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deactivated"})
	})

	// GET /emergency/break-glass/status
	mux.HandleFunc("GET /emergency/break-glass/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.breakGlass.Status())
	})

	// POST /emergency/kill-switch/activate
	mux.HandleFunc("POST /emergency/kill-switch/activate", func(w http.ResponseWriter, r *http.Request) {
		var req KillAllRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		result, err := m.killSwitch.Activate(r.Context(), req)
		if err != nil {
			if err == ErrAlreadyActivated {
				http.Error(w, err.Error(), http.StatusConflict)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// POST /emergency/kill-switch/reset
	mux.HandleFunc("POST /emergency/kill-switch/reset", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Actor string `json:"actor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if err := m.killSwitch.Reset(r.Context(), req.Actor); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
	})

	// GET /emergency/kill-switch/status
	mux.HandleFunc("GET /emergency/kill-switch/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.killSwitch.Status())
	})

	return mux
}

// HealthCheck returns an error if any emergency mode is active.
func (m *Manager) HealthCheck() error {
	if m.killSwitch.IsActivated() {
		return fmt.Errorf("kill switch activated")
	}
	return nil
}

// DefaultManagerConfig returns a default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		BreakGlass: DefaultConfig(),
		KillSwitch: KillSwitchConfig{},
	}
}

// FormatDuration formats a duration for display.
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}
