package hotreload

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewRuntimeConfig(t *testing.T) {
	config := NewRuntimeConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}

	// Default log level
	if config.LogLevel() != "info" {
		t.Errorf("LogLevel() = %q, want info", config.LogLevel())
	}
}

func TestRuntimeConfig_LogLevel(t *testing.T) {
	var called bool
	var gotLevel string

	config := NewRuntimeConfig(
		WithLogLevelCallback(func(level string) {
			called = true
			gotLevel = level
		}),
	)

	config.SetLogLevel("debug")

	if config.LogLevel() != "debug" {
		t.Errorf("LogLevel() = %q, want debug", config.LogLevel())
	}

	if !called {
		t.Error("callback not called")
	}

	if gotLevel != "debug" {
		t.Errorf("callback got level = %q, want debug", gotLevel)
	}
}

func TestRuntimeConfig_LogLevel_NoCallbackOnSameValue(t *testing.T) {
	callCount := 0

	config := NewRuntimeConfig(
		WithLogLevelCallback(func(level string) {
			callCount++
		}),
	)

	config.SetLogLevel("debug")
	config.SetLogLevel("debug") // Same value

	if callCount != 1 {
		t.Errorf("callback called %d times, want 1", callCount)
	}
}

func TestRuntimeConfig_RateLimits(t *testing.T) {
	var called bool
	var gotConfig RateLimitConfig

	config := NewRuntimeConfig(
		WithRateLimitsCallback(func(c RateLimitConfig) {
			called = true
			gotConfig = c
		}),
	)

	limits := RateLimitConfig{
		RequestsPerSecond: 100,
		BurstSize:         10,
		WindowDuration:    time.Second,
	}

	config.SetRateLimits(limits)

	got := config.RateLimits()
	if got.RequestsPerSecond != 100 {
		t.Errorf("RequestsPerSecond = %v, want 100", got.RequestsPerSecond)
	}

	if !called {
		t.Error("callback not called")
	}

	if gotConfig.RequestsPerSecond != 100 {
		t.Errorf("callback got RequestsPerSecond = %v, want 100", gotConfig.RequestsPerSecond)
	}
}

func TestRuntimeConfig_FeatureFlags(t *testing.T) {
	var called bool
	var gotFlag string
	var gotEnabled bool

	config := NewRuntimeConfig(
		WithFeatureFlagCallback(func(flag string, enabled bool) {
			called = true
			gotFlag = flag
			gotEnabled = enabled
		}),
	)

	config.SetFeatureFlag("new_feature", true)

	if !config.FeatureFlag("new_feature") {
		t.Error("FeatureFlag(new_feature) = false, want true")
	}

	if !called {
		t.Error("callback not called")
	}

	if gotFlag != "new_feature" || !gotEnabled {
		t.Errorf("callback got (%q, %v), want (new_feature, true)", gotFlag, gotEnabled)
	}

	// Get all flags
	flags := config.FeatureFlags()
	if !flags["new_feature"] {
		t.Error("FeatureFlags() missing new_feature")
	}
}

func TestRuntimeConfig_CustomValues(t *testing.T) {
	config := NewRuntimeConfig()

	config.SetCustomValue("timeout", 30*time.Second)
	config.SetCustomValue("name", "test")

	v, ok := config.GetCustomValue("timeout")
	if !ok {
		t.Error("GetCustomValue(timeout) not found")
	}
	if v != 30*time.Second {
		t.Errorf("GetCustomValue(timeout) = %v, want 30s", v)
	}

	v, ok = config.GetCustomValue("name")
	if !ok {
		t.Error("GetCustomValue(name) not found")
	}
	if v != "test" {
		t.Errorf("GetCustomValue(name) = %v, want test", v)
	}

	_, ok = config.GetCustomValue("missing")
	if ok {
		t.Error("GetCustomValue(missing) should return false")
	}
}

func TestRuntimeConfig_UpdateCount(t *testing.T) {
	config := NewRuntimeConfig()

	if config.UpdateCount() != 0 {
		t.Errorf("UpdateCount() = %d, want 0", config.UpdateCount())
	}

	config.SetLogLevel("debug")
	config.SetFeatureFlag("test", true)
	config.SetCustomValue("key", "value")

	if config.UpdateCount() != 3 {
		t.Errorf("UpdateCount() = %d, want 3", config.UpdateCount())
	}
}

func TestRuntimeConfig_Apply(t *testing.T) {
	config := NewRuntimeConfig()

	level := "warn"
	update := RuntimeConfigUpdate{
		LogLevel: &level,
		RateLimits: &RateLimitConfig{
			RequestsPerSecond: 50,
		},
		FeatureFlags: map[string]bool{
			"feature_a": true,
			"feature_b": false,
		},
		CustomValues: map[string]any{
			"custom_key": "custom_value",
		},
	}

	config.Apply(update)

	if config.LogLevel() != "warn" {
		t.Errorf("LogLevel() = %q, want warn", config.LogLevel())
	}

	if config.RateLimits().RequestsPerSecond != 50 {
		t.Errorf("RateLimits().RequestsPerSecond = %v, want 50", config.RateLimits().RequestsPerSecond)
	}

	if !config.FeatureFlag("feature_a") {
		t.Error("FeatureFlag(feature_a) = false, want true")
	}

	v, _ := config.GetCustomValue("custom_key")
	if v != "custom_value" {
		t.Errorf("GetCustomValue(custom_key) = %v, want custom_value", v)
	}
}

func TestRuntimeConfig_Snapshot(t *testing.T) {
	config := NewRuntimeConfig()
	config.SetLogLevel("error")
	config.SetFeatureFlag("test", true)

	snapshot := config.Snapshot()

	if snapshot.LogLevel != "error" {
		t.Errorf("Snapshot.LogLevel = %q, want error", snapshot.LogLevel)
	}

	if !snapshot.FeatureFlags["test"] {
		t.Error("Snapshot.FeatureFlags[test] = false, want true")
	}

	if snapshot.UpdateCount != 2 {
		t.Errorf("Snapshot.UpdateCount = %d, want 2", snapshot.UpdateCount)
	}
}

func TestRuntimeConfig_HTTPHandler_GetConfig(t *testing.T) {
	config := NewRuntimeConfig()
	config.SetLogLevel("debug")

	handler := config.HTTPHandler()

	req := httptest.NewRequest("GET", "/config", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var snapshot RuntimeConfigSnapshot
	if err := json.NewDecoder(w.Body).Decode(&snapshot); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if snapshot.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", snapshot.LogLevel)
	}
}

func TestRuntimeConfig_HTTPHandler_PatchConfig(t *testing.T) {
	config := NewRuntimeConfig()
	handler := config.HTTPHandler()

	update := RuntimeConfigUpdate{
		FeatureFlags: map[string]bool{
			"new_feature": true,
		},
	}
	body, _ := json.Marshal(update)

	req := httptest.NewRequest("PATCH", "/config", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if !config.FeatureFlag("new_feature") {
		t.Error("feature flag not set")
	}
}

func TestRuntimeConfig_HTTPHandler_SetLogLevel(t *testing.T) {
	config := NewRuntimeConfig()
	handler := config.HTTPHandler()

	body := []byte(`{"level": "warn"}`)
	req := httptest.NewRequest("PUT", "/config/log-level", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if config.LogLevel() != "warn" {
		t.Errorf("LogLevel() = %q, want warn", config.LogLevel())
	}
}

func TestRuntimeConfig_HTTPHandler_SetFeatureFlag(t *testing.T) {
	config := NewRuntimeConfig()
	handler := config.HTTPHandler()

	body := []byte(`{"enabled": true}`)
	req := httptest.NewRequest("PUT", "/config/feature-flags/my_flag", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if !config.FeatureFlag("my_flag") {
		t.Error("feature flag not set")
	}
}
