package hotreload

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// RuntimeConfig manages configuration that can be updated at runtime.
type RuntimeConfig struct {
	mu sync.RWMutex

	// Dynamically updatable fields
	logLevel     string
	rateLimits   RateLimitConfig
	featureFlags map[string]bool
	customValues map[string]any

	// Callbacks for when values change
	onLogLevelChange     func(level string)
	onRateLimitsChange   func(config RateLimitConfig)
	onFeatureFlagChange  func(flag string, enabled bool)

	// Update tracking
	updateCount atomic.Int64
	lastUpdate  time.Time
}

// RateLimitConfig defines rate limiting configuration.
type RateLimitConfig struct {
	RequestsPerSecond float64       `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	WindowDuration    time.Duration `json:"window_duration"`
}

// RuntimeConfigOption configures RuntimeConfig.
type RuntimeConfigOption func(*RuntimeConfig)

// WithLogLevelCallback sets the callback for log level changes.
func WithLogLevelCallback(fn func(level string)) RuntimeConfigOption {
	return func(c *RuntimeConfig) {
		c.onLogLevelChange = fn
	}
}

// WithRateLimitsCallback sets the callback for rate limit changes.
func WithRateLimitsCallback(fn func(config RateLimitConfig)) RuntimeConfigOption {
	return func(c *RuntimeConfig) {
		c.onRateLimitsChange = fn
	}
}

// WithFeatureFlagCallback sets the callback for feature flag changes.
func WithFeatureFlagCallback(fn func(flag string, enabled bool)) RuntimeConfigOption {
	return func(c *RuntimeConfig) {
		c.onFeatureFlagChange = fn
	}
}

// NewRuntimeConfig creates a new runtime configuration.
func NewRuntimeConfig(opts ...RuntimeConfigOption) *RuntimeConfig {
	c := &RuntimeConfig{
		logLevel:     "info",
		featureFlags: make(map[string]bool),
		customValues: make(map[string]any),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// LogLevel returns the current log level.
func (c *RuntimeConfig) LogLevel() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logLevel
}

// SetLogLevel updates the log level.
func (c *RuntimeConfig) SetLogLevel(level string) {
	c.mu.Lock()
	old := c.logLevel
	c.logLevel = level
	c.lastUpdate = time.Now()
	c.updateCount.Add(1)
	callback := c.onLogLevelChange
	c.mu.Unlock()

	if callback != nil && old != level {
		callback(level)
	}
}

// RateLimits returns the current rate limit configuration.
func (c *RuntimeConfig) RateLimits() RateLimitConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rateLimits
}

// SetRateLimits updates the rate limit configuration.
func (c *RuntimeConfig) SetRateLimits(config RateLimitConfig) {
	c.mu.Lock()
	c.rateLimits = config
	c.lastUpdate = time.Now()
	c.updateCount.Add(1)
	callback := c.onRateLimitsChange
	c.mu.Unlock()

	if callback != nil {
		callback(config)
	}
}

// FeatureFlag returns whether a feature flag is enabled.
func (c *RuntimeConfig) FeatureFlag(flag string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.featureFlags[flag]
}

// SetFeatureFlag updates a feature flag.
func (c *RuntimeConfig) SetFeatureFlag(flag string, enabled bool) {
	c.mu.Lock()
	old := c.featureFlags[flag]
	c.featureFlags[flag] = enabled
	c.lastUpdate = time.Now()
	c.updateCount.Add(1)
	callback := c.onFeatureFlagChange
	c.mu.Unlock()

	if callback != nil && old != enabled {
		callback(flag, enabled)
	}
}

// FeatureFlags returns a copy of all feature flags.
func (c *RuntimeConfig) FeatureFlags() map[string]bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	flags := make(map[string]bool, len(c.featureFlags))
	for k, v := range c.featureFlags {
		flags[k] = v
	}
	return flags
}

// SetCustomValue sets a custom configuration value.
func (c *RuntimeConfig) SetCustomValue(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.customValues[key] = value
	c.lastUpdate = time.Now()
	c.updateCount.Add(1)
}

// GetCustomValue gets a custom configuration value.
func (c *RuntimeConfig) GetCustomValue(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.customValues[key]
	return v, ok
}

// UpdateCount returns the total number of updates.
func (c *RuntimeConfig) UpdateCount() int64 {
	return c.updateCount.Load()
}

// LastUpdate returns the time of the last update.
func (c *RuntimeConfig) LastUpdate() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastUpdate
}

// RuntimeConfigUpdate represents an update request.
type RuntimeConfigUpdate struct {
	LogLevel     *string            `json:"log_level,omitempty"`
	RateLimits   *RateLimitConfig   `json:"rate_limits,omitempty"`
	FeatureFlags map[string]bool    `json:"feature_flags,omitempty"`
	CustomValues map[string]any     `json:"custom_values,omitempty"`
}

// Apply applies an update to the runtime configuration.
func (c *RuntimeConfig) Apply(update RuntimeConfigUpdate) {
	if update.LogLevel != nil {
		c.SetLogLevel(*update.LogLevel)
	}

	if update.RateLimits != nil {
		c.SetRateLimits(*update.RateLimits)
	}

	for flag, enabled := range update.FeatureFlags {
		c.SetFeatureFlag(flag, enabled)
	}

	for key, value := range update.CustomValues {
		c.SetCustomValue(key, value)
	}
}

// Snapshot returns a snapshot of the current configuration.
type RuntimeConfigSnapshot struct {
	LogLevel     string          `json:"log_level"`
	RateLimits   RateLimitConfig `json:"rate_limits"`
	FeatureFlags map[string]bool `json:"feature_flags"`
	CustomValues map[string]any  `json:"custom_values"`
	UpdateCount  int64           `json:"update_count"`
	LastUpdate   time.Time       `json:"last_update,omitempty"`
}

// Snapshot returns a snapshot of the current configuration.
func (c *RuntimeConfig) Snapshot() RuntimeConfigSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	flags := make(map[string]bool, len(c.featureFlags))
	for k, v := range c.featureFlags {
		flags[k] = v
	}

	custom := make(map[string]any, len(c.customValues))
	for k, v := range c.customValues {
		custom[k] = v
	}

	return RuntimeConfigSnapshot{
		LogLevel:     c.logLevel,
		RateLimits:   c.rateLimits,
		FeatureFlags: flags,
		CustomValues: custom,
		UpdateCount:  c.updateCount.Load(),
		LastUpdate:   c.lastUpdate,
	}
}

// HTTPHandler returns an HTTP handler for runtime config updates.
func (c *RuntimeConfig) HTTPHandler() http.Handler {
	mux := http.NewServeMux()

	// GET /config - Get current config
	mux.HandleFunc("GET /config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c.Snapshot())
	})

	// PATCH /config - Update config
	mux.HandleFunc("PATCH /config", func(w http.ResponseWriter, r *http.Request) {
		var update RuntimeConfigUpdate
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		c.Apply(update)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c.Snapshot())
	})

	// PUT /config/log-level - Update log level
	mux.HandleFunc("PUT /config/log-level", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Level string `json:"level"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		c.SetLogLevel(req.Level)
		w.WriteHeader(http.StatusOK)
	})

	// PUT /config/feature-flags/{flag} - Update feature flag
	mux.HandleFunc("PUT /config/feature-flags/", func(w http.ResponseWriter, r *http.Request) {
		flag := r.URL.Path[len("/config/feature-flags/"):]
		if flag == "" {
			http.Error(w, "flag name required", http.StatusBadRequest)
			return
		}

		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
			return
		}

		c.SetFeatureFlag(flag, req.Enabled)
		w.WriteHeader(http.StatusOK)
	})

	return mux
}
