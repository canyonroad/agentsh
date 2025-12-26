package hotreload

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// Reloadable represents something that can be reloaded atomically.
type Reloadable[T any] struct {
	value   atomic.Pointer[T]
	mu      sync.Mutex
	version atomic.Int64
}

// NewReloadable creates a new reloadable value.
func NewReloadable[T any](initial *T) *Reloadable[T] {
	r := &Reloadable[T]{}
	if initial != nil {
		r.value.Store(initial)
	}
	return r
}

// Get returns the current value.
func (r *Reloadable[T]) Get() *T {
	return r.value.Load()
}

// Swap atomically swaps the value and returns the old one.
func (r *Reloadable[T]) Swap(new *T) *T {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.value.Swap(new)
	r.version.Add(1)
	return old
}

// CompareAndSwap atomically swaps if current matches old.
func (r *Reloadable[T]) CompareAndSwap(old, new *T) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.value.CompareAndSwap(old, new) {
		r.version.Add(1)
		return true
	}
	return false
}

// Version returns the current version number (incremented on each swap).
func (r *Reloadable[T]) Version() int64 {
	return r.version.Load()
}

// ConfigManager manages hot-reloadable configuration.
type ConfigManager struct {
	policyWatcher *PolicyWatcher
	runtime       *RuntimeConfig
	mu            sync.RWMutex
	reloadables   map[string]any
	running       atomic.Bool
}

// ConfigManagerOption configures ConfigManager.
type ConfigManagerOption func(*ConfigManager)

// WithPolicyWatcher adds a policy watcher.
func WithPolicyWatcher(watcher *PolicyWatcher) ConfigManagerOption {
	return func(m *ConfigManager) {
		m.policyWatcher = watcher
	}
}

// WithRuntimeConfig adds runtime configuration.
func WithRuntimeConfig(config *RuntimeConfig) ConfigManagerOption {
	return func(m *ConfigManager) {
		m.runtime = config
	}
}

// NewConfigManager creates a new configuration manager.
func NewConfigManager(opts ...ConfigManagerOption) *ConfigManager {
	m := &ConfigManager{
		reloadables: make(map[string]any),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Start starts all managed watchers.
func (m *ConfigManager) Start(ctx context.Context) error {
	if !m.running.CompareAndSwap(false, true) {
		return fmt.Errorf("config manager already running")
	}

	if m.policyWatcher != nil {
		if err := m.policyWatcher.Start(ctx); err != nil {
			m.running.Store(false)
			return fmt.Errorf("starting policy watcher: %w", err)
		}
	}

	return nil
}

// Stop stops all managed watchers.
func (m *ConfigManager) Stop() error {
	if !m.running.CompareAndSwap(true, false) {
		return nil
	}

	var errs []error

	if m.policyWatcher != nil {
		if err := m.policyWatcher.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("stopping policy watcher: %w", err))
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// PolicyWatcher returns the policy watcher.
func (m *ConfigManager) PolicyWatcher() *PolicyWatcher {
	return m.policyWatcher
}

// Runtime returns the runtime configuration.
func (m *ConfigManager) Runtime() *RuntimeConfig {
	return m.runtime
}

// Register registers a reloadable value by name.
func (m *ConfigManager) Register(name string, reloadable any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadables[name] = reloadable
}

// Get retrieves a registered reloadable by name.
func (m *ConfigManager) Get(name string) (any, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.reloadables[name]
	return v, ok
}

// TriggerReload triggers a manual reload of all watched resources.
func (m *ConfigManager) TriggerReload() error {
	if m.policyWatcher != nil {
		return m.policyWatcher.TriggerReload()
	}
	return nil
}

// Status returns the current status of all managed components.
type ConfigManagerStatus struct {
	Running       bool           `json:"running"`
	WatcherStats  *WatcherStats  `json:"watcher_stats,omitempty"`
	RuntimeConfig *RuntimeConfigSnapshot `json:"runtime_config,omitempty"`
}

// Status returns the current status.
func (m *ConfigManager) Status() ConfigManagerStatus {
	status := ConfigManagerStatus{
		Running: m.running.Load(),
	}

	if m.policyWatcher != nil {
		stats := m.policyWatcher.Stats()
		status.WatcherStats = &stats
	}

	if m.runtime != nil {
		snapshot := m.runtime.Snapshot()
		status.RuntimeConfig = &snapshot
	}

	return status
}
