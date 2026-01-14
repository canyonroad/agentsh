package pnacl

import (
	"fmt"
	"sync"
)

// Manager coordinates PNACL policy evaluation.
// It wraps the configuration, matcher, and evaluator components to provide
// a unified interface for network access control decisions.
// Manager is safe for concurrent use.
type Manager struct {
	config    *Config
	matcher   *ConfigMatcher
	evaluator *PolicyEvaluator
	mu        sync.RWMutex
}

// NewManager creates a new PNACL manager from the given configuration.
// Returns an error if the configuration contains invalid patterns.
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = &Config{}
	}

	// Create the config matcher.
	matcher, err := NewConfigMatcherFromConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create matcher: %w", err)
	}

	// Create the policy evaluator from the configuration.
	evaluator := LoadFromConfig(config)

	return &Manager{
		config:    config.Clone(),
		matcher:   matcher,
		evaluator: evaluator,
	}, nil
}

// Evaluate evaluates a connection against the policy.
// It finds the appropriate process ACL and evaluates the connection rules.
// Returns the evaluation result containing the decision and match details.
func (m *Manager) Evaluate(ctx ConnectionContext) EvaluationResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.evaluator.EvaluateConnection(ctx)
}

// UpdateConfig updates the configuration and recompiles all matchers.
// Returns an error if the new configuration contains invalid patterns.
func (m *Manager) UpdateConfig(config *Config) error {
	if config == nil {
		config = &Config{}
	}

	// Create new matcher first to validate before modifying state.
	matcher, err := NewConfigMatcherFromConfig(config)
	if err != nil {
		return fmt.Errorf("create matcher: %w", err)
	}

	// Create new evaluator.
	evaluator := LoadFromConfig(config)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.config = config.Clone()
	m.matcher = matcher
	m.evaluator = evaluator

	return nil
}

// GetConfig returns a copy of the current configuration.
// The returned configuration is safe to modify without affecting the manager.
func (m *Manager) GetConfig() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.config.Clone()
}

// GetMatcher returns the current config matcher.
// This method is provided for advanced use cases that need direct access
// to the matcher for process lookups.
func (m *Manager) GetMatcher() *ConfigMatcher {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.matcher
}

// GetEvaluator returns the current policy evaluator.
// This method is provided for advanced use cases that need direct access
// to the evaluator.
func (m *Manager) GetEvaluator() *PolicyEvaluator {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.evaluator
}

// GetDefaultDecision returns the global default decision from the configuration.
func (m *Manager) GetDefaultDecision() Decision {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config == nil || m.config.Default == "" {
		return DecisionDeny
	}

	return Decision(m.config.Default)
}
