//go:build linux

package api

import (
	"fmt"
	"log/slog"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/landlock"
	"github.com/agentsh/agentsh/internal/policy"
)

// LandlockHook is a post-fork hook that applies Landlock restrictions.
type LandlockHook struct {
	cfg       *config.LandlockConfig
	secCaps   *capabilities.SecurityCapabilities
	workspace string
	policy    *policy.Policy
	logger    *slog.Logger
}

// CreateLandlockHook creates a hook for applying Landlock restrictions.
// Returns nil if Landlock is disabled or unavailable.
func CreateLandlockHook(
	cfg *config.LandlockConfig,
	secCaps *capabilities.SecurityCapabilities,
	workspace string,
	pol *policy.Policy,
) *LandlockHook {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	if secCaps == nil || !secCaps.Landlock {
		return nil
	}

	return &LandlockHook{
		cfg:       cfg,
		secCaps:   secCaps,
		workspace: workspace,
		policy:    pol,
		logger:    slog.Default(),
	}
}

// Apply builds and enforces the Landlock ruleset.
// This should be called in the child process after fork, before exec.
func (h *LandlockHook) Apply() error {
	// Build the ruleset
	builder, err := landlock.BuildFromConfig(h.cfg, h.policy, h.workspace, h.secCaps.LandlockABI)
	if err != nil {
		return fmt.Errorf("build landlock ruleset: %w", err)
	}

	rulesetFd, err := builder.Build()
	if err != nil {
		return fmt.Errorf("create landlock ruleset: %w", err)
	}

	// Enforce the ruleset
	if err := landlock.Enforce(rulesetFd); err != nil {
		return fmt.Errorf("enforce landlock ruleset: %w", err)
	}

	h.logger.Debug("landlock restrictions applied",
		"workspace", h.workspace,
		"abi", h.secCaps.LandlockABI,
		"execute_paths", len(h.cfg.AllowExecute),
		"deny_paths", len(h.cfg.DenyPaths))

	return nil
}

// SetLogger sets a custom logger for the hook.
func (h *LandlockHook) SetLogger(logger *slog.Logger) {
	h.logger = logger
}
