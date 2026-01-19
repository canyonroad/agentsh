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

// MakeLandlockPostStartHook creates a postStartHook that prepares Landlock restrictions.
// Note: Full Landlock enforcement requires applying restrictions in the child process
// before exec, which requires a wrapper binary. This hook prepares the ruleset that
// would be passed to such a wrapper.
//
// Returns nil if Landlock is disabled or unavailable.
func MakeLandlockPostStartHook(
	cfg *config.LandlockConfig,
	secCaps *capabilities.SecurityCapabilities,
	workspace string,
	pol *policy.Policy,
) postStartHook {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	if secCaps == nil || !secCaps.Landlock {
		return nil
	}

	return func(pid int) (cleanup func() error, err error) {
		// Build the ruleset configuration
		builder, err := landlock.BuildFromConfig(cfg, pol, workspace, secCaps.LandlockABI)
		if err != nil {
			slog.Error("failed to build landlock config",
				"error", err,
				"pid", pid,
			)
			// Non-fatal: return nil to continue without Landlock
			return nil, nil
		}

		// Log the configuration for debugging
		slog.Debug("landlock configuration prepared",
			"pid", pid,
			"workspace", workspace,
			"abi", secCaps.LandlockABI,
			"execute_paths", len(cfg.AllowExecute),
			"read_paths", len(cfg.AllowRead),
			"deny_paths", len(cfg.DenyPaths),
		)

		// Note: To actually enforce Landlock, we need one of:
		// 1. A wrapper binary that the child execs through, which applies Landlock
		// 2. Use /proc/PID/ns/user to enter the child's namespace and apply
		// 3. Have the child apply it before exec (requires fork/exec control)
		//
		// For now, we prepare the config and document what would be needed.
		// The capability dropping can be done via the capabilities package.

		// Drop capabilities in the parent's context (this affects children via bounding set)
		// Note: This is partial protection - full protection requires applying in child
		if err := capabilities.DropCapabilities(cfg.AllowExecute); err != nil {
			slog.Warn("failed to drop capabilities",
				"error", err,
				"pid", pid,
			)
		}

		_ = builder // Suppress unused variable warning for now

		// No cleanup needed
		return nil, nil
	}
}

// GetLandlockEnvVars returns environment variables to pass to child processes
// for Landlock-aware wrapper binaries.
func GetLandlockEnvVars(cfg *config.LandlockConfig, workspace string, abi int) map[string]string {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	return map[string]string{
		"AGENTSH_LANDLOCK_ENABLED":   "1",
		"AGENTSH_LANDLOCK_WORKSPACE": workspace,
		"AGENTSH_LANDLOCK_ABI":       fmt.Sprintf("%d", abi),
	}
}
