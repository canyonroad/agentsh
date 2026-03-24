//go:build darwin && cgo

package api

import (
	"log/slog"

	"github.com/agentsh/agentsh/internal/platform/darwin"
	"github.com/agentsh/agentsh/internal/policy"
)

// compileDarwinSandboxProfile compiles a policy-driven SBPL profile and populates
// the wrapper config's CompiledProfile and ExtensionTokens fields.
// Returns true if compilation succeeded, false to fall back to legacy profile.
func compileDarwinSandboxProfile(cfg *macSandboxWrapperConfig, engine *policy.Engine, workspace string) bool {
	pol := engine.Policy()
	if pol == nil {
		return false
	}

	sandboxCfg, err := darwin.CompileDarwinSandbox(pol, workspace)
	if err != nil {
		slog.Warn("failed to compile darwin sandbox profile, falling back to legacy",
			"error", err)
		return false
	}

	cfg.CompiledProfile = sandboxCfg.Profile
	cfg.ExtensionTokens = sandboxCfg.TokenValues
	return true
}
