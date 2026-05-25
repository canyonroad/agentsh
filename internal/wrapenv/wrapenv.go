// Package wrapenv applies env_policy filtering to the inherited environment on
// the client-spawned wrap path (shell shim / kernel-install / agentsh wrap),
// the counterpart to server-side buildPolicyEnv. Issue #379.
package wrapenv

import (
	"log/slog"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// Filter applies the wrapped command's env policy subtractively over the
// inherited base environment. A nil wire returns base unchanged (fail-open for
// the default-off and mixed-version cases). On a BuildEnv error it returns base
// unchanged with a warning — env filtering must never block a command.
func Filter(base []string, wire *types.EnvPolicyWire) []string {
	if wire == nil {
		return base
	}
	pol := policy.ResolvedEnvPolicy{
		Allow:    wire.Allow,
		Deny:     wire.Deny,
		MaxBytes: wire.MaxBytes,
		MaxKeys:  wire.MaxKeys,
	}
	out, err := policy.BuildEnv(pol, base, nil)
	if err != nil {
		slog.Warn("wrap env policy filter failed; passing inherited env unfiltered", "error", err)
		return base
	}
	return out
}
