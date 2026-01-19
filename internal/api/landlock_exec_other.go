//go:build !linux

package api

import (
	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

// MakeLandlockPostStartHook returns nil on non-Linux platforms.
func MakeLandlockPostStartHook(
	cfg *config.LandlockConfig,
	secCaps *capabilities.SecurityCapabilities,
	workspace string,
	pol *policy.Policy,
) postStartHook {
	return nil
}

// GetLandlockEnvVars returns nil on non-Linux platforms.
func GetLandlockEnvVars(cfg *config.LandlockConfig, workspace string, abi int) map[string]string {
	return nil
}
