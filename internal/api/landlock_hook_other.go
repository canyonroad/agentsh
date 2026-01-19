//go:build !linux

package api

import (
	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

// LandlockHook is a no-op on non-Linux platforms.
type LandlockHook struct{}

// CreateLandlockHook returns nil on non-Linux platforms.
func CreateLandlockHook(
	cfg *config.LandlockConfig,
	secCaps *capabilities.SecurityCapabilities,
	workspace string,
	pol *policy.Policy,
) *LandlockHook {
	return nil
}

// Apply is a no-op on non-Linux platforms.
func (h *LandlockHook) Apply() error {
	return nil
}
