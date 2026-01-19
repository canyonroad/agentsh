//go:build linux

package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
)

func TestMakeLandlockPostStartHook(t *testing.T) {
	cfg := &config.LandlockConfig{
		Enabled:      true,
		AllowExecute: []string{"/usr/bin", "/bin"},
	}

	capsCfg := &config.CapabilitiesConfig{
		Allow: []string{},
	}

	secCaps := &capabilities.SecurityCapabilities{
		Landlock:    true,
		LandlockABI: 3,
	}

	hook := MakeLandlockPostStartHook(cfg, capsCfg, secCaps, "/tmp/workspace", nil)

	if hook == nil {
		t.Error("expected non-nil hook when Landlock enabled")
	}
}

func TestMakeLandlockPostStartHook_Disabled(t *testing.T) {
	cfg := &config.LandlockConfig{
		Enabled: false,
	}

	secCaps := &capabilities.SecurityCapabilities{
		Landlock:    true,
		LandlockABI: 3,
	}

	hook := MakeLandlockPostStartHook(cfg, nil, secCaps, "/tmp/workspace", nil)

	if hook != nil {
		t.Error("expected nil hook when Landlock disabled")
	}
}

func TestMakeLandlockPostStartHook_Unavailable(t *testing.T) {
	cfg := &config.LandlockConfig{
		Enabled: true,
	}

	secCaps := &capabilities.SecurityCapabilities{
		Landlock: false,
	}

	hook := MakeLandlockPostStartHook(cfg, nil, secCaps, "/tmp/workspace", nil)

	if hook != nil {
		t.Error("expected nil hook when Landlock unavailable")
	}
}
