//go:build linux

package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
)

func TestCreateLandlockHook(t *testing.T) {
	cfg := &config.LandlockConfig{
		Enabled:      true,
		AllowExecute: []string{"/usr/bin", "/bin"},
		AllowRead:    []string{"/etc/ssl/certs"},
		DenyPaths:    []string{"/var/run/docker.sock"},
	}

	secCaps := &capabilities.SecurityCapabilities{
		Landlock:    true,
		LandlockABI: 3,
	}

	hook := CreateLandlockHook(cfg, secCaps, "/tmp/workspace", nil)

	if hook == nil {
		t.Error("expected non-nil hook when Landlock available")
	}
}

func TestCreateLandlockHook_Disabled(t *testing.T) {
	cfg := &config.LandlockConfig{
		Enabled: false,
	}

	secCaps := &capabilities.SecurityCapabilities{
		Landlock:    true,
		LandlockABI: 3,
	}

	hook := CreateLandlockHook(cfg, secCaps, "/tmp/workspace", nil)

	if hook != nil {
		t.Error("expected nil hook when Landlock disabled")
	}
}

func TestCreateLandlockHook_Unavailable(t *testing.T) {
	cfg := &config.LandlockConfig{
		Enabled: true,
	}

	secCaps := &capabilities.SecurityCapabilities{
		Landlock: false,
	}

	hook := CreateLandlockHook(cfg, secCaps, "/tmp/workspace", nil)

	if hook != nil {
		t.Error("expected nil hook when Landlock unavailable")
	}
}

func TestCreateLandlockHook_NilConfig(t *testing.T) {
	secCaps := &capabilities.SecurityCapabilities{
		Landlock:    true,
		LandlockABI: 3,
	}

	hook := CreateLandlockHook(nil, secCaps, "/tmp/workspace", nil)

	if hook != nil {
		t.Error("expected nil hook when config is nil")
	}
}

func TestCreateLandlockHook_NilCaps(t *testing.T) {
	cfg := &config.LandlockConfig{
		Enabled: true,
	}

	hook := CreateLandlockHook(cfg, nil, "/tmp/workspace", nil)

	if hook != nil {
		t.Error("expected nil hook when caps is nil")
	}
}
