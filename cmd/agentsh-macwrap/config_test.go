//go:build darwin

package main

import (
	"os"
	"testing"
)

func TestLoadConfig_FromEnv(t *testing.T) {
	os.Setenv("AGENTSH_SANDBOX_CONFIG", `{
		"workspace_path": "/tmp/test",
		"allow_network": true,
		"mach_services": {
			"default_action": "deny",
			"allow": ["com.apple.system.logger"]
		}
	}`)
	defer os.Unsetenv("AGENTSH_SANDBOX_CONFIG")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.WorkspacePath != "/tmp/test" {
		t.Errorf("workspace_path = %q, want /tmp/test", cfg.WorkspacePath)
	}
	if !cfg.AllowNetwork {
		t.Error("allow_network should be true")
	}
	if cfg.MachServices.DefaultAction != "deny" {
		t.Errorf("default_action = %q, want deny", cfg.MachServices.DefaultAction)
	}
	if len(cfg.MachServices.Allow) != 1 {
		t.Errorf("allow list len = %d, want 1", len(cfg.MachServices.Allow))
	}
}

func TestLoadConfig_Default(t *testing.T) {
	os.Unsetenv("AGENTSH_SANDBOX_CONFIG")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.MachServices.DefaultAction != "allow" {
		t.Errorf("default should be allow, got %q", cfg.MachServices.DefaultAction)
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	os.Setenv("AGENTSH_SANDBOX_CONFIG", `{invalid}`)
	defer os.Unsetenv("AGENTSH_SANDBOX_CONFIG")

	_, err := loadConfig()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
