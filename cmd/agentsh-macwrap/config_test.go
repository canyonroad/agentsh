//go:build darwin

package main

import (
	"os"
	"path/filepath"
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

func TestLoadConfig_CompiledProfile(t *testing.T) {
	os.Setenv("AGENTSH_SANDBOX_CONFIG", `{
		"workspace_path": "/tmp/ws",
		"compiled_profile": "(version 1)(allow default)",
		"extension_tokens": ["com.apple.app-sandbox.read:/tmp/extra", "com.apple.app-sandbox.write:/tmp/out"]
	}`)
	defer os.Unsetenv("AGENTSH_SANDBOX_CONFIG")
	os.Unsetenv("AGENTSH_SANDBOX_CONFIG_FILE")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.CompiledProfile != "(version 1)(allow default)" {
		t.Errorf("compiled_profile = %q, want %q", cfg.CompiledProfile, "(version 1)(allow default)")
	}
	if len(cfg.ExtensionTokens) != 2 {
		t.Fatalf("extension_tokens len = %d, want 2", len(cfg.ExtensionTokens))
	}
	if cfg.ExtensionTokens[0] != "com.apple.app-sandbox.read:/tmp/extra" {
		t.Errorf("extension_tokens[0] = %q, want %q", cfg.ExtensionTokens[0], "com.apple.app-sandbox.read:/tmp/extra")
	}
	if cfg.ExtensionTokens[1] != "com.apple.app-sandbox.write:/tmp/out" {
		t.Errorf("extension_tokens[1] = %q, want %q", cfg.ExtensionTokens[1], "com.apple.app-sandbox.write:/tmp/out")
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	os.Unsetenv("AGENTSH_SANDBOX_CONFIG")

	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.json")
	data := []byte(`{
		"workspace_path": "/tmp/file-ws",
		"compiled_profile": "(version 1)(deny default)",
		"allow_network": true
	}`)
	if err := os.WriteFile(cfgFile, data, 0600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	os.Setenv("AGENTSH_SANDBOX_CONFIG_FILE", cfgFile)
	defer os.Unsetenv("AGENTSH_SANDBOX_CONFIG_FILE")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.WorkspacePath != "/tmp/file-ws" {
		t.Errorf("workspace_path = %q, want /tmp/file-ws", cfg.WorkspacePath)
	}
	if cfg.CompiledProfile != "(version 1)(deny default)" {
		t.Errorf("compiled_profile = %q, want %q", cfg.CompiledProfile, "(version 1)(deny default)")
	}
	if !cfg.AllowNetwork {
		t.Error("allow_network should be true")
	}

	// File should be deleted after loading
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Error("config file should be deleted after loading")
	}
}

func TestLoadConfig_BackwardsCompatible(t *testing.T) {
	os.Unsetenv("AGENTSH_SANDBOX_CONFIG_FILE")
	os.Setenv("AGENTSH_SANDBOX_CONFIG", `{
		"workspace_path": "/tmp/old",
		"allowed_paths": ["/usr/bin"],
		"allow_network": false,
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

	if cfg.WorkspacePath != "/tmp/old" {
		t.Errorf("workspace_path = %q, want /tmp/old", cfg.WorkspacePath)
	}
	if len(cfg.AllowedPaths) != 1 || cfg.AllowedPaths[0] != "/usr/bin" {
		t.Errorf("allowed_paths = %v, want [/usr/bin]", cfg.AllowedPaths)
	}
	if cfg.AllowNetwork {
		t.Error("allow_network should be false")
	}
	if cfg.MachServices.DefaultAction != "deny" {
		t.Errorf("default_action = %q, want deny", cfg.MachServices.DefaultAction)
	}
	if cfg.CompiledProfile != "" {
		t.Errorf("compiled_profile should be empty for old config, got %q", cfg.CompiledProfile)
	}
	if len(cfg.ExtensionTokens) != 0 {
		t.Errorf("extension_tokens should be empty for old config, got %v", cfg.ExtensionTokens)
	}
}
