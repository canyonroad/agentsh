package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSandboxXPCConfig_Defaults(t *testing.T) {
	yamlData := `
sandbox:
  xpc:
    enabled: true
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	applyDefaults(&cfg)

	if cfg.Sandbox.XPC.Mode != "enforce" {
		t.Errorf("mode should default to enforce, got %q", cfg.Sandbox.XPC.Mode)
	}
	if cfg.Sandbox.XPC.MachServices.DefaultAction != "deny" {
		t.Errorf("default_action should default to deny, got %q", cfg.Sandbox.XPC.MachServices.DefaultAction)
	}
}

func TestSandboxXPCConfig_Validation(t *testing.T) {
	yamlData := `
sandbox:
  xpc:
    enabled: true
    mode: invalid_mode
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	applyDefaults(&cfg)
	err := validateConfig(&cfg)
	if err == nil {
		t.Error("expected validation error for invalid mode")
	}
}

func TestSandboxXPCConfig_Parse(t *testing.T) {
	yamlData := `
sandbox:
  xpc:
    enabled: true
    mode: enforce
    mach_services:
      default_action: deny
      allow:
        - "com.apple.system.logger"
      block:
        - "com.apple.security.authhost"
      allow_prefixes:
        - "com.apple.cfprefsd."
      block_prefixes:
        - "com.apple.accessibility."
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !cfg.Sandbox.XPC.Enabled {
		t.Error("xpc.enabled should be true")
	}
	if cfg.Sandbox.XPC.Mode != "enforce" {
		t.Errorf("xpc.mode = %q, want enforce", cfg.Sandbox.XPC.Mode)
	}
	if cfg.Sandbox.XPC.MachServices.DefaultAction != "deny" {
		t.Errorf("default_action = %q, want deny", cfg.Sandbox.XPC.MachServices.DefaultAction)
	}
	if len(cfg.Sandbox.XPC.MachServices.Allow) != 1 {
		t.Errorf("allow len = %d, want 1", len(cfg.Sandbox.XPC.MachServices.Allow))
	}
	if len(cfg.Sandbox.XPC.MachServices.AllowPrefixes) != 1 {
		t.Errorf("allow_prefixes len = %d, want 1", len(cfg.Sandbox.XPC.MachServices.AllowPrefixes))
	}
}
