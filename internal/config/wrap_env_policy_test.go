package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// Issue #379: sandbox.wrap_env_policy.enabled is an opt-in flag, default false.

func TestWrapEnvPolicy_DefaultsOff(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	if cfg.Sandbox.WrapEnvPolicy.Enabled {
		t.Error("sandbox.wrap_env_policy.enabled must default to false")
	}
}

func TestWrapEnvPolicy_UnmarshalsTrue(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("sandbox:\n  wrap_env_policy:\n    enabled: true\n"), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cfg.Sandbox.WrapEnvPolicy.Enabled {
		t.Error("sandbox.wrap_env_policy.enabled should be true after unmarshal")
	}
}
