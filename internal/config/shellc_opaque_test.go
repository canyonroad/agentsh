package config

import (
	"strings"
	"testing"
)

// Issue #378: sandbox.seccomp.shellc.opaque controls opaque shell-c handling.
// It defaults to "enforce" and validateConfig rejects unknown values.

func TestApplyDefaults_ShellcOpaqueDefaultsEnforce(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	if got := cfg.Sandbox.Seccomp.Shellc.Opaque; got != "enforce" {
		t.Errorf("default seccomp.shellc.opaque = %q, want \"enforce\"", got)
	}
}

func TestValidateConfig_ShellcOpaqueAcceptsValidValues(t *testing.T) {
	for _, v := range []string{"", "deny", "enforce", "allow"} {
		cfg := &Config{}
		applyDefaults(cfg)
		cfg.Sandbox.Seccomp.Shellc.Opaque = v
		if err := validateConfig(cfg); err != nil {
			t.Errorf("opaque=%q: unexpected validation error: %v", v, err)
		}
	}
}

func TestValidateConfig_ShellcOpaqueRejectsUnknown(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Sandbox.Seccomp.Shellc.Opaque = "bogus"
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("opaque=bogus must fail validation")
	}
	if !strings.Contains(err.Error(), "seccomp.shellc.opaque") {
		t.Errorf("error should name seccomp.shellc.opaque; got: %v", err)
	}
}
