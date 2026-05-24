package config

import (
	"strings"
	"testing"
)

// Issue #376: validateConfig (run by config.Load and `agentsh config validate`)
// must enforce the config-schema cross-field invariants the server also checks
// at startup, with the same messages, so misconfig is caught pre-deploy.

func TestValidateConfig_RejectsPtraceUnixSocketsNonExecveOnly(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	enabled := true
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.Seccomp.Execve.Enabled = false // isolate the unix_sockets path (else ptrace+seccomp.execve mutual-exclusion fires first)
	cfg.Sandbox.Ptrace = DefaultPtraceConfig() // valid sub-fields; Trace.* all true => NOT execve-only
	cfg.Sandbox.Ptrace.Enabled = true

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("ptrace + unix_sockets with non-execve-only tracing must fail validation")
	}
	if !strings.Contains(err.Error(), "sandbox config:") || !strings.Contains(err.Error(), "requires execve-only tracing") {
		t.Errorf("error should match the startup message; got: %v", err)
	}
}

func TestValidateConfig_RejectsPtraceWithSeccompExecve(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Sandbox.Ptrace = DefaultPtraceConfig()
	cfg.Sandbox.Ptrace.Enabled = true
	cfg.Sandbox.Seccomp.Execve.Enabled = true

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("ptrace + seccomp.execve must fail validation (mutually exclusive)")
	}
	if !strings.Contains(err.Error(), "sandbox config:") || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should match the startup message; got: %v", err)
	}
}

func TestValidateConfig_RejectsSigningEnforceWithoutTrustStore(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Policies.Signing.Mode = "enforce"
	cfg.Policies.Signing.TrustStore = ""

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("signing mode=enforce without trust_store must fail validation")
	}
	if !strings.Contains(err.Error(), "signing config:") || !strings.Contains(err.Error(), "trust_store is required") {
		t.Errorf("error should match the startup message; got: %v", err)
	}
}

func TestValidateConfig_RejectsSigningWarnWithoutTrustStore(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Policies.Signing.Mode = "warn"
	cfg.Policies.Signing.TrustStore = ""

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("signing mode=warn without trust_store must fail validation")
	}
	if !strings.Contains(err.Error(), "signing config:") || !strings.Contains(err.Error(), "trust_store is required") {
		t.Errorf("error should match the startup message; got: %v", err)
	}
}

func TestValidateConfig_AcceptsDefaultBaseline(t *testing.T) {
	// Regression guard: the newly-wired validators must NOT reject a normal
	// default config (also confirms validateConfig still reaches its tail).
	cfg := &Config{}
	applyDefaults(cfg)
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("default config must validate cleanly; got: %v", err)
	}
}

func TestValidateConfig_AcceptsExecveOnlyPtraceWithUnixSockets(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	enabled := true
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.Seccomp.Execve.Enabled = false
	cfg.Sandbox.Ptrace = DefaultPtraceConfig()
	cfg.Sandbox.Ptrace.Enabled = true
	cfg.Sandbox.Ptrace.Trace.File = false
	cfg.Sandbox.Ptrace.Trace.Network = false
	cfg.Sandbox.Ptrace.Trace.Signal = false // now execve-only

	if err := validateConfig(cfg); err != nil {
		t.Fatalf("execve-only ptrace + unix_sockets must validate cleanly; got: %v", err)
	}
}
