package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSeccompConfigParse(t *testing.T) {
	yamlData := `
sandbox:
  seccomp:
    enabled: true
    mode: enforce
    unix_socket:
      enabled: true
      action: enforce
    syscalls:
      default_action: allow
      block:
        - ptrace
        - mount
      on_block: kill
`
	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	require.NoError(t, err)

	require.True(t, cfg.Sandbox.Seccomp.Enabled)
	require.Equal(t, "enforce", cfg.Sandbox.Seccomp.Mode)
	require.True(t, cfg.Sandbox.Seccomp.UnixSocket.Enabled)
	require.Equal(t, "enforce", cfg.Sandbox.Seccomp.UnixSocket.Action)
	require.Equal(t, "allow", cfg.Sandbox.Seccomp.Syscalls.DefaultAction)
	require.Contains(t, cfg.Sandbox.Seccomp.Syscalls.Block, "ptrace")
	require.Contains(t, cfg.Sandbox.Seccomp.Syscalls.Block, "mount")
	require.Equal(t, "kill", cfg.Sandbox.Seccomp.Syscalls.OnBlock)
}

func TestOnBlockExplicitValues(t *testing.T) {
	for _, v := range []string{"errno", "kill", "log", "log_and_kill"} {
		t.Run(v, func(t *testing.T) {
			yamlData := `
sandbox:
  seccomp:
    enabled: true
    syscalls:
      on_block: ` + v + `
`
			var cfg Config
			require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))
			require.Equal(t, v, cfg.Sandbox.Seccomp.Syscalls.OnBlock)
		})
	}
}

func TestFileMonitorAutoEnable_ExplicitFalse(t *testing.T) {
	// When user explicitly sets file_monitor.enabled: false,
	// it must NOT be overridden to true by the auto-enable logic.
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: true
    file_monitor:
      enabled: false
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	// Before defaults: user's explicit false should be preserved as *false
	require.NotNil(t, cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"explicit false must parse as non-nil *bool")
	require.False(t, *cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"explicit false must be *false")

	// After defaults: explicit false must survive the auto-enable logic.
	applyDefaults(&cfg)
	require.NotNil(t, cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"applyDefaults must not nil out explicit false")
	require.False(t, *cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"applyDefaults must not override explicit false")
}

func TestFileMonitorAutoEnable_Omitted(t *testing.T) {
	// When user omits file_monitor entirely, Enabled should be nil
	// (so auto-enable logic can default it to true).
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: true
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	require.Nil(t, cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"omitted field must be nil")

	// After defaults: omitted field should be auto-enabled to *true.
	applyDefaults(&cfg)
	require.NotNil(t, cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"applyDefaults must set omitted field")
	require.True(t, *cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"applyDefaults must auto-enable omitted file_monitor")
}

func TestSeccompConfigDefaults(t *testing.T) {
	yamlData := `
sandbox:
  seccomp:
    enabled: true
`
	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	require.NoError(t, err)

	applyDefaults(&cfg)

	require.True(t, cfg.Sandbox.Seccomp.Enabled)
	require.Equal(t, "enforce", cfg.Sandbox.Seccomp.Mode)
	require.True(t, cfg.Sandbox.Seccomp.UnixSocket.Enabled)
	require.Greater(t, len(cfg.Sandbox.Seccomp.Syscalls.Block), 0)
}

func TestOnBlockDefaultsToErrno(t *testing.T) {
	yamlData := `
sandbox:
  seccomp:
    enabled: true
`
	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))
	applyDefaults(&cfg)
	require.Equal(t, "errno", cfg.Sandbox.Seccomp.Syscalls.OnBlock,
		"default on_block must be errno (matches runtime behavior since b6708353)")
}

func TestOnBlockRejectsUnknown(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.FUSE.Audit.Mode = "monitor" // satisfy existing validator
	cfg.Sandbox.Seccomp.Syscalls.OnBlock = "banana"
	err := validateConfig(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "on_block")
	require.Contains(t, err.Error(), "errno")
	require.Contains(t, err.Error(), "kill")
	require.Contains(t, err.Error(), "log")
	require.Contains(t, err.Error(), "log_and_kill")
}

func TestOnBlockValidatorAcceptsLegalValues(t *testing.T) {
	for _, v := range []string{"", "errno", "kill", "log", "log_and_kill"} {
		t.Run("v="+v, func(t *testing.T) {
			cfg := &Config{}
			cfg.Sandbox.FUSE.Audit.Mode = "monitor"
			cfg.Sandbox.Seccomp.Syscalls.OnBlock = v
			require.NoError(t, validateConfig(cfg))
		})
	}
}

// TestSandboxSeccompSocketFamilyConfig_DefaultMerge verifies that when
// blocked_socket_families is omitted (nil slice), applyDefaults populates
// the list from DefaultBlockedFamilies (including AF_ALG).
func TestSandboxSeccompSocketFamilyConfig_DefaultMerge(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	applyDefaults(cfg)

	require.NotEmpty(t, cfg.Sandbox.Seccomp.BlockedSocketFamilies,
		"expected default-merge to populate BlockedSocketFamilies; got empty")

	found := false
	for _, e := range cfg.Sandbox.Seccomp.BlockedSocketFamilies {
		if e.Family == "AF_ALG" {
			found = true
			break
		}
	}
	require.True(t, found, "AF_ALG missing from default BlockedSocketFamilies")
}

// TestSandboxSeccompSocketFamilyConfig_ExplicitEmptyOptOut verifies that when
// blocked_socket_families is set to an explicit empty slice (opt-out),
// applyDefaults does NOT replace it with defaults.
func TestSandboxSeccompSocketFamilyConfig_ExplicitEmptyOptOut(t *testing.T) {
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: true
    blocked_socket_families: []
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))
	require.NotNil(t, cfg.Sandbox.Seccomp.BlockedSocketFamilies,
		"explicit [] must parse as non-nil empty slice")

	applyDefaults(&cfg)

	require.Empty(t, cfg.Sandbox.Seccomp.BlockedSocketFamilies,
		"explicit empty should not be replaced by defaults")
}

// TestSandboxSeccompSocketFamilyConfig_NonEmptyOverridesDefaults verifies that
// when the operator provides explicit entries, applyDefaults leaves them alone.
func TestSandboxSeccompSocketFamilyConfig_NonEmptyOverridesDefaults(t *testing.T) {
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: true
    blocked_socket_families:
      - family: AF_VSOCK
        action: errno
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.Len(t, cfg.Sandbox.Seccomp.BlockedSocketFamilies, 1,
		"non-empty should override defaults entirely")
	require.Equal(t, "AF_VSOCK", cfg.Sandbox.Seccomp.BlockedSocketFamilies[0].Family)
}

// TestSandboxSeccompSocketFamilyConfig_OmittedWhenSeccompDisabled verifies that
// defaults are not applied when both seccomp and the unix_sockets wrapper are
// explicitly disabled (seccompActive is false in that case).
func TestSandboxSeccompSocketFamilyConfig_OmittedWhenSeccompDisabled(t *testing.T) {
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: false
  unix_sockets:
    enabled: false
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))
	applyDefaults(&cfg)

	require.Nil(t, cfg.Sandbox.Seccomp.BlockedSocketFamilies,
		"defaults must not be applied when seccomp is disabled")
}

// TestSandboxSeccompSocketFamilyConfig_ParseYAML verifies full YAML round-trip
// for a non-trivial blocked_socket_families list.
func TestSandboxSeccompSocketFamilyConfig_ParseYAML(t *testing.T) {
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: true
    blocked_socket_families:
      - family: AF_ALG
        action: errno
      - family: AF_VSOCK
        action: kill
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	require.Len(t, cfg.Sandbox.Seccomp.BlockedSocketFamilies, 2)
	require.Equal(t, "AF_ALG", cfg.Sandbox.Seccomp.BlockedSocketFamilies[0].Family)
	require.Equal(t, "errno", cfg.Sandbox.Seccomp.BlockedSocketFamilies[0].Action)
	require.Equal(t, "AF_VSOCK", cfg.Sandbox.Seccomp.BlockedSocketFamilies[1].Family)
	require.Equal(t, "kill", cfg.Sandbox.Seccomp.BlockedSocketFamilies[1].Action)
}
