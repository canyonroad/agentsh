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
