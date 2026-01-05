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
