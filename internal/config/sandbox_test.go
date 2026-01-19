package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestExecveConfig_Defaults(t *testing.T) {
	cfg := DefaultExecveConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, 1000, cfg.MaxArgc)
	assert.Equal(t, 65536, cfg.MaxArgvBytes)
	assert.Equal(t, "deny", cfg.OnTruncated)
	assert.Equal(t, 10*time.Second, cfg.ApprovalTimeout)
	assert.Equal(t, "deny", cfg.ApprovalTimeoutAction)
	assert.Equal(t, []string{"/usr/local/bin/agentsh", "/usr/local/bin/agentsh-unixwrap", "*.real"}, cfg.InternalBypass)
}

func TestExecveConfig_ParseYAML(t *testing.T) {
	yamlData := `
execve:
  enabled: true
  max_argc: 500
  max_argv_bytes: 32768
  on_truncated: approval
  approval_timeout: 5s
  approval_timeout_action: deny
  internal_bypass:
    - /usr/local/bin/agentsh
    - "*.real"
`
	var cfg SeccompConfig
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	require.NoError(t, err)

	assert.True(t, cfg.Execve.Enabled)
	assert.Equal(t, 500, cfg.Execve.MaxArgc)
	assert.Equal(t, 32768, cfg.Execve.MaxArgvBytes)
	assert.Equal(t, "approval", cfg.Execve.OnTruncated)
	assert.Equal(t, 5*time.Second, cfg.Execve.ApprovalTimeout)
	assert.Contains(t, cfg.Execve.InternalBypass, "/usr/local/bin/agentsh")
}
