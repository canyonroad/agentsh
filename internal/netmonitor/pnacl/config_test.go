package pnacl

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool {
	return &b
}

func TestParseConfig_WrappedFormat(t *testing.T) {
	yaml := `
network_acl:
  default: deny

  processes:
    - name: "claude-code"
      match:
        process_name: "claude-code"
        path: "/usr/bin/claude-code"
        bundle_id: "com.anthropic.claudecode"
        strict: true

      default: approve

      rules:
        - target: "api.anthropic.com"
          port: "443"
          protocol: tcp
          decision: allow

        - target: "*.anthropic.com"
          port: "443"
          decision: allow

        - cidr: "10.0.0.0/8"
          decision: deny

      children:
        - name: "curl"
          match:
            process_name: "curl"
          inherit: true
          rules:
            - target: "pypi.org"
              port: "443"
              decision: allow
`

	config, err := ParseConfig([]byte(yaml))
	require.NoError(t, err)

	assert.Equal(t, "deny", config.Default)
	require.Len(t, config.Processes, 1)

	proc := config.Processes[0]
	assert.Equal(t, "claude-code", proc.Name)
	assert.Equal(t, "claude-code", proc.Match.ProcessName)
	assert.Equal(t, "/usr/bin/claude-code", proc.Match.Path)
	assert.Equal(t, "com.anthropic.claudecode", proc.Match.BundleID)
	assert.True(t, proc.Match.Strict)
	assert.Equal(t, "approve", proc.Default)

	require.Len(t, proc.Rules, 3)
	assert.Equal(t, "api.anthropic.com", proc.Rules[0].Host)
	assert.Equal(t, "443", proc.Rules[0].Port)
	assert.Equal(t, "tcp", proc.Rules[0].Protocol)
	assert.Equal(t, DecisionAllow, proc.Rules[0].Decision)

	assert.Equal(t, "*.anthropic.com", proc.Rules[1].Host)
	assert.Equal(t, "10.0.0.0/8", proc.Rules[2].CIDR)

	require.Len(t, proc.Children, 1)
	child := proc.Children[0]
	assert.Equal(t, "curl", child.Name)
	assert.Equal(t, "curl", child.Match.ProcessName)
	assert.True(t, child.InheritRules()) // Explicitly set to true in YAML
	require.Len(t, child.Rules, 1)
	assert.Equal(t, "pypi.org", child.Rules[0].Host)
}

func TestParseConfig_DirectFormat(t *testing.T) {
	yaml := `
default: allow

processes:
  - name: "my-app"
    match:
      process_name: "my-app"
    rules:
      - target: "api.example.com"
        decision: allow
`

	config, err := ParseConfig([]byte(yaml))
	require.NoError(t, err)

	assert.Equal(t, "allow", config.Default)
	require.Len(t, config.Processes, 1)
	assert.Equal(t, "my-app", config.Processes[0].Name)
}

func TestLoadConfig_FromFile(t *testing.T) {
	yaml := `
network_acl:
  default: deny
  processes:
    - name: "test-app"
      match:
        process_name: "test-app"
      rules:
        - target: "example.com"
          decision: allow
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "pnacl.yaml")
	err := os.WriteFile(configPath, []byte(yaml), 0644)
	require.NoError(t, err)

	config, err := LoadConfig(configPath)
	require.NoError(t, err)

	assert.Equal(t, "deny", config.Default)
	require.Len(t, config.Processes, 1)
	assert.Equal(t, "test-app", config.Processes[0].Name)
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	assert.Error(t, err)
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Default: "deny",
				Processes: []ProcessConfig{
					{
						Name: "test",
						Match: ProcessMatchCriteria{
							ProcessName: "test",
						},
						Rules: []NetworkTarget{
							{
								Host:     "example.com",
								Decision: DecisionAllow,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid default decision",
			config: Config{
				Default: "invalid",
			},
			wantErr: true,
		},
		{
			name: "missing process name",
			config: Config{
				Processes: []ProcessConfig{
					{
						Match: ProcessMatchCriteria{
							ProcessName: "test",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing match criteria",
			config: Config{
				Processes: []ProcessConfig{
					{
						Name: "test",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid rule decision",
			config: Config{
				Processes: []ProcessConfig{
					{
						Name: "test",
						Match: ProcessMatchCriteria{
							ProcessName: "test",
						},
						Rules: []NetworkTarget{
							{
								Host:     "example.com",
								Decision: Decision("invalid"),
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "rule missing target",
			config: Config{
				Processes: []ProcessConfig{
					{
						Name: "test",
						Match: ProcessMatchCriteria{
							ProcessName: "test",
						},
						Rules: []NetworkTarget{
							{
								Decision: DecisionAllow,
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "rule missing decision",
			config: Config{
				Processes: []ProcessConfig{
					{
						Name: "test",
						Match: ProcessMatchCriteria{
							ProcessName: "test",
						},
						Rules: []NetworkTarget{
							{
								Host: "example.com",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			config: Config{
				Processes: []ProcessConfig{
					{
						Name: "test",
						Match: ProcessMatchCriteria{
							ProcessName: "test",
						},
						Rules: []NetworkTarget{
							{
								Host:     "example.com",
								Protocol: "invalid",
								Decision: DecisionAllow,
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid child config",
			config: Config{
				Processes: []ProcessConfig{
					{
						Name: "parent",
						Match: ProcessMatchCriteria{
							ProcessName: "parent",
						},
						Children: []ChildConfig{
							{
								Name: "child",
								Match: ProcessMatchCriteria{
									ProcessName: "child",
								},
								Inherit: boolPtr(true),
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "child missing name",
			config: Config{
				Processes: []ProcessConfig{
					{
						Name: "parent",
						Match: ProcessMatchCriteria{
							ProcessName: "parent",
						},
						Children: []ChildConfig{
							{
								Match: ProcessMatchCriteria{
									ProcessName: "child",
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "child missing match criteria",
			config: Config{
				Processes: []ProcessConfig{
					{
						Name: "parent",
						Match: ProcessMatchCriteria{
							ProcessName: "parent",
						},
						Children: []ChildConfig{
							{
								Name: "child",
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMergeConfigs(t *testing.T) {
	base := &Config{
		Default: "deny",
		Processes: []ProcessConfig{
			{
				Name: "app-a",
				Match: ProcessMatchCriteria{
					ProcessName: "app-a",
				},
				Default: "approve",
				Rules: []NetworkTarget{
					{
						Host:     "base.example.com",
						Decision: DecisionAllow,
					},
				},
				Children: []ChildConfig{
					{
						Name: "child-a",
						Match: ProcessMatchCriteria{
							ProcessName: "child-a",
						},
						Inherit: boolPtr(true),
						Rules: []NetworkTarget{
							{
								Host:     "child-base.example.com",
								Decision: DecisionAllow,
							},
						},
					},
				},
			},
			{
				Name: "app-b",
				Match: ProcessMatchCriteria{
					ProcessName: "app-b",
				},
				Rules: []NetworkTarget{
					{
						Host:     "app-b.example.com",
						Decision: DecisionAllow,
					},
				},
			},
		},
	}

	override := &Config{
		Default: "allow",
		Processes: []ProcessConfig{
			{
				Name: "app-a",
				Match: ProcessMatchCriteria{
					ProcessName: "app-a-override",
				},
				Default: "deny",
				Rules: []NetworkTarget{
					{
						Host:     "override.example.com",
						Decision: DecisionDeny,
					},
				},
				Children: []ChildConfig{
					{
						Name: "child-a",
						Match: ProcessMatchCriteria{
							ProcessName: "child-a-override",
						},
						Inherit: boolPtr(false),
						Rules: []NetworkTarget{
							{
								Host:     "child-override.example.com",
								Decision: DecisionDeny,
							},
						},
					},
				},
			},
			{
				Name: "app-c",
				Match: ProcessMatchCriteria{
					ProcessName: "app-c",
				},
				Rules: []NetworkTarget{
					{
						Host:     "app-c.example.com",
						Decision: DecisionAllow,
					},
				},
			},
		},
	}

	merged := MergeConfigs(base, override)

	// Override default should take precedence.
	assert.Equal(t, "allow", merged.Default)

	// Should have 3 processes: app-a (merged), app-b (base only), app-c (override only).
	require.Len(t, merged.Processes, 3)

	// Find merged app-a.
	var appA *ProcessConfig
	var appB *ProcessConfig
	var appC *ProcessConfig
	for i := range merged.Processes {
		switch merged.Processes[i].Name {
		case "app-a":
			appA = &merged.Processes[i]
		case "app-b":
			appB = &merged.Processes[i]
		case "app-c":
			appC = &merged.Processes[i]
		}
	}

	require.NotNil(t, appA)
	require.NotNil(t, appB)
	require.NotNil(t, appC)

	// app-a should have override match criteria.
	assert.Equal(t, "app-a-override", appA.Match.ProcessName)

	// app-a should have override default.
	assert.Equal(t, "deny", appA.Default)

	// app-a rules should have override first, then base.
	require.Len(t, appA.Rules, 2)
	assert.Equal(t, "override.example.com", appA.Rules[0].Host)
	assert.Equal(t, "base.example.com", appA.Rules[1].Host)

	// app-a children should be merged.
	require.Len(t, appA.Children, 1)
	childA := appA.Children[0]
	assert.Equal(t, "child-a", childA.Name)
	assert.Equal(t, "child-a-override", childA.Match.ProcessName)
	assert.False(t, childA.InheritRules()) // Explicitly set to false in override.
	require.Len(t, childA.Rules, 2)
	assert.Equal(t, "child-override.example.com", childA.Rules[0].Host)
	assert.Equal(t, "child-base.example.com", childA.Rules[1].Host)

	// app-b should be unchanged from base.
	assert.Equal(t, "app-b", appB.Match.ProcessName)

	// app-c should be from override.
	assert.Equal(t, "app-c", appC.Match.ProcessName)
}

func TestMergeConfigs_NilInputs(t *testing.T) {
	config := &Config{Default: "allow"}

	// Nil base returns override.
	merged := MergeConfigs(nil, config)
	assert.Equal(t, config, merged)

	// Nil override returns base.
	merged = MergeConfigs(config, nil)
	assert.Equal(t, config, merged)
}

func TestConfig_Clone(t *testing.T) {
	original := &Config{
		Default: "deny",
		Processes: []ProcessConfig{
			{
				Name: "app",
				Match: ProcessMatchCriteria{
					ProcessName: "app",
				},
				Default: "approve",
				Rules: []NetworkTarget{
					{
						Host:     "example.com",
						Decision: DecisionAllow,
					},
				},
				Children: []ChildConfig{
					{
						Name: "child",
						Match: ProcessMatchCriteria{
							ProcessName: "child",
						},
						Inherit: boolPtr(true),
						Rules: []NetworkTarget{
							{
								Host:     "child.example.com",
								Decision: DecisionAllow,
							},
						},
					},
				},
			},
		},
	}

	clone := original.Clone()

	// Verify clone matches original.
	assert.Equal(t, original.Default, clone.Default)
	require.Len(t, clone.Processes, 1)
	assert.Equal(t, original.Processes[0].Name, clone.Processes[0].Name)

	// Modify clone and verify original is unchanged.
	clone.Default = "allow"
	clone.Processes[0].Name = "modified"
	clone.Processes[0].Rules[0].Host = "modified.com"
	clone.Processes[0].Children[0].Rules[0].Host = "child-modified.com"

	assert.Equal(t, "deny", original.Default)
	assert.Equal(t, "app", original.Processes[0].Name)
	assert.Equal(t, "example.com", original.Processes[0].Rules[0].Host)
	assert.Equal(t, "child.example.com", original.Processes[0].Children[0].Rules[0].Host)
}

func TestConfig_Clone_Nil(t *testing.T) {
	var config *Config
	clone := config.Clone()
	assert.Nil(t, clone)
}

func TestParseConfig_InvalidYAML(t *testing.T) {
	yaml := `
invalid yaml content
  - not proper yaml
`
	_, err := ParseConfig([]byte(yaml))
	assert.Error(t, err)
}

func TestParseConfig_InvalidFieldYAML(t *testing.T) {
	yaml := `
network_acl:
  default: deny
  unknown_field: value
`
	_, err := ParseConfig([]byte(yaml))
	assert.Error(t, err)
}

func TestProcessConfig_Clone(t *testing.T) {
	original := ProcessConfig{
		Name: "test",
		Match: ProcessMatchCriteria{
			ProcessName: "test",
		},
		Default: "approve",
		Rules: []NetworkTarget{
			{Host: "example.com", Decision: DecisionAllow},
		},
		Children: []ChildConfig{
			{
				Name:    "child",
				Match:   ProcessMatchCriteria{ProcessName: "child"},
				Inherit: boolPtr(true),
			},
		},
	}

	clone := original.Clone()

	// Verify independence.
	clone.Name = "modified"
	clone.Rules[0].Host = "modified.com"
	clone.Children[0].Name = "modified-child"

	assert.Equal(t, "test", original.Name)
	assert.Equal(t, "example.com", original.Rules[0].Host)
	assert.Equal(t, "child", original.Children[0].Name)
}

func TestChildConfig_Clone(t *testing.T) {
	original := ChildConfig{
		Name:    "child",
		Match:   ProcessMatchCriteria{ProcessName: "child"},
		Inherit: boolPtr(true),
		Rules: []NetworkTarget{
			{Host: "example.com", Decision: DecisionAllow},
		},
	}

	clone := original.Clone()

	// Verify independence.
	clone.Name = "modified"
	clone.Rules[0].Host = "modified.com"

	assert.Equal(t, "child", original.Name)
	assert.Equal(t, "example.com", original.Rules[0].Host)
}

func TestValidateNetworkTarget_AllDecisionTypes(t *testing.T) {
	decisions := []Decision{
		DecisionAllow,
		DecisionDeny,
		DecisionApprove,
		DecisionAllowOnceThenApprove,
		DecisionAudit,
	}

	for _, d := range decisions {
		t.Run(string(d), func(t *testing.T) {
			target := NetworkTarget{
				Host:     "example.com",
				Decision: d,
			}
			err := validateNetworkTarget(target)
			assert.NoError(t, err)
		})
	}
}

func TestValidateNetworkTarget_ValidProtocols(t *testing.T) {
	protocols := []string{"tcp", "udp", "*", ""}

	for _, p := range protocols {
		t.Run(p, func(t *testing.T) {
			target := NetworkTarget{
				Host:     "example.com",
				Protocol: p,
				Decision: DecisionAllow,
			}
			err := validateNetworkTarget(target)
			assert.NoError(t, err)
		})
	}
}

func TestParseConfig_WithApprovalUI(t *testing.T) {
	yaml := `
network_acl:
  default: deny
  approval_ui:
    mode: enabled
    timeout: 30s
  processes:
    - name: "test-app"
      match:
        process_name: "test-app"
      rules:
        - target: "example.com"
          decision: approve
`

	config, err := ParseConfig([]byte(yaml))
	require.NoError(t, err)

	assert.Equal(t, "deny", config.Default)
	require.NotNil(t, config.ApprovalUI)
	assert.Equal(t, "enabled", config.ApprovalUI.Mode)
	assert.Equal(t, "30s", config.ApprovalUI.Timeout)
	assert.Equal(t, "enabled", config.ApprovalUI.GetMode())
	assert.Equal(t, 30*time.Second, config.ApprovalUI.GetTimeout())
}

func TestParseConfig_WithApprovalUIDirectFormat(t *testing.T) {
	yaml := `
default: allow
approval_ui:
  mode: disabled
processes:
  - name: "my-app"
    match:
      process_name: "my-app"
    rules:
      - target: "api.example.com"
        decision: allow
`

	config, err := ParseConfig([]byte(yaml))
	require.NoError(t, err)

	assert.Equal(t, "allow", config.Default)
	require.NotNil(t, config.ApprovalUI)
	assert.Equal(t, "disabled", config.ApprovalUI.Mode)
	assert.Equal(t, "", config.ApprovalUI.Timeout)
	assert.Equal(t, "disabled", config.ApprovalUI.GetMode())
	assert.Equal(t, time.Duration(0), config.ApprovalUI.GetTimeout())
}

func TestApprovalUIConfig_GetMode(t *testing.T) {
	tests := []struct {
		name     string
		config   *ApprovalUIConfig
		expected string
	}{
		{
			name:     "nil config returns auto",
			config:   nil,
			expected: "auto",
		},
		{
			name:     "empty mode returns auto",
			config:   &ApprovalUIConfig{Mode: ""},
			expected: "auto",
		},
		{
			name:     "auto mode returns auto",
			config:   &ApprovalUIConfig{Mode: "auto"},
			expected: "auto",
		},
		{
			name:     "enabled mode returns enabled",
			config:   &ApprovalUIConfig{Mode: "enabled"},
			expected: "enabled",
		},
		{
			name:     "disabled mode returns disabled",
			config:   &ApprovalUIConfig{Mode: "disabled"},
			expected: "disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.GetMode())
		})
	}
}

func TestApprovalUIConfig_GetTimeout(t *testing.T) {
	tests := []struct {
		name     string
		config   *ApprovalUIConfig
		expected time.Duration
	}{
		{
			name:     "nil config returns 0",
			config:   nil,
			expected: 0,
		},
		{
			name:     "empty timeout returns 0",
			config:   &ApprovalUIConfig{Timeout: ""},
			expected: 0,
		},
		{
			name:     "30s timeout",
			config:   &ApprovalUIConfig{Timeout: "30s"},
			expected: 30 * time.Second,
		},
		{
			name:     "1m timeout",
			config:   &ApprovalUIConfig{Timeout: "1m"},
			expected: time.Minute,
		},
		{
			name:     "2m30s timeout",
			config:   &ApprovalUIConfig{Timeout: "2m30s"},
			expected: 2*time.Minute + 30*time.Second,
		},
		{
			name:     "invalid timeout returns 0",
			config:   &ApprovalUIConfig{Timeout: "invalid"},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.GetTimeout())
		})
	}
}

