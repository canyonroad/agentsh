package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findProjectRoot walks up from the current directory to find go.mod.
func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root (go.mod)")
		}
		dir = parent
	}
}

func TestAgentPolicies(t *testing.T) {
	root := findProjectRoot(t)
	policiesDir := filepath.Join(root, "configs", "policies")

	tests := []struct {
		file             string
		name             string
		wantCommandRules int
		wantFileRules    int
		wantNetworkRules int
	}{
		{
			file:             "agent-default.yaml",
			name:             "agent-default",
			wantCommandRules: 4,
			wantFileRules:    3,
			wantNetworkRules: 3,
		},
		{
			file:             "agent-strict.yaml",
			name:             "agent-strict",
			wantCommandRules: 3,
			wantFileRules:    3,
			wantNetworkRules: 1,
		},
		{
			file:             "agent-observe.yaml",
			name:             "agent-observe",
			wantCommandRules: 1,
			wantFileRules:    1,
			wantNetworkRules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(policiesDir, tt.file)
			p, err := LoadFromFile(path)
			require.NoError(t, err, "failed to load policy %s", tt.file)

			assert.Equal(t, 1, p.Version)
			assert.Equal(t, tt.name, p.Name)
			assert.NotEmpty(t, p.Description)

			assert.Len(t, p.CommandRules, tt.wantCommandRules,
				"command_rules count mismatch for %s", tt.name)
			assert.Len(t, p.FileRules, tt.wantFileRules,
				"file_rules count mismatch for %s", tt.name)
			assert.Len(t, p.NetworkRules, tt.wantNetworkRules,
				"network_rules count mismatch for %s", tt.name)

			// Validate returns nil (already checked by LoadFromFile, but be explicit)
			assert.NoError(t, p.Validate())
		})
	}
}

func TestAgentPolicies_DefaultRuleDetails(t *testing.T) {
	root := findProjectRoot(t)
	path := filepath.Join(root, "configs", "policies", "agent-default.yaml")
	p, err := LoadFromFile(path)
	require.NoError(t, err)

	// Check pkg-install requires approval (first rule — must precede dev-tools
	// so that first-match semantics route "npm install" through approval)
	assert.Equal(t, "pkg-install", p.CommandRules[0].Name)
	assert.Equal(t, "approve", p.CommandRules[0].Decision)
	assert.NotEmpty(t, p.CommandRules[0].ArgsPatterns)

	// Check dev-tools rule
	assert.Equal(t, "dev-tools", p.CommandRules[1].Name)
	assert.Equal(t, "allow", p.CommandRules[1].Decision)
	assert.Contains(t, p.CommandRules[1].Commands, "git")
	assert.Contains(t, p.CommandRules[1].Commands, "node")

	// Check dangerous commands denied
	assert.Equal(t, "dangerous", p.CommandRules[3].Name)
	assert.Equal(t, "deny", p.CommandRules[3].Decision)

	// Check workspace file rule
	assert.Equal(t, "workspace", p.FileRules[0].Name)
	assert.Equal(t, "allow", p.FileRules[0].Decision)
	assert.Contains(t, p.FileRules[0].Paths, "${PROJECT_ROOT}/**")

	// Check system write deny
	assert.Equal(t, "system-write", p.FileRules[2].Name)
	assert.Equal(t, "deny", p.FileRules[2].Decision)

	// Check GitHub network access
	assert.Equal(t, "github", p.NetworkRules[1].Name)
	assert.Equal(t, "allow", p.NetworkRules[1].Decision)
	assert.Contains(t, p.NetworkRules[1].Domains, "github.com")
}

func TestAgentPolicies_StrictRuleDetails(t *testing.T) {
	root := findProjectRoot(t)
	path := filepath.Join(root, "configs", "policies", "agent-strict.yaml")
	p, err := LoadFromFile(path)
	require.NoError(t, err)

	// Read-only tools allowed
	assert.Equal(t, "read-only-tools", p.CommandRules[0].Name)
	assert.Equal(t, "allow", p.CommandRules[0].Decision)

	// Git read operations allowed
	assert.Equal(t, "git-read", p.CommandRules[1].Name)
	assert.Equal(t, "allow", p.CommandRules[1].Decision)
	assert.NotEmpty(t, p.CommandRules[1].ArgsPatterns)

	// All other commands require approval
	assert.Equal(t, "all-other-commands", p.CommandRules[2].Name)
	assert.Equal(t, "approve", p.CommandRules[2].Decision)

	// All writes denied
	assert.Equal(t, "all-writes-denied", p.FileRules[2].Name)
	assert.Equal(t, "deny", p.FileRules[2].Decision)

	// All network denied
	assert.Equal(t, "all-network-denied", p.NetworkRules[0].Name)
	assert.Equal(t, "deny", p.NetworkRules[0].Decision)
}

func TestAgentPolicies_ObserveRuleDetails(t *testing.T) {
	root := findProjectRoot(t)
	path := filepath.Join(root, "configs", "policies", "agent-observe.yaml")
	p, err := LoadFromFile(path)
	require.NoError(t, err)

	// All commands audited
	assert.Equal(t, "audit-all-commands", p.CommandRules[0].Name)
	assert.Equal(t, "audit", p.CommandRules[0].Decision)
	assert.Equal(t, []string{"*"}, p.CommandRules[0].Commands)

	// All files audited
	assert.Equal(t, "audit-all-files", p.FileRules[0].Name)
	assert.Equal(t, "audit", p.FileRules[0].Decision)
	assert.Equal(t, []string{"/**"}, p.FileRules[0].Paths)
	assert.Equal(t, []string{"*"}, p.FileRules[0].Operations)

	// All network audited
	assert.Equal(t, "audit-all-network", p.NetworkRules[0].Name)
	assert.Equal(t, "audit", p.NetworkRules[0].Decision)
	assert.Equal(t, []string{"*"}, p.NetworkRules[0].Domains)

	// Audit settings enabled
	assert.True(t, p.Audit.LogAllowed)
	assert.True(t, p.Audit.LogDenied)
	assert.True(t, p.Audit.LogApproved)
	assert.True(t, p.Audit.IncludeStdout)
	assert.True(t, p.Audit.IncludeStderr)
}
