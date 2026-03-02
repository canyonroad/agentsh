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
			wantCommandRules: 20,
			wantFileRules:    12,
			wantNetworkRules: 15,
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

	// --- Command rules ---

	// Git guardrails come first (redirects before allow-dev-tools)
	assert.Equal(t, "redirect-git-force-push", p.CommandRules[0].Name)
	assert.Equal(t, "redirect", p.CommandRules[0].Decision)

	assert.Equal(t, "redirect-git-hard-reset", p.CommandRules[1].Name)
	assert.Equal(t, "redirect", p.CommandRules[1].Decision)

	assert.Equal(t, "redirect-git-clean", p.CommandRules[2].Name)
	assert.Equal(t, "redirect", p.CommandRules[2].Decision)

	assert.Equal(t, "redirect-git-push-main", p.CommandRules[3].Name)
	assert.Equal(t, "redirect", p.CommandRules[3].Decision)

	assert.Equal(t, "redirect-destructive-rm", p.CommandRules[4].Name)
	assert.Equal(t, "redirect", p.CommandRules[4].Decision)

	// Deny rules follow redirects
	assert.Equal(t, "deny-system-admin", p.CommandRules[5].Name)
	assert.Equal(t, "deny", p.CommandRules[5].Decision)

	assert.Equal(t, "deny-privilege-escalation", p.CommandRules[6].Name)
	assert.Equal(t, "deny", p.CommandRules[6].Decision)

	assert.Equal(t, "deny-raw-network", p.CommandRules[7].Name)
	assert.Equal(t, "deny", p.CommandRules[7].Decision)

	assert.Equal(t, "deny-system-pkg-install", p.CommandRules[8].Name)
	assert.Equal(t, "deny", p.CommandRules[8].Decision)
	assert.NotEmpty(t, p.CommandRules[8].ArgsPatterns)

	// Dev tools allowed
	assert.Equal(t, "allow-dev-tools", p.CommandRules[14].Name)
	assert.Equal(t, "allow", p.CommandRules[14].Decision)
	assert.Contains(t, p.CommandRules[14].Commands, "git")
	assert.Contains(t, p.CommandRules[14].Commands, "node")
	assert.Contains(t, p.CommandRules[14].Commands, "npm")
	assert.Contains(t, p.CommandRules[14].Commands, "cargo")
	assert.Contains(t, p.CommandRules[14].Commands, "go")

	// HTTP tools allowed (network rules are the guard)
	assert.Equal(t, "allow-http-tools", p.CommandRules[16].Name)
	assert.Equal(t, "allow", p.CommandRules[16].Decision)
	assert.Contains(t, p.CommandRules[16].Commands, "curl")
	assert.Contains(t, p.CommandRules[16].Commands, "wget")

	// --- File rules ---

	// Workspace full access
	assert.Equal(t, "allow-workspace", p.FileRules[0].Name)
	assert.Equal(t, "allow", p.FileRules[0].Decision)
	assert.Contains(t, p.FileRules[0].Paths, "${PROJECT_ROOT}/**")

	// Credential paths require approval
	assert.Equal(t, "approve-ssh-keys", p.FileRules[6].Name)
	assert.Equal(t, "approve", p.FileRules[6].Decision)

	assert.Equal(t, "approve-cloud-credentials", p.FileRules[7].Name)
	assert.Equal(t, "approve", p.FileRules[7].Decision)

	// Default deny at the end
	assert.Equal(t, "default-deny-files", p.FileRules[11].Name)
	assert.Equal(t, "deny", p.FileRules[11].Decision)

	// --- Network rules ---

	// LLM providers allowed (agents need their backends)
	assert.Equal(t, "allow-llm-providers", p.NetworkRules[0].Name)
	assert.Equal(t, "allow", p.NetworkRules[0].Decision)
	assert.Contains(t, p.NetworkRules[0].Domains, "api.anthropic.com")
	assert.Contains(t, p.NetworkRules[0].Domains, "api.openai.com")

	// GitHub allowed
	assert.Equal(t, "allow-github", p.NetworkRules[6].Name)
	assert.Equal(t, "allow", p.NetworkRules[6].Decision)
	assert.Contains(t, p.NetworkRules[6].Domains, "github.com")

	// Cloud metadata denied
	assert.Equal(t, "deny-metadata-services", p.NetworkRules[11].Name)
	assert.Equal(t, "deny", p.NetworkRules[11].Decision)

	// Default deny at the end
	assert.Equal(t, "default-deny-network", p.NetworkRules[14].Name)
	assert.Equal(t, "deny", p.NetworkRules[14].Decision)

	// --- Env policy ---
	assert.True(t, p.EnvPolicy.BlockIteration)
	assert.Contains(t, p.EnvPolicy.Deny, "ANTHROPIC_API_KEY")
	assert.Contains(t, p.EnvPolicy.Deny, "OPENAI_API_KEY")
	assert.Contains(t, p.EnvPolicy.Deny, "*_SECRET*")

	// --- Package rules ---
	require.Len(t, p.PackageRules, 2)
	assert.Equal(t, "block", p.PackageRules[0].Action)
	assert.Equal(t, "vulnerability", p.PackageRules[0].Match.FindingType)
	assert.Equal(t, "critical", p.PackageRules[0].Match.Severity)
	assert.Equal(t, "block", p.PackageRules[1].Action)
	assert.Equal(t, "malware", p.PackageRules[1].Match.FindingType)

	// --- Resource limits ---
	assert.Equal(t, 8192, p.ResourceLimits.MaxMemoryMB)
	assert.Equal(t, 100, p.ResourceLimits.CPUQuotaPercent)
	assert.Equal(t, 500, p.ResourceLimits.PidsMax)

	// --- Signal rules ---
	require.Len(t, p.SignalRules, 6)
	assert.Equal(t, "allow-self", p.SignalRules[0].Name)
	assert.Equal(t, "deny-system", p.SignalRules[5].Name)

	// --- Audit ---
	assert.False(t, p.Audit.LogAllowed)
	assert.True(t, p.Audit.LogDenied)
	assert.True(t, p.Audit.LogApproved)
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
