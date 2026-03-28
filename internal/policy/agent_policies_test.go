package policy

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
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
			wantCommandRules: 21,
			wantFileRules:    14,
			wantNetworkRules: 15,
		},
		{
			file:             "agent-strict.yaml",
			name:             "agent-strict",
			wantCommandRules: 3,
			wantFileRules:    4,
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

	// Env files require approval (MUST precede workspace allow)
	assert.Equal(t, "approve-env-files", p.FileRules[0].Name)
	assert.Equal(t, "approve", p.FileRules[0].Decision)
	assert.Contains(t, p.FileRules[0].Paths, "**/.env")

	// Git credentials require approval (MUST precede workspace allow)
	assert.Equal(t, "approve-git-credentials", p.FileRules[1].Name)
	assert.Equal(t, "approve", p.FileRules[1].Decision)
	assert.Contains(t, p.FileRules[1].Paths, "**/.netrc")

	// Workspace full access
	assert.Equal(t, "allow-workspace", p.FileRules[2].Name)
	assert.Equal(t, "allow", p.FileRules[2].Decision)
	assert.Contains(t, p.FileRules[2].Paths, "${PROJECT_ROOT}/**")

	// Credential paths require approval
	assert.Equal(t, "approve-ssh-keys", p.FileRules[8].Name)
	assert.Equal(t, "approve", p.FileRules[8].Decision)

	assert.Equal(t, "approve-cloud-credentials", p.FileRules[9].Name)
	assert.Equal(t, "approve", p.FileRules[9].Decision)

	// Default deny at the end
	assert.Equal(t, "deny-passwd-shadow", p.FileRules[10].Name)
	assert.Equal(t, "deny", p.FileRules[10].Decision)

	assert.Equal(t, "deny-proc-sensitive", p.FileRules[11].Name)
	assert.Equal(t, "deny", p.FileRules[11].Decision)

	assert.Equal(t, "default-deny-files", p.FileRules[13].Name)
	assert.Equal(t, "deny", p.FileRules[13].Decision)

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

// loadAgentDefaultEngine loads agent-default.yaml and creates an engine with
// variable expansion and enforced approvals.
func loadAgentDefaultEngine(t *testing.T) *Engine {
	t.Helper()
	root := findProjectRoot(t)
	path := filepath.Join(root, "configs", "policies", "agent-default.yaml")
	p, err := LoadFromFile(path)
	require.NoError(t, err)

	vars := map[string]string{
		"PROJECT_ROOT": "/home/user/project",
		"GIT_ROOT":     "/home/user/project",
		"HOME":         "/home/user",
	}
	engine, err := NewEngineWithVariables(p, true, true, vars)
	require.NoError(t, err)
	return engine
}

func TestAgentDefault_CommandDecisions(t *testing.T) {
	e := loadAgentDefaultEngine(t)

	tests := []struct {
		name     string
		cmd      string
		args     []string
		wantDec  types.Decision
		wantRule string
	}{
		// Allowed dev tools
		{
			name:     "curl allowed",
			cmd:      "curl",
			args:     []string{"https://example.com"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-http-tools",
		},
		{
			name:     "git status allowed",
			cmd:      "git",
			args:     []string{"status"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-dev-tools",
		},
		{
			name:     "node allowed",
			cmd:      "node",
			args:     []string{"index.js"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-dev-tools",
		},
		{
			name:     "ls allowed",
			cmd:      "ls",
			args:     []string{"-la"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-file-ops",
		},
		{
			name:     "grep allowed",
			cmd:      "grep",
			args:     []string{"-r", "TODO", "."},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-search-tools",
		},
		{
			name:     "jq allowed",
			cmd:      "jq",
			args:     []string{"."},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-text-processing",
		},
		{
			name:     "bash allowed",
			cmd:      "bash",
			args:     []string{"-c", "echo hello"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-shell-exec",
		},
		{
			name:     "docker allowed",
			cmd:      "docker",
			args:     []string{"ps"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-containers",
		},
		{
			name:     "pytest allowed",
			cmd:      "pytest",
			args:     []string{"-v"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-build-test",
		},
		{
			name:     "tar allowed",
			cmd:      "tar",
			args:     []string{"-xzf", "archive.tar.gz"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-archive-tools",
		},
		{
			name:     "ps allowed",
			cmd:      "ps",
			args:     []string{"aux"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-misc-tools",
		},

		// Denied commands
		{
			name:     "sudo denied",
			cmd:      "sudo",
			args:     []string{"rm", "-rf", "/"},
			wantDec:  types.DecisionDeny,
			wantRule: "deny-privilege-escalation",
		},
		{
			name:     "su denied",
			cmd:      "su",
			args:     []string{"-"},
			wantDec:  types.DecisionDeny,
			wantRule: "deny-privilege-escalation",
		},
		{
			name:     "shutdown denied",
			cmd:      "shutdown",
			args:     []string{"-h", "now"},
			wantDec:  types.DecisionDeny,
			wantRule: "deny-system-admin",
		},
		{
			name:     "nc denied",
			cmd:      "nc",
			args:     []string{"-l", "8080"},
			wantDec:  types.DecisionDeny,
			wantRule: "deny-raw-network",
		},
		{
			name:     "apt install denied",
			cmd:      "apt",
			args:     []string{"install", "nginx"},
			wantDec:  types.DecisionDeny,
			wantRule: "deny-system-pkg-install",
		},

		// Git guardrails (redirects)
		{
			name:     "git push --force redirected",
			cmd:      "git",
			args:     []string{"push", "--force"},
			wantDec:  types.DecisionRedirect,
			wantRule: "redirect-git-force-push",
		},
		{
			name:     "git push -f redirected",
			cmd:      "git",
			args:     []string{"push", "-f"},
			wantDec:  types.DecisionRedirect,
			wantRule: "redirect-git-force-push",
		},
		{
			name:     "git reset --hard redirected",
			cmd:      "git",
			args:     []string{"reset", "--hard", "HEAD~1"},
			wantDec:  types.DecisionRedirect,
			wantRule: "redirect-git-hard-reset",
		},
		{
			name:     "git clean -fd redirected",
			cmd:      "git",
			args:     []string{"clean", "-fd"},
			wantDec:  types.DecisionRedirect,
			wantRule: "redirect-git-clean",
		},
		{
			name:     "git push origin main redirected",
			cmd:      "git",
			args:     []string{"push", "origin", "main"},
			wantDec:  types.DecisionRedirect,
			wantRule: "redirect-git-push-main",
		},
		{
			name:     "git push origin master redirected",
			cmd:      "git",
			args:     []string{"push", "origin", "master"},
			wantDec:  types.DecisionRedirect,
			wantRule: "redirect-git-push-main",
		},
		{
			name:     "rm -rf / redirected",
			cmd:      "rm",
			args:     []string{"-rf", "/"},
			wantDec:  types.DecisionRedirect,
			wantRule: "redirect-destructive-rm",
		},

		// Git normal ops still allowed (not caught by redirects)
		{
			name:     "git commit allowed",
			cmd:      "git",
			args:     []string{"commit", "-m", "fix: stuff"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-dev-tools",
		},
		{
			name:     "git push feature branch allowed",
			cmd:      "git",
			args:     []string{"push", "origin", "feature-branch"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-dev-tools",
		},
		{
			name:     "git push branch ending in -f allowed",
			cmd:      "git",
			args:     []string{"push", "origin", "topic-f"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-dev-tools",
		},
		{
			name:     "rm single file allowed",
			cmd:      "rm",
			args:     []string{"temp.txt"},
			wantDec:  types.DecisionAllow,
			wantRule: "allow-file-ops",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.CheckCommand(tt.cmd, tt.args)
			assert.Equal(t, tt.wantDec, dec.PolicyDecision, "decision mismatch")
			assert.Equal(t, tt.wantRule, dec.Rule, "rule mismatch")
		})
	}
}

func TestAgentDefault_FileDecisions(t *testing.T) {
	e := loadAgentDefaultEngine(t)

	tests := []struct {
		name     string
		path     string
		op       string
		wantDec  types.Decision
		wantRule string
	}{
		// Workspace full access
		{
			name:     "read project file",
			path:     "/home/user/project/main.go",
			op:       "read",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-workspace",
		},
		{
			name:     "write project file",
			path:     "/home/user/project/src/app.ts",
			op:       "write",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-workspace",
		},
		{
			name:     "delete project file",
			path:     "/home/user/project/old.txt",
			op:       "delete",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-workspace",
		},

		// Temp full access
		{
			name:     "write to tmp",
			path:     "/tmp/build-output/result.json",
			op:       "write",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-tmp",
		},

		// Package caches
		{
			name:     "npm cache access",
			path:     "/home/user/.npm/_cacache/content-v2/sha512/abc",
			op:       "write",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-package-caches",
		},
		{
			name:     "cargo cache access",
			path:     "/home/user/.cargo/registry/src/index.crates.io/serde-1.0/src/lib.rs",
			op:       "read",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-package-caches",
		},

		// System read-only
		{
			name:     "read /usr/lib",
			path:     "/usr/lib/libssl.so",
			op:       "read",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-system-read",
		},
		{
			name:     "write /usr denied",
			path:     "/usr/local/bin/tool",
			op:       "write",
			wantDec:  types.DecisionDeny,
			wantRule: "default-deny-files",
		},
		{
			name:     "read /etc/hosts",
			path:     "/etc/hosts",
			op:       "read",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-etc-read",
		},

		// Credential paths require approval
		{
			name:     "read SSH private key",
			path:     "/home/user/.ssh/id_rsa",
			op:       "read",
			wantDec:  types.DecisionApprove,
			wantRule: "approve-ssh-keys",
		},
		{
			name:     "read AWS credentials",
			path:     "/home/user/.aws/credentials",
			op:       "read",
			wantDec:  types.DecisionApprove,
			wantRule: "approve-cloud-credentials",
		},
		{
			name:     "read kube config",
			path:     "/home/user/.kube/config",
			op:       "read",
			wantDec:  types.DecisionApprove,
			wantRule: "approve-cloud-credentials",
		},
		{
			name:     "read git-credentials",
			path:     "/home/user/.git-credentials",
			op:       "read",
			wantDec:  types.DecisionApprove,
			wantRule: "approve-git-credentials",
		},
		{
			name:     "read .netrc in project (approval required)",
			path:     "/home/user/project/.netrc",
			op:       "read",
			wantDec:  types.DecisionApprove,
			wantRule: "approve-git-credentials",
		},
		{
			name:     "read .env in project (approval required)",
			path:     "/home/user/project/.env",
			op:       "read",
			wantDec:  types.DecisionApprove,
			wantRule: "approve-env-files",
		},
		{
			name:     "read .env outside project (approval gate)",
			path:     "/home/user/other-project/.env",
			op:       "read",
			wantDec:  types.DecisionApprove,
			wantRule: "approve-env-files",
		},

		// Denied paths
		{
			name:     "read /etc/shadow denied",
			path:     "/etc/shadow",
			op:       "read",
			wantDec:  types.DecisionDeny,
			wantRule: "deny-passwd-shadow",
		},
		{
			name:     "read /etc/gshadow denied",
			path:     "/etc/gshadow",
			op:       "open",
			wantDec:  types.DecisionDeny,
			wantRule: "deny-passwd-shadow",
		},
		{
			name:     "read /proc/self/environ denied (secrets)",
			path:     "/proc/self/environ",
			op:       "read",
			wantDec:  types.DecisionDeny,
			wantRule: "deny-proc-sensitive",
		},
		{
			name:     "read /sys allowed (reads not blocked)",
			path:     "/sys/class/net/eth0/address",
			op:       "read",
			wantDec:  types.DecisionAllow,
			wantRule: "default-allow-reads",
		},
		{
			name:     "read random home path allowed (reads not blocked)",
			path:     "/home/user/.bashrc",
			op:       "read",
			wantDec:  types.DecisionAllow,
			wantRule: "default-allow-reads",
		},

		// Read-allow defaults (new behavior)
		{
			name:     "read unknown path defaults to allow",
			path:     "/some/unknown/path",
			op:       "open",
			wantDec:  types.DecisionAllow,
			wantRule: "default-allow-reads",
		},
		{
			name:     "write unknown path defaults to deny",
			path:     "/some/unknown/path",
			op:       "write",
			wantDec:  types.DecisionDeny,
			wantRule: "default-deny-files",
		},

		// /proc read/write behavior after narrowing
		{
			name:     "open /proc/self/environ denied (secrets)",
			path:     "/proc/self/environ",
			op:       "open",
			wantDec:  types.DecisionDeny,
			wantRule: "deny-proc-sensitive",
		},
		{
			name:     "read /proc/self/status allowed",
			path:     "/proc/self/status",
			op:       "open",
			wantDec:  types.DecisionAllow,
			wantRule: "default-allow-reads",
		},
		{
			name:     "write /proc/self/status denied",
			path:     "/proc/self/status",
			op:       "write",
			wantDec:  types.DecisionDeny,
			wantRule: "deny-proc-sys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.CheckFile(tt.path, tt.op)
			assert.Equal(t, tt.wantDec, dec.PolicyDecision, "decision mismatch")
			assert.Equal(t, tt.wantRule, dec.Rule, "rule mismatch")
		})
	}
}

func TestAgentDefault_NetworkDecisions(t *testing.T) {
	e := loadAgentDefaultEngine(t)

	tests := []struct {
		name     string
		domain   string
		port     int
		wantDec  types.Decision
		wantRule string
	}{
		// LLM providers
		{
			name:     "Anthropic API allowed",
			domain:   "api.anthropic.com",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-llm-providers",
		},
		{
			name:     "OpenAI API allowed",
			domain:   "api.openai.com",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-llm-providers",
		},
		{
			name:     "Google AI API allowed",
			domain:   "generativelanguage.googleapis.com",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-llm-providers",
		},

		// Package registries
		{
			name:     "npm registry allowed",
			domain:   "registry.npmjs.org",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-npm",
		},
		{
			name:     "PyPI allowed",
			domain:   "pypi.org",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-pypi",
		},
		{
			name:     "crates.io allowed",
			domain:   "crates.io",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-cargo",
		},
		{
			name:     "Go proxy allowed",
			domain:   "proxy.golang.org",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-go-proxy",
		},
		{
			name:     "Maven Central allowed",
			domain:   "repo1.maven.org",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-other-registries",
		},
		{
			name:     "RubyGems allowed",
			domain:   "rubygems.org",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-other-registries",
		},
		{
			name:     "Docker Hub allowed",
			domain:   "registry-1.docker.io",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-other-registries",
		},

		// Code hosting
		{
			name:     "GitHub HTTPS allowed",
			domain:   "github.com",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-github",
		},
		{
			name:     "GitHub SSH allowed",
			domain:   "github.com",
			port:     22,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-github",
		},
		{
			name:     "GitLab allowed",
			domain:   "gitlab.com",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-gitlab",
		},

		// CDNs
		{
			name:     "jsdelivr allowed",
			domain:   "cdn.jsdelivr.net",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-cdns",
		},
		{
			name:     "unpkg allowed",
			domain:   "unpkg.com",
			port:     443,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-cdns",
		},

		// Unknown HTTPS requires approval
		{
			name:     "random.com HTTPS requires approval",
			domain:   "random.com",
			port:     443,
			wantDec:  types.DecisionApprove,
			wantRule: "approve-unknown-https",
		},

		// Non-HTTPS unknown denied
		{
			name:     "random.com HTTP denied",
			domain:   "random.com",
			port:     80,
			wantDec:  types.DecisionDeny,
			wantRule: "default-deny-network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.CheckNetwork(tt.domain, tt.port)
			assert.Equal(t, tt.wantDec, dec.PolicyDecision, "decision mismatch")
			assert.Equal(t, tt.wantRule, dec.Rule, "rule mismatch")
		})
	}
}

func TestAgentDefault_NetworkIPDecisions(t *testing.T) {
	e := loadAgentDefaultEngine(t)

	tests := []struct {
		name     string
		ip       string
		port     int
		wantDec  types.Decision
		wantRule string
	}{
		{
			name:     "localhost allowed",
			ip:       "127.0.0.1",
			port:     3000,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-localhost",
		},
		{
			name:     "IPv6 localhost allowed",
			ip:       "::1",
			port:     8080,
			wantDec:  types.DecisionAllow,
			wantRule: "allow-localhost",
		},
		{
			name:     "cloud metadata denied",
			ip:       "169.254.169.254",
			port:     80,
			wantDec:  types.DecisionDeny,
			wantRule: "deny-metadata-services",
		},
		{
			name:     "Alibaba metadata denied",
			ip:       "100.100.100.200",
			port:     80,
			wantDec:  types.DecisionDeny,
			wantRule: "deny-metadata-services",
		},
		{
			name:     "private network 10.x denied",
			ip:       "10.0.0.1",
			port:     443,
			wantDec:  types.DecisionDeny,
			wantRule: "deny-private-networks",
		},
		{
			name:     "private network 172.16.x denied",
			ip:       "172.16.0.1",
			port:     443,
			wantDec:  types.DecisionDeny,
			wantRule: "deny-private-networks",
		},
		{
			name:     "private network 192.168.x denied",
			ip:       "192.168.1.1",
			port:     443,
			wantDec:  types.DecisionDeny,
			wantRule: "deny-private-networks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.CheckNetworkIP("", net.ParseIP(tt.ip), tt.port)
			assert.Equal(t, tt.wantDec, dec.PolicyDecision, "decision mismatch")
			assert.Equal(t, tt.wantRule, dec.Rule, "rule mismatch")
		})
	}
}

func TestAgentDefault_EnvDecisions(t *testing.T) {
	e := loadAgentDefaultEngine(t)

	tests := []struct {
		name        string
		envVar      string
		wantAllowed bool
	}{
		// Safe vars allowed
		{name: "PATH allowed", envVar: "PATH", wantAllowed: true},
		{name: "HOME allowed", envVar: "HOME", wantAllowed: true},
		{name: "GOPATH allowed", envVar: "GOPATH", wantAllowed: true},
		{name: "NODE_ENV allowed", envVar: "NODE_ENV", wantAllowed: true},
		{name: "EDITOR allowed", envVar: "EDITOR", wantAllowed: true},

		// Explicit deny patterns
		{name: "ANTHROPIC_API_KEY denied", envVar: "ANTHROPIC_API_KEY", wantAllowed: false},
		{name: "OPENAI_API_KEY denied", envVar: "OPENAI_API_KEY", wantAllowed: false},
		{name: "GITHUB_TOKEN denied", envVar: "GITHUB_TOKEN", wantAllowed: false},
		{name: "GH_TOKEN denied", envVar: "GH_TOKEN", wantAllowed: false},
		{name: "NPM_TOKEN denied", envVar: "NPM_TOKEN", wantAllowed: false},
		{name: "AWS_SECRET_ACCESS_KEY denied", envVar: "AWS_SECRET_ACCESS_KEY", wantAllowed: false},
		{name: "AWS_SESSION_TOKEN denied", envVar: "AWS_SESSION_TOKEN", wantAllowed: false},
		{name: "GOOGLE_APPLICATION_CREDENTIALS denied", envVar: "GOOGLE_APPLICATION_CREDENTIALS", wantAllowed: false},

		// Wildcard deny patterns
		{name: "MY_SECRET_KEY denied (*_SECRET*)", envVar: "MY_SECRET_KEY", wantAllowed: false},
		{name: "DB_PASSWORD denied (*_PASSWORD*)", envVar: "DB_PASSWORD", wantAllowed: false},
		{name: "SSH_PRIVATE_KEY denied (*_PRIVATE_KEY*)", envVar: "SSH_PRIVATE_KEY", wantAllowed: false},
		{name: "STRIPE_API_KEY denied (*_API_KEY*)", envVar: "STRIPE_API_KEY", wantAllowed: false},
		{name: "AWS_ACCESS_KEY_ID denied (*_ACCESS_KEY*)", envVar: "AWS_ACCESS_KEY_ID", wantAllowed: false},
		{name: "SESSION_TOKEN denied (*_TOKEN)", envVar: "SESSION_TOKEN", wantAllowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.CheckEnv(tt.envVar)
			assert.Equal(t, tt.wantAllowed, dec.Allowed, "env decision mismatch for %s", tt.envVar)
		})
	}
}

func TestAgentDefault_UnixSocketDecisions(t *testing.T) {
	e := loadAgentDefaultEngine(t)

	// Docker socket allowed for connect
	dec := e.CheckUnixSocket("/var/run/docker.sock", "connect")
	assert.Equal(t, types.DecisionAllow, dec.PolicyDecision)
	assert.Equal(t, "allow-docker-socket", dec.Rule)

	// Other system sockets denied
	dec = e.CheckUnixSocket("/var/run/dbus/system_bus_socket", "connect")
	assert.Equal(t, types.DecisionDeny, dec.PolicyDecision)
	assert.Equal(t, "deny-system-sockets", dec.Rule)
}
