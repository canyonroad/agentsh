package pkgcheck

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestChecker(resolvers []Resolver, providers map[string]ProviderEntry, rules []policy.PackageRule) *Checker {
	return NewChecker(CheckerConfig{
		Scope:     "new_packages_only",
		Resolvers: resolvers,
		Providers: providers,
		Rules:     rules,
		Allowlist: NewAllowlist(30 * time.Second),
	})
}

func TestCheckerEndToEnd(t *testing.T) {
	// Clean package — provider returns no findings, should allow.
	resolver := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Direct: []PackageRef{
				{Name: "express", Version: "4.18.0", Direct: true},
			},
		},
	}
	provider := &mockProvider{
		name:         "test-provider",
		capabilities: []FindingType{FindingVulnerability},
		findings:     nil, // no findings
	}
	rules := []policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	checker := newTestChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"test-provider": {Provider: provider, Timeout: 5 * time.Second, OnFailure: "warn"},
		},
		rules,
	)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "express"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.Equal(t, VerdictAllow, verdict.Action)
	assert.Contains(t, verdict.Summary, "express")
	assert.Contains(t, verdict.Summary, "npm")

	// Verify allowlist was populated.
	assert.True(t, checker.cfg.Allowlist.IsAllowed("", "express", "4.18.0"))
}

func TestCheckerNonInstallCommand(t *testing.T) {
	// "ls -la" is not an install command, should return nil.
	checker := newTestChecker(nil, nil, nil)

	verdict, err := checker.Check(context.Background(), "ls", []string{"-la"}, t.TempDir())
	require.NoError(t, err)
	assert.Nil(t, verdict)
}

func TestCheckerBlockedPackage(t *testing.T) {
	// Provider returns a malware finding, policy blocks malware -> should block.
	resolver := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Direct: []PackageRef{
				{Name: "evil-pkg", Version: "1.0.0", Direct: true},
			},
		},
	}
	provider := &mockProvider{
		name:         "malware-scanner",
		capabilities: []FindingType{FindingMalware},
		findings: []Finding{
			{
				Type:     FindingMalware,
				Provider: "malware-scanner",
				Package:  PackageRef{Name: "evil-pkg", Version: "1.0.0"},
				Severity: SeverityCritical,
				Title:    "Known malware package",
			},
		},
	}
	rules := []policy.PackageRule{
		{
			Match:  policy.PackageMatch{FindingType: "malware"},
			Action: "block",
			Reason: "malware detected",
		},
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	checker := newTestChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"malware-scanner": {Provider: provider, Timeout: 5 * time.Second, OnFailure: "deny"},
		},
		rules,
	)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "evil-pkg"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.Equal(t, VerdictBlock, verdict.Action)
	assert.Len(t, verdict.Findings, 1)

	// Allowlist should NOT be populated for blocked packages.
	assert.False(t, checker.cfg.Allowlist.IsAllowed("", "evil-pkg", "1.0.0"))
}

func TestCheckerNoResolver(t *testing.T) {
	// npm install command but no resolvers configured -> should error.
	checker := newTestChecker(nil, nil, nil)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "express"}, t.TempDir())
	require.Error(t, err)
	assert.Nil(t, verdict)
	assert.Contains(t, err.Error(), "no resolver")
}

func TestCheckerProviderFailureDeny(t *testing.T) {
	// Provider errors with on_failure="deny" -> should block.
	resolver := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Direct: []PackageRef{
				{Name: "lodash", Version: "4.17.21", Direct: true},
			},
		},
	}
	provider := &mockProvider{
		name: "failing-provider",
		err:  assert.AnError,
	}
	rules := []policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	checker := newTestChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"failing-provider": {Provider: provider, Timeout: 5 * time.Second, OnFailure: "deny"},
		},
		rules,
	)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "lodash"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.Equal(t, VerdictBlock, verdict.Action)
	assert.Contains(t, verdict.Summary, "on_failure=deny")
}

func TestCheckerProviderFailureWarn(t *testing.T) {
	// Provider errors with on_failure="warn" -> finding is added but overall allow.
	resolver := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Direct: []PackageRef{
				{Name: "lodash", Version: "4.17.21", Direct: true},
			},
		},
	}
	provider := &mockProvider{
		name: "flaky-provider",
		err:  assert.AnError,
	}
	rules := []policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	checker := newTestChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"flaky-provider": {Provider: provider, Timeout: 5 * time.Second, OnFailure: "warn"},
		},
		rules,
	)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "lodash"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)
	// With the "warn" on_failure, a finding is injected but the default rule allows.
	assert.Equal(t, VerdictAllow, verdict.Action)
}
