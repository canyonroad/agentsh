package pkgcheck

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIntegrationChecker creates a full Checker with all layers wired for integration tests.
func newIntegrationChecker(
	resolvers []Resolver,
	providers map[string]ProviderEntry,
	rules []policy.PackageRule,
	allowlist *Allowlist,
) *Checker {
	if allowlist == nil {
		allowlist = NewAllowlist(30 * time.Second)
	}
	return NewChecker(CheckerConfig{
		Scope:     "new_packages_only",
		Resolvers: resolvers,
		Providers: providers,
		Rules:     rules,
		Allowlist: allowlist,
	})
}

func TestIntegrationBlockCriticalVuln(t *testing.T) {
	// A critical vulnerability finding should result in a block verdict
	// when the policy has a rule that blocks critical findings.

	resolver := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Direct: []PackageRef{
				{Name: "vulnerable-pkg", Version: "1.0.0", Direct: true},
			},
		},
	}

	vulnProvider := &mockProvider{
		name:         "vuln-db",
		capabilities: []FindingType{FindingVulnerability},
		findings: []Finding{
			{
				Type:     FindingVulnerability,
				Provider: "vuln-db",
				Package:  PackageRef{Name: "vulnerable-pkg", Version: "1.0.0"},
				Severity: SeverityCritical,
				Title:    "CVE-2024-0001: Remote Code Execution",
				Detail:   "Arbitrary code execution via crafted input",
				Links:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
			},
		},
	}

	rules := []policy.PackageRule{
		{
			Match:  policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"},
			Action: "block",
			Reason: "critical vulnerabilities must be blocked",
		},
		{
			Match:  policy.PackageMatch{FindingType: "vulnerability", Severity: "high"},
			Action: "approve",
			Reason: "high vulnerabilities need approval",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
		},
	}

	allowlist := NewAllowlist(30 * time.Second)
	checker := newIntegrationChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"vuln-db": {Provider: vulnProvider, Timeout: 5 * time.Second, OnFailure: "warn"},
		},
		rules,
		allowlist,
	)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "vulnerable-pkg"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)

	assert.Equal(t, VerdictBlock, verdict.Action)
	assert.Len(t, verdict.Findings, 1)
	assert.Equal(t, SeverityCritical, verdict.Findings[0].Severity)
	assert.Contains(t, verdict.Summary, "vulnerable-pkg")

	// Blocked packages must not appear in the allowlist.
	assert.False(t, allowlist.IsAllowed("", "vulnerable-pkg", "1.0.0"))
}

func TestIntegrationAllowCleanPackage(t *testing.T) {
	// A clean package (no findings) should be allowed and added to the allowlist.

	resolver := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Registry:  "https://registry.npmjs.org",
			Direct: []PackageRef{
				{Name: "lodash", Version: "4.17.21", Direct: true},
			},
		},
	}

	cleanProvider := &mockProvider{
		name:         "vuln-db",
		capabilities: []FindingType{FindingVulnerability},
		findings:     nil, // no findings
	}

	rules := []policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	allowlist := NewAllowlist(30 * time.Second)
	checker := newIntegrationChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"vuln-db": {Provider: cleanProvider, Timeout: 5 * time.Second, OnFailure: "warn"},
		},
		rules,
		allowlist,
	)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "lodash"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)

	assert.Equal(t, VerdictAllow, verdict.Action)
	assert.Empty(t, verdict.Findings)
	assert.Contains(t, verdict.Summary, "lodash")

	// Allowed packages must be in the allowlist.
	assert.True(t, allowlist.IsAllowed("https://registry.npmjs.org", "lodash", "4.17.21"))
}

func TestIntegrationWarnMediumVuln(t *testing.T) {
	// A medium-severity vulnerability should produce a warn verdict
	// and populate the allowlist (since warn is permissive).

	resolver := &mockResolver{
		name:       "pip-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "pip",
			Ecosystem: EcosystemPyPI,
			Registry:  "https://pypi.org",
			Direct: []PackageRef{
				{Name: "requests", Version: "2.28.0", Direct: true},
			},
		},
	}

	vulnProvider := &mockProvider{
		name:         "vuln-db",
		capabilities: []FindingType{FindingVulnerability},
		findings: []Finding{
			{
				Type:     FindingVulnerability,
				Provider: "vuln-db",
				Package:  PackageRef{Name: "requests", Version: "2.28.0"},
				Severity: SeverityMedium,
				Title:    "CVE-2023-1234: Information Disclosure",
			},
		},
	}

	rules := []policy.PackageRule{
		{
			Match:  policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"},
			Action: "block",
		},
		{
			Match:  policy.PackageMatch{FindingType: "vulnerability", Severity: "high"},
			Action: "approve",
		},
		{
			Match:  policy.PackageMatch{FindingType: "vulnerability", Severity: "medium"},
			Action: "warn",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
		},
	}

	allowlist := NewAllowlist(30 * time.Second)
	checker := newIntegrationChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"vuln-db": {Provider: vulnProvider, Timeout: 5 * time.Second, OnFailure: "warn"},
		},
		rules,
		allowlist,
	)

	verdict, err := checker.Check(context.Background(), "pip", []string{"install", "requests"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)

	assert.Equal(t, VerdictWarn, verdict.Action)
	assert.Len(t, verdict.Findings, 1)
	assert.Contains(t, verdict.Summary, "requests")

	// Warn-level packages are still allowed to install, so the allowlist should be populated.
	assert.True(t, allowlist.IsAllowed("https://pypi.org", "requests", "2.28.0"))
}

func TestIntegrationProviderDown(t *testing.T) {
	// When a provider is down and on_failure="deny", the install should be blocked.
	// When on_failure="warn", it should still allow.

	resolver := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Direct: []PackageRef{
				{Name: "express", Version: "4.18.2", Direct: true},
			},
		},
	}

	failProvider := &mockProvider{
		name: "down-provider",
		err:  fmt.Errorf("connection refused"),
	}

	rules := []policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	t.Run("on_failure=deny blocks install", func(t *testing.T) {
		allowlist := NewAllowlist(30 * time.Second)
		checker := newIntegrationChecker(
			[]Resolver{resolver},
			map[string]ProviderEntry{
				"down-provider": {Provider: failProvider, Timeout: 5 * time.Second, OnFailure: "deny"},
			},
			rules,
			allowlist,
		)

		verdict, err := checker.Check(context.Background(), "npm", []string{"install", "express"}, t.TempDir())
		require.NoError(t, err)
		require.NotNil(t, verdict)

		assert.Equal(t, VerdictBlock, verdict.Action)
		assert.Contains(t, verdict.Summary, "on_failure=deny")
		assert.False(t, allowlist.IsAllowed("", "express", "4.18.2"))
	})

	t.Run("on_failure=allow permits install", func(t *testing.T) {
		allowlist := NewAllowlist(30 * time.Second)
		checker := newIntegrationChecker(
			[]Resolver{resolver},
			map[string]ProviderEntry{
				"down-provider": {Provider: failProvider, Timeout: 5 * time.Second, OnFailure: "allow"},
			},
			rules,
			allowlist,
		)

		verdict, err := checker.Check(context.Background(), "npm", []string{"install", "express"}, t.TempDir())
		require.NoError(t, err)
		require.NotNil(t, verdict)

		// on_failure="allow" means no finding is injected, so no findings -> default allow.
		assert.Equal(t, VerdictAllow, verdict.Action)
		assert.Empty(t, verdict.Findings)
		assert.True(t, allowlist.IsAllowed("", "express", "4.18.2"))
	})

	t.Run("on_failure=warn injects finding but allows", func(t *testing.T) {
		allowlist := NewAllowlist(30 * time.Second)
		checker := newIntegrationChecker(
			[]Resolver{resolver},
			map[string]ProviderEntry{
				"down-provider": {Provider: failProvider, Timeout: 5 * time.Second, OnFailure: "warn"},
			},
			rules,
			allowlist,
		)

		verdict, err := checker.Check(context.Background(), "npm", []string{"install", "express"}, t.TempDir())
		require.NoError(t, err)
		require.NotNil(t, verdict)

		// A finding is injected for the provider error, but the catch-all rule allows.
		assert.Equal(t, VerdictAllow, verdict.Action)
		assert.Len(t, verdict.Findings, 1)
		assert.True(t, allowlist.IsAllowed("", "express", "4.18.2"))
	})
}

func TestIntegrationMultipleProviders(t *testing.T) {
	// Multiple providers run in parallel; the strictest finding determines the verdict.

	resolver := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Direct: []PackageRef{
				{Name: "sketchy-pkg", Version: "0.1.0", Direct: true},
			},
		},
	}

	vulnProvider := &mockProvider{
		name:         "vuln-db",
		capabilities: []FindingType{FindingVulnerability},
		findings: []Finding{
			{
				Type:     FindingVulnerability,
				Provider: "vuln-db",
				Package:  PackageRef{Name: "sketchy-pkg", Version: "0.1.0"},
				Severity: SeverityMedium,
				Title:    "Known vulnerability",
			},
		},
	}

	malwareProvider := &mockProvider{
		name:         "malware-scanner",
		capabilities: []FindingType{FindingMalware},
		findings: []Finding{
			{
				Type:     FindingMalware,
				Provider: "malware-scanner",
				Package:  PackageRef{Name: "sketchy-pkg", Version: "0.1.0"},
				Severity: SeverityCritical,
				Title:    "Suspected malware",
			},
		},
	}

	rules := []policy.PackageRule{
		{
			Match:  policy.PackageMatch{FindingType: "malware"},
			Action: "block",
		},
		{
			Match:  policy.PackageMatch{FindingType: "vulnerability", Severity: "medium"},
			Action: "warn",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
		},
	}

	checker := newIntegrationChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"vuln-db":         {Provider: vulnProvider, Timeout: 5 * time.Second, OnFailure: "warn"},
			"malware-scanner": {Provider: malwareProvider, Timeout: 5 * time.Second, OnFailure: "deny"},
		},
		rules,
		nil,
	)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "sketchy-pkg"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)

	// malware -> block takes priority over vuln -> warn
	assert.Equal(t, VerdictBlock, verdict.Action)
	assert.Len(t, verdict.Findings, 2)
}
