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

func TestCheckerMixedProviderFailures_DenyWins(t *testing.T) {
	// Two providers fail: one with on_failure="approve", one with on_failure="deny".
	// The deny (VerdictBlock) is stricter than approve, so deny must win.
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
	approveProvider := &mockProvider{
		name: "approve-provider",
		err:  assert.AnError,
	}
	denyProvider := &mockProvider{
		name: "deny-provider",
		err:  assert.AnError,
	}
	rules := []policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	checker := newTestChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"approve-provider": {Provider: approveProvider, Timeout: 5 * time.Second, OnFailure: "approve"},
			"deny-provider":    {Provider: denyProvider, Timeout: 5 * time.Second, OnFailure: "deny"},
		},
		rules,
	)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "lodash"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)
	// Deny is stricter than approve, so block must win.
	assert.Equal(t, VerdictBlock, verdict.Action)
	assert.Contains(t, verdict.Summary, "on_failure=deny")
}

func TestCheckerProviderFailureApproveUpgrades(t *testing.T) {
	// Provider fails with on_failure="approve" and findings evaluate to allow.
	// The approve failure should upgrade the verdict from allow to approve.
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
	failProvider := &mockProvider{
		name: "approve-on-fail",
		err:  assert.AnError,
	}
	rules := []policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	checker := newTestChecker(
		[]Resolver{resolver},
		map[string]ProviderEntry{
			"approve-on-fail": {Provider: failProvider, Timeout: 5 * time.Second, OnFailure: "approve"},
		},
		rules,
	)

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "express"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)
	// Findings evaluate to allow, but the approve failure upgrades to approve.
	assert.Equal(t, VerdictApprove, verdict.Action)
	assert.Contains(t, verdict.Summary, "on_failure=approve")
}

func TestChecker_PrivacyFilterSurfacesSkipped(t *testing.T) {
	// A PrivacyFilter that excludes @private/* packages.
	// The fake provider records what it receives.
	// Only the public package should reach the provider;
	// the private one should appear in Verdict.Skipped.
	rp := &recordingProvider{name: "fake"}

	resolver := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Direct: []PackageRef{
				{Name: "lodash", Version: "4.17.21", Registry: "registry.npmjs.org", Direct: true},
				{Name: "@private/utils", Version: "1.0.0", Registry: "registry.npmjs.org", Direct: true},
			},
		},
	}

	rules := []policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	checker := NewChecker(CheckerConfig{
		Scope:     "new_packages_only",
		Resolvers: []Resolver{resolver},
		Providers: map[string]ProviderEntry{
			"fake": {Provider: rp, Timeout: 5 * time.Second, OnFailure: "warn"},
		},
		Rules:     rules,
		Allowlist: NewAllowlist(30 * time.Second),
		Privacy: PrivacyConfig{
			ExternalScanRegistries: []string{"registry.npmjs.org"},
			PrivateScopeDenylist:   []string{"@private"},
		},
	})

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "lodash", "@private/utils"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)

	// The fake provider should have received only lodash (not @private/utils).
	require.Len(t, rp.last, 1, "provider should receive only non-skipped packages")
	assert.Equal(t, "lodash", rp.last[0].Name)

	// The verdict should report the skipped package.
	require.Len(t, verdict.Skipped, 1, "verdict should report skipped packages")
	assert.Equal(t, "@private/utils", verdict.Skipped[0].Package.Name)
	assert.Equal(t, SkipReasonPrivateScopeDenylist, verdict.Skipped[0].Reason)
}

// fakeResolver returns a fixed InstallPlan.
type fakeResolver struct {
	plan *InstallPlan
}

func (f *fakeResolver) Name() string                          { return "fake-resolver" }
func (f *fakeResolver) CanResolve(_ string, _ []string) bool  { return true }
func (f *fakeResolver) Resolve(_ context.Context, _ string, _ []string) (*InstallPlan, error) {
	return f.plan, nil
}

// TestChecker_RegistryPropagationAllowsPublicPackages proves that packages
// without an explicit Registry on the PackageRef still pass the privacy filter
// when the plan's Registry matches the allowlist. Without AllPackagesWithRegistry,
// the fail-closed rule would skip every package and the provider would never fire.
func TestChecker_RegistryPropagationAllowsPublicPackages(t *testing.T) {
	rp := &recordingProvider{name: "fake"}

	resolver := &fakeResolver{
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Registry:  "registry.npmjs.org", // plan-level registry, NOT on the refs
			Direct: []PackageRef{
				{Name: "lodash", Version: "4.17.21", Direct: true}, // no Registry field
			},
		},
	}

	rules := []policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	}

	checker := NewChecker(CheckerConfig{
		Scope:     "new_packages_only",
		Resolvers: []Resolver{resolver},
		Providers: map[string]ProviderEntry{
			"fake": {Provider: rp, Timeout: 5 * time.Second, OnFailure: "warn"},
		},
		Rules:     rules,
		Allowlist: NewAllowlist(30 * time.Second),
		Privacy: PrivacyConfig{
			ExternalScanRegistries: []string{"registry.npmjs.org"},
		},
	})

	verdict, err := checker.Check(context.Background(), "npm", []string{"install", "lodash"}, t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, verdict)

	// The provider must have received lodash — not skipped due to empty Registry.
	require.Len(t, rp.last, 1, "provider should receive the package (registry propagated from plan)")
	assert.Equal(t, "lodash", rp.last[0].Name)
	assert.Equal(t, "registry.npmjs.org", rp.last[0].Registry, "registry should be populated from plan")

	// No packages should be skipped.
	assert.Empty(t, verdict.Skipped, "no packages should be skipped for a public-registry install")
}
