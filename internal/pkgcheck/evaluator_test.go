package pkgcheck

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluatorCriticalVulnBlocks(t *testing.T) {
	rules := []policy.PackageRule{
		{
			Match:  policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"},
			Action: "deny",
			Reason: "critical vulnerabilities are not allowed",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
			Reason: "default allow",
		},
	}

	findings := []Finding{
		{
			Type:     FindingVulnerability,
			Provider: "osv",
			Package:  PackageRef{Name: "lodash", Version: "4.17.20"},
			Severity: SeverityCritical,
			Title:    "Prototype Pollution in lodash",
		},
	}

	ev := NewEvaluator(rules)
	verdict := ev.Evaluate(findings, EcosystemNPM)

	require.NotNil(t, verdict)
	assert.Equal(t, VerdictBlock, verdict.Action)
	assert.Len(t, verdict.Findings, 1)

	pv, ok := verdict.Packages["lodash@4.17.20"]
	require.True(t, ok)
	assert.Equal(t, VerdictBlock, pv.Action)
}

func TestEvaluatorLicenseDeny(t *testing.T) {
	rules := []policy.PackageRule{
		{
			Match: policy.PackageMatch{
				FindingType: "license",
				LicenseSPDX: &policy.LicenseSPDXMatch{
					Deny: []string{"AGPL-3.0", "AGPL-3.0-only"},
				},
			},
			Action: "deny",
			Reason: "AGPL licenses are prohibited",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
			Reason: "default allow",
		},
	}

	findings := []Finding{
		{
			Type:     FindingLicense,
			Provider: "depsdev",
			Package:  PackageRef{Name: "some-agpl-lib", Version: "1.0.0"},
			Severity: SeverityHigh,
			Title:    "Non-permissive license: AGPL-3.0",
			Metadata: map[string]string{"spdx": "AGPL-3.0"},
		},
	}

	ev := NewEvaluator(rules)
	verdict := ev.Evaluate(findings, EcosystemNPM)

	require.NotNil(t, verdict)
	assert.Equal(t, VerdictBlock, verdict.Action)

	pv, ok := verdict.Packages["some-agpl-lib@1.0.0"]
	require.True(t, ok)
	assert.Equal(t, VerdictBlock, pv.Action)
}

func TestEvaluatorPermissiveLicenseAllows(t *testing.T) {
	rules := []policy.PackageRule{
		{
			Match: policy.PackageMatch{
				FindingType: "license",
				LicenseSPDX: &policy.LicenseSPDXMatch{
					Allow: []string{"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"},
				},
			},
			Action: "allow",
			Reason: "permissive licenses are allowed",
		},
		{
			Match:  policy.PackageMatch{FindingType: "license"},
			Action: "deny",
			Reason: "unknown licenses are denied",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
			Reason: "default allow",
		},
	}

	findings := []Finding{
		{
			Type:     FindingLicense,
			Provider: "depsdev",
			Package:  PackageRef{Name: "express", Version: "4.18.0"},
			Severity: SeverityInfo,
			Title:    "License: MIT",
			Metadata: map[string]string{"spdx": "MIT"},
		},
	}

	ev := NewEvaluator(rules)
	verdict := ev.Evaluate(findings, EcosystemNPM)

	require.NotNil(t, verdict)
	assert.Equal(t, VerdictAllow, verdict.Action)

	pv, ok := verdict.Packages["express@4.18.0"]
	require.True(t, ok)
	assert.Equal(t, VerdictAllow, pv.Action)
}

func TestEvaluatorStaticAllowlist(t *testing.T) {
	rules := []policy.PackageRule{
		{
			Match: policy.PackageMatch{
				Packages: []string{"trusted-pkg"},
			},
			Action: "allow",
			Reason: "trusted package",
		},
		{
			Match:  policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"},
			Action: "deny",
			Reason: "critical vulnerabilities block",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
			Reason: "default allow",
		},
	}

	findings := []Finding{
		{
			Type:     FindingVulnerability,
			Provider: "osv",
			Package:  PackageRef{Name: "trusted-pkg", Version: "2.0.0"},
			Severity: SeverityCritical,
			Title:    "Known vuln in trusted-pkg",
		},
	}

	ev := NewEvaluator(rules)
	verdict := ev.Evaluate(findings, EcosystemNPM)

	require.NotNil(t, verdict)
	// The allowlist rule matches first, so the package is allowed despite critical vuln.
	assert.Equal(t, VerdictAllow, verdict.Action)

	pv, ok := verdict.Packages["trusted-pkg@2.0.0"]
	require.True(t, ok)
	assert.Equal(t, VerdictAllow, pv.Action)
}

func TestEvaluatorNoFindings(t *testing.T) {
	rules := []policy.PackageRule{
		{
			Match:  policy.PackageMatch{FindingType: "vulnerability"},
			Action: "deny",
			Reason: "block vulns",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
			Reason: "default allow",
		},
	}

	ev := NewEvaluator(rules)
	verdict := ev.Evaluate(nil, EcosystemNPM)

	require.NotNil(t, verdict)
	assert.Equal(t, VerdictAllow, verdict.Action)
	assert.Empty(t, verdict.Findings)
	assert.Empty(t, verdict.Packages)
	assert.Contains(t, verdict.Summary, "no findings")
}

func TestEvaluatorEcosystemScope(t *testing.T) {
	rules := []policy.PackageRule{
		{
			Match: policy.PackageMatch{
				FindingType: "vulnerability",
				Severity:    "high",
				Ecosystem:   "npm",
			},
			Action: "deny",
			Reason: "block high npm vulns",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
			Reason: "default allow",
		},
	}

	findings := []Finding{
		{
			Type:     FindingVulnerability,
			Provider: "osv",
			Package:  PackageRef{Name: "requests", Version: "2.28.0"},
			Severity: SeverityHigh,
			Title:    "HTTP header injection in requests",
		},
	}

	ev := NewEvaluator(rules)
	// The finding is in the pypi ecosystem, so the npm-scoped deny rule should NOT match.
	verdict := ev.Evaluate(findings, EcosystemPyPI)

	require.NotNil(t, verdict)
	assert.Equal(t, VerdictAllow, verdict.Action)

	pv, ok := verdict.Packages["requests@2.28.0"]
	require.True(t, ok)
	assert.Equal(t, VerdictAllow, pv.Action)
}

func TestEvaluatorNamePatterns(t *testing.T) {
	rules := []policy.PackageRule{
		{
			Match: policy.PackageMatch{
				NamePatterns: []string{"@evil/*", "malicious-*"},
			},
			Action: "deny",
			Reason: "block known bad patterns",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
			Reason: "default allow",
		},
	}

	ev := NewEvaluator(rules)

	// Package matching @evil/* glob should be blocked
	findings := []Finding{
		{
			Type:     FindingReputation,
			Provider: "test",
			Package:  PackageRef{Name: "@evil/inject", Version: "1.0.0"},
			Severity: SeverityHigh,
			Title:    "suspicious package",
		},
	}
	verdict := ev.Evaluate(findings, EcosystemNPM)
	require.NotNil(t, verdict)
	assert.Equal(t, VerdictBlock, verdict.Action)

	// Package matching malicious-* glob should be blocked
	findings2 := []Finding{
		{
			Type:     FindingReputation,
			Provider: "test",
			Package:  PackageRef{Name: "malicious-lib", Version: "0.1.0"},
			Severity: SeverityMedium,
			Title:    "bad package",
		},
	}
	verdict2 := ev.Evaluate(findings2, EcosystemNPM)
	require.NotNil(t, verdict2)
	assert.Equal(t, VerdictBlock, verdict2.Action)

	// Package not matching any glob should be allowed (catch-all)
	findings3 := []Finding{
		{
			Type:     FindingReputation,
			Provider: "test",
			Package:  PackageRef{Name: "safe-lib", Version: "2.0.0"},
			Severity: SeverityLow,
			Title:    "normal package",
		},
	}
	verdict3 := ev.Evaluate(findings3, EcosystemNPM)
	require.NotNil(t, verdict3)
	assert.Equal(t, VerdictAllow, verdict3.Action)
}

func TestEvaluatorOptionsNonMatch(t *testing.T) {
	// Rules with Options are rejected at validation time (Policy.Validate),
	// so in practice the evaluator never sees them. But if it does, the
	// Options rule should be a non-match so it falls through safely.
	rules := []policy.PackageRule{
		{
			Match: policy.PackageMatch{
				FindingType: "vulnerability",
				Severity:    "critical",
				Options:     map[string]any{"some_option": "value"},
			},
			Action: "deny",
			Reason: "this rule has unsupported Options, should not match",
		},
		{
			Match:  policy.PackageMatch{},
			Action: "allow",
			Reason: "default allow",
		},
	}

	findings := []Finding{
		{
			Type:     FindingVulnerability,
			Provider: "osv",
			Package:  PackageRef{Name: "bad-pkg", Version: "1.0.0"},
			Severity: SeverityCritical,
			Title:    "critical vulnerability",
		},
	}

	ev := NewEvaluator(rules)
	verdict := ev.Evaluate(findings, EcosystemNPM)

	require.NotNil(t, verdict)
	// The Options rule should NOT match; the finding falls through to
	// the catch-all allow rule.
	assert.Equal(t, VerdictAllow, verdict.Action)

	pv, ok := verdict.Packages["bad-pkg@1.0.0"]
	require.True(t, ok)
	assert.Equal(t, VerdictAllow, pv.Action)
}
