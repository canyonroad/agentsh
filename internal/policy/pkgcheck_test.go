package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestPackageRules_YAMLParsing(t *testing.T) {
	yamlInput := `
version: 1
name: test-policy
package_rules:
  - match:
      finding_type: vulnerability
      severity: critical
    action: block
    reason: "Critical vulnerabilities are not allowed"
  - match:
      packages:
        - lodash
        - underscore
    action: warn
    reason: "Consider alternatives"
  - match:
      name_patterns:
        - "@evil/*"
        - "malicious-*"
    action: block
  - match:
      license_spdx:
        deny:
          - GPL-3.0
          - AGPL-3.0
    action: approve
    reason: "Copyleft license requires approval"
  - match:
      ecosystem: npm
      finding_type: reputation
      severity: high
    action: block
  - match:
      reasons:
        - no_provenance
        - missing_signature
    action: warn
  - match:
      finding_type: license
      options:
        strict: "true"
    action: approve
`

	var p Policy
	err := yaml.Unmarshal([]byte(yamlInput), &p)
	require.NoError(t, err)

	require.Len(t, p.PackageRules, 7)

	// Rule 1: critical vulnerability block
	r := p.PackageRules[0]
	assert.Equal(t, "vulnerability", r.Match.FindingType)
	assert.Equal(t, "critical", r.Match.Severity)
	assert.Equal(t, "block", r.Action)
	assert.Equal(t, "Critical vulnerabilities are not allowed", r.Reason)

	// Rule 2: specific packages warn
	r = p.PackageRules[1]
	assert.Equal(t, []string{"lodash", "underscore"}, r.Match.Packages)
	assert.Equal(t, "warn", r.Action)

	// Rule 3: name patterns block
	r = p.PackageRules[2]
	assert.Equal(t, []string{"@evil/*", "malicious-*"}, r.Match.NamePatterns)
	assert.Equal(t, "block", r.Action)

	// Rule 4: license SPDX deny with approval
	r = p.PackageRules[3]
	require.NotNil(t, r.Match.LicenseSPDX)
	assert.Equal(t, []string{"GPL-3.0", "AGPL-3.0"}, r.Match.LicenseSPDX.Deny)
	assert.Nil(t, r.Match.LicenseSPDX.Allow)
	assert.Equal(t, "approve", r.Action)

	// Rule 5: ecosystem + finding type + severity
	r = p.PackageRules[4]
	assert.Equal(t, "npm", r.Match.Ecosystem)
	assert.Equal(t, "reputation", r.Match.FindingType)
	assert.Equal(t, "high", r.Match.Severity)
	assert.Equal(t, "block", r.Action)

	// Rule 6: reason codes
	r = p.PackageRules[5]
	assert.Equal(t, []string{"no_provenance", "missing_signature"}, r.Match.Reasons)
	assert.Equal(t, "warn", r.Action)

	// Rule 7: options
	r = p.PackageRules[6]
	assert.Equal(t, "license", r.Match.FindingType)
	assert.Equal(t, "true", r.Match.Options["strict"])
	assert.Equal(t, "approve", r.Action)
}

func TestPackageRules_LicenseSPDXAllow(t *testing.T) {
	yamlInput := `
version: 1
name: test
package_rules:
  - match:
      license_spdx:
        allow:
          - MIT
          - Apache-2.0
          - BSD-2-Clause
          - BSD-3-Clause
    action: allow
`

	var p Policy
	err := yaml.Unmarshal([]byte(yamlInput), &p)
	require.NoError(t, err)

	require.Len(t, p.PackageRules, 1)
	r := p.PackageRules[0]
	require.NotNil(t, r.Match.LicenseSPDX)
	assert.Equal(t, []string{"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"}, r.Match.LicenseSPDX.Allow)
	assert.Nil(t, r.Match.LicenseSPDX.Deny)
	assert.Equal(t, "allow", r.Action)
}

func TestPackageRules_EmptyRules(t *testing.T) {
	yamlInput := `
version: 1
name: test
`
	var p Policy
	err := yaml.Unmarshal([]byte(yamlInput), &p)
	require.NoError(t, err)
	assert.Nil(t, p.PackageRules)
}

func TestPackageRules_RoundTrip(t *testing.T) {
	original := []PackageRule{
		{
			Match: PackageMatch{
				FindingType: "malware",
			},
			Action: "block",
			Reason: "No malware allowed",
		},
		{
			Match: PackageMatch{
				LicenseSPDX: &LicenseSPDXMatch{
					Allow: []string{"MIT"},
					Deny:  []string{"GPL-3.0"},
				},
			},
			Action: "approve",
		},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var decoded []PackageRule
	err = yaml.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded, 2)
	assert.Equal(t, "malware", decoded[0].Match.FindingType)
	assert.Equal(t, "block", decoded[0].Action)
	assert.Equal(t, "No malware allowed", decoded[0].Reason)
	require.NotNil(t, decoded[1].Match.LicenseSPDX)
	assert.Equal(t, []string{"MIT"}, decoded[1].Match.LicenseSPDX.Allow)
	assert.Equal(t, []string{"GPL-3.0"}, decoded[1].Match.LicenseSPDX.Deny)
}
