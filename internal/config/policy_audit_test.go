package config

import (
	"strings"
	"testing"
)

func TestPolicyVersion(t *testing.T) {
	content := []byte(`file_policy:
  default_action: deny
  rules:
    - name: allow-read
      paths: ["/tmp/*"]
      action: allow
`)

	version := PolicyVersion(content)

	if !strings.HasPrefix(version, "sha256:") {
		t.Errorf("expected sha256: prefix, got %s", version)
	}

	// Verify hash length (sha256: + 16 hex chars for 8 bytes)
	expectedLen := len("sha256:") + 16
	if len(version) != expectedLen {
		t.Errorf("expected version length %d, got %d", expectedLen, len(version))
	}

	// Same content = same version
	version2 := PolicyVersion(content)
	if version != version2 {
		t.Error("same content should produce same version")
	}

	// Different content = different version
	version3 := PolicyVersion([]byte("different"))
	if version == version3 {
		t.Error("different content should produce different version")
	}
}

func TestPolicyVersionEmptyContent(t *testing.T) {
	version := PolicyVersion([]byte{})
	if !strings.HasPrefix(version, "sha256:") {
		t.Errorf("expected sha256: prefix for empty content, got %s", version)
	}

	// Ensure empty content is deterministic
	version2 := PolicyVersion([]byte{})
	if version != version2 {
		t.Error("empty content should produce consistent version")
	}
}

func TestPolicyDiff(t *testing.T) {
	old := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{{Name: "rule1"}},
		},
	}

	new := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{{Name: "rule1"}, {Name: "rule2"}},
		},
	}

	diff := PolicyDiff(old, new)

	if !strings.Contains(diff, "+1") {
		t.Errorf("expected +1 rule in diff, got: %s", diff)
	}
}

func TestPolicyDiffRemoveRules(t *testing.T) {
	old := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{
				{Name: "rule1"},
				{Name: "rule2"},
				{Name: "rule3"},
			},
		},
	}

	new := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{{Name: "rule1"}},
		},
	}

	diff := PolicyDiff(old, new)

	if !strings.Contains(diff, "-2") {
		t.Errorf("expected -2 rules in diff, got: %s", diff)
	}
}

func TestPolicyDiffNetworkRules(t *testing.T) {
	old := &PolicyFiles{
		Network: &NetworkPolicyConfig{
			Rules: []NetworkPolicyRule{{Name: "net1"}},
		},
	}

	new := &PolicyFiles{
		Network: &NetworkPolicyConfig{
			Rules: []NetworkPolicyRule{
				{Name: "net1"},
				{Name: "net2"},
				{Name: "net3"},
			},
		},
	}

	diff := PolicyDiff(old, new)

	if !strings.Contains(diff, "+2") {
		t.Errorf("expected +2 rules in diff for network, got: %s", diff)
	}
}

func TestPolicyDiffDNSRules(t *testing.T) {
	old := &PolicyFiles{
		DNS: &DNSPolicyConfig{
			Rules: []DNSPolicyRule{{Name: "dns1"}},
		},
	}

	new := &PolicyFiles{
		DNS: &DNSPolicyConfig{
			Rules: []DNSPolicyRule{
				{Name: "dns1"},
				{Name: "dns2"},
			},
		},
	}

	diff := PolicyDiff(old, new)

	if !strings.Contains(diff, "+1") {
		t.Errorf("expected +1 rule in diff for DNS, got: %s", diff)
	}
}

func TestPolicyDiffRegistryRules(t *testing.T) {
	old := &PolicyFiles{
		Registry: &RegistryPolicyConfig{
			Rules: []RegistryPolicyRule{
				{Name: "reg1"},
				{Name: "reg2"},
			},
		},
	}

	new := &PolicyFiles{
		Registry: &RegistryPolicyConfig{
			Rules: []RegistryPolicyRule{{Name: "reg1"}},
		},
	}

	diff := PolicyDiff(old, new)

	if !strings.Contains(diff, "-1") {
		t.Errorf("expected -1 rule in diff for registry, got: %s", diff)
	}
}

func TestPolicyDiffNoChanges(t *testing.T) {
	old := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{{Name: "rule1"}},
		},
	}

	new := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{{Name: "rule1"}},
		},
	}

	diff := PolicyDiff(old, new)

	// Same number of rules means modified count but no added/removed
	if strings.Contains(diff, "no changes") {
		t.Errorf("same rule count should show checked count, got: %s", diff)
	}
	if !strings.Contains(diff, "~1") {
		t.Errorf("expected ~1 checked in diff, got: %s", diff)
	}
}

func TestPolicyDiffNilPolicies(t *testing.T) {
	diff := PolicyDiff(nil, nil)
	if diff != "no changes detected" {
		t.Errorf("expected 'no changes detected' for nil policies, got: %s", diff)
	}
}

func TestPolicyDiffOneNilPolicy(t *testing.T) {
	old := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{{Name: "rule1"}},
		},
	}

	diff := PolicyDiff(old, nil)
	if diff != "no changes detected" {
		t.Errorf("expected 'no changes detected' when new policy is nil, got: %s", diff)
	}

	diff2 := PolicyDiff(nil, old)
	if diff2 != "no changes detected" {
		t.Errorf("expected 'no changes detected' when old policy is nil, got: %s", diff2)
	}
}

func TestPolicyDiffMixedChanges(t *testing.T) {
	old := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{{Name: "file1"}},
		},
		Network: &NetworkPolicyConfig{
			Rules: []NetworkPolicyRule{
				{Name: "net1"},
				{Name: "net2"},
				{Name: "net3"},
			},
		},
	}

	new := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{
				{Name: "file1"},
				{Name: "file2"},
			},
		},
		Network: &NetworkPolicyConfig{
			Rules: []NetworkPolicyRule{{Name: "net1"}},
		},
	}

	diff := PolicyDiff(old, new)

	// +1 file rule, -2 network rules = net +1 -2
	// Note: added and removed are separate counters
	if !strings.Contains(diff, "+1") {
		t.Errorf("expected +1 in diff for added file rule, got: %s", diff)
	}
	if !strings.Contains(diff, "-2") {
		t.Errorf("expected -2 in diff for removed network rules, got: %s", diff)
	}
}

func TestPolicyDiffEmptyRuleSets(t *testing.T) {
	old := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{},
		},
	}

	new := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{},
		},
	}

	diff := PolicyDiff(old, new)
	if diff != "no changes detected" {
		t.Errorf("expected 'no changes detected' for empty rule sets, got: %s", diff)
	}
}

func TestPolicyDiffNilSubPolicies(t *testing.T) {
	// Test when File is nil in one policy but not the other
	old := &PolicyFiles{
		File: &FilePolicyConfig{
			Rules: []FilePolicyRule{{Name: "rule1"}},
		},
	}

	new := &PolicyFiles{
		// File is nil
		Network: &NetworkPolicyConfig{
			Rules: []NetworkPolicyRule{{Name: "net1"}},
		},
	}

	// Should not panic and should return no changes since comparison
	// requires both sides to have the same sub-policy type
	diff := PolicyDiff(old, new)
	if diff != "no changes detected" {
		t.Errorf("expected 'no changes detected' when sub-policies don't match, got: %s", diff)
	}
}
