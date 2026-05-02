package config

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestCompileBlockOn_DefaultsAndOverrides(t *testing.T) {
	rules := CompileBlockOn(BlockOnConfig{
		Malware:       "any",
		Vulnerability: "critical",
		License:       "never",
		Reputation:    "never",
		Provenance:    "never",
	})

	// Expect: malware-any → deny; vuln-critical → deny; vuln-high → warn;
	// then a catch-all allow at the end.
	if len(rules) < 4 {
		t.Fatalf("want >=4 rules, got %d: %+v", len(rules), rules)
	}

	denyMalware := containsRule(rules, policy.PackageRule{
		Match: policy.PackageMatch{FindingType: "malware"}, Action: "deny",
	})
	denyCritVuln := containsRule(rules, policy.PackageRule{
		Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny",
	})
	warnHighVuln := containsRule(rules, policy.PackageRule{
		Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "high"}, Action: "warn",
	})
	if !denyMalware {
		t.Error("missing malware deny rule")
	}
	if !denyCritVuln {
		t.Error("missing vulnerability/critical deny rule")
	}
	if !warnHighVuln {
		t.Error("missing vulnerability/high warn rule")
	}

	last := rules[len(rules)-1]
	if last.Action != "allow" || last.Match.FindingType != "" {
		t.Errorf("expected catch-all allow as last rule, got %+v", last)
	}
}

func TestCompileBlockOn_MalwareCriticalOnly(t *testing.T) {
	rules := CompileBlockOn(BlockOnConfig{Malware: "critical"})
	denyCritMalware := containsRule(rules, policy.PackageRule{
		Match: policy.PackageMatch{FindingType: "malware", Severity: "critical"}, Action: "deny",
	})
	denyAnyMalware := containsRule(rules, policy.PackageRule{
		Match: policy.PackageMatch{FindingType: "malware"}, Action: "deny",
	})
	if !denyCritMalware {
		t.Error("missing malware/critical deny rule")
	}
	if denyAnyMalware {
		t.Error("malware/critical mode must NOT also produce an unconditional malware deny rule")
	}
}

// containsRule compares rules ignoring Reason text.
func containsRule(rules []policy.PackageRule, want policy.PackageRule) bool {
	for _, r := range rules {
		if r.Match.FindingType == want.Match.FindingType &&
			r.Match.Severity == want.Match.Severity &&
			r.Action == want.Action {
			return true
		}
	}
	return false
}
