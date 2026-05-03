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

func TestCompileBlockOnRules_NoCatchAll(t *testing.T) {
	// CompileBlockOnRules must NOT append a catch-all allow rule.
	// CompileBlockOn (the public wrapper) should still end with one.
	cfg := BlockOnConfig{
		Malware:       "any",
		Vulnerability: "critical",
	}

	rules := CompileBlockOnRules(cfg)
	if len(rules) == 0 {
		t.Fatal("expected at least one rule from CompileBlockOnRules")
	}
	last := rules[len(rules)-1]
	if last.Match.FindingType == "" && last.Action == "allow" {
		t.Errorf("CompileBlockOnRules must NOT end with a catch-all allow rule; got %+v", last)
	}

	// CompileBlockOn should still end with a catch-all.
	allRules := CompileBlockOn(cfg)
	lastAll := allRules[len(allRules)-1]
	if lastAll.Match.FindingType != "" || lastAll.Action != "allow" {
		t.Errorf("CompileBlockOn must still end with a catch-all allow rule; got %+v", lastAll)
	}
	// CompileBlockOn should have exactly one more rule than CompileBlockOnRules.
	if len(allRules) != len(rules)+1 {
		t.Errorf("CompileBlockOn len=%d, CompileBlockOnRules len=%d; expected exactly 1 more", len(allRules), len(rules))
	}
}

func TestBlockOnConfig_ValidateRejectsTypos(t *testing.T) {
	cfg := BlockOnConfig{Vulnerability: "critcal"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("typo must be rejected")
	}
}

func TestBlockOnConfig_ValidateAcceptsAllValidCombinations(t *testing.T) {
	cases := []BlockOnConfig{
		{Malware: "any", Vulnerability: "critical", License: "never", Reputation: "never", Provenance: "never"},
		{Malware: "critical", Vulnerability: "high"},
		{Malware: "never", Vulnerability: "medium", License: "any"},
		{}, // all empty is fine
	}
	for _, c := range cases {
		if err := c.Validate(); err != nil {
			t.Errorf("config %+v: unexpected error %v", c, err)
		}
	}
}
