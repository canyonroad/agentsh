package skillcheck

import "testing"

func TestEvaluator_NoFindings_Allow(t *testing.T) {
	e := NewEvaluator(DefaultThresholds())
	v := e.Evaluate(nil, SkillRef{Name: "x", SHA256: "abc"})
	if v.Action != VerdictAllow {
		t.Errorf("action=%s want allow", v.Action)
	}
}

func TestEvaluator_HighFinding_Approve(t *testing.T) {
	e := NewEvaluator(DefaultThresholds())
	skill := SkillRef{Name: "x", SHA256: "abc"}
	v := e.Evaluate([]Finding{{
		Type: FindingPromptInjection, Severity: SeverityHigh, Skill: skill,
	}}, skill)
	if v.Action != VerdictApprove {
		t.Errorf("high → action=%s want approve", v.Action)
	}
}

func TestEvaluator_CriticalFinding_Block(t *testing.T) {
	e := NewEvaluator(DefaultThresholds())
	skill := SkillRef{Name: "x", SHA256: "abc"}
	v := e.Evaluate([]Finding{{Severity: SeverityCritical, Skill: skill}}, skill)
	if v.Action != VerdictBlock {
		t.Errorf("critical → action=%s want block", v.Action)
	}
}

func TestEvaluator_ProvenanceDowngrades(t *testing.T) {
	e := NewEvaluator(DefaultThresholds())
	skill := SkillRef{Name: "x", SHA256: "abc"}
	v := e.Evaluate([]Finding{
		{Type: FindingPromptInjection, Severity: SeverityHigh, Skill: skill},
		{Type: FindingProvenance, Severity: SeverityInfo, Skill: skill},
	}, skill)
	if v.Action != VerdictWarn {
		t.Errorf("high+provenance → action=%s want warn", v.Action)
	}
}

func TestEvaluator_ProvenanceFailUpgrades(t *testing.T) {
	e := NewEvaluator(DefaultThresholds())
	skill := SkillRef{Name: "x", SHA256: "abc"}
	v := e.Evaluate([]Finding{
		{Type: FindingPromptInjection, Severity: SeverityMedium, Skill: skill},
		{Type: FindingProvenance, Severity: SeverityHigh, Skill: skill, Reasons: []Reason{{Code: "skills_sh_audit_fail"}}},
	}, skill)
	if v.Action != VerdictApprove {
		t.Errorf("medium+failed-audit → action=%s want approve", v.Action)
	}
}
