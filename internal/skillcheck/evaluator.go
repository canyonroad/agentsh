package skillcheck

import "fmt"

// Thresholds maps severity → action. The default is documented in the spec.
type Thresholds map[Severity]VerdictAction

// DefaultThresholds returns: info,low → allow; medium → warn; high → approve;
// critical → block.
func DefaultThresholds() Thresholds {
	return Thresholds{
		SeverityInfo:     VerdictAllow,
		SeverityLow:      VerdictAllow,
		SeverityMedium:   VerdictWarn,
		SeverityHigh:     VerdictApprove,
		SeverityCritical: VerdictBlock,
	}
}

// Evaluator turns provider findings into a Verdict using the configured
// severity thresholds and a provenance-aware adjustment.
type Evaluator struct {
	thresholds Thresholds
}

// NewEvaluator creates a new Evaluator with the given thresholds.
// If t is nil, DefaultThresholds() is used.
func NewEvaluator(t Thresholds) *Evaluator {
	if t == nil {
		t = DefaultThresholds()
	}
	return &Evaluator{thresholds: t}
}

// Evaluate computes a Verdict for a single skill from its findings.
func (e *Evaluator) Evaluate(findings []Finding, skill SkillRef) *Verdict {
	if len(findings) == 0 {
		return &Verdict{Action: VerdictAllow, Summary: "no findings"}
	}

	// 1. base severity = max non-provenance severity; negative provenance
	// (audit_fail) is included because it represents a known-bad signal.
	base := SeverityInfo
	for _, f := range findings {
		if f.Type == FindingProvenance && !isAuditFail(f) {
			continue // exclude positive provenance from base
		}
		if f.Severity.Weight() > base.Weight() {
			base = f.Severity
		}
	}

	// 2. provenance adjustment
	registered := false
	auditFail := false
	for _, f := range findings {
		if f.Type != FindingProvenance {
			continue
		}
		registered = true
		if isAuditFail(f) {
			auditFail = true
		}
	}
	adjusted := base
	if registered {
		if auditFail {
			adjusted = stepUp(base)
		} else {
			adjusted = stepDown(base)
		}
	}

	action := e.thresholds[adjusted]
	if action == "" {
		action = VerdictBlock
	}

	skillKey := skill.String()
	return &Verdict{
		Action:   action,
		Findings: findings,
		Summary:  fmt.Sprintf("%d finding(s); base=%s adjusted=%s; action=%s", len(findings), base, adjusted, action),
		Skills: map[string]SkillVerdict{
			skillKey: {Skill: skill, Action: action, Findings: findings},
		},
	}
}

func stepUp(s Severity) Severity {
	switch s {
	case SeverityInfo:
		return SeverityLow
	case SeverityLow:
		return SeverityMedium
	case SeverityMedium:
		return SeverityHigh
	case SeverityHigh:
		return SeverityCritical
	default:
		return SeverityCritical
	}
}

func stepDown(s Severity) Severity {
	switch s {
	case SeverityCritical:
		return SeverityHigh
	case SeverityHigh:
		return SeverityMedium
	case SeverityMedium:
		return SeverityLow
	case SeverityLow:
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// isAuditFail reports whether a provenance finding represents a failed
// upstream audit (e.g. skills_sh_audit_fail) rather than a positive signal.
func isAuditFail(f Finding) bool {
	if f.Type != FindingProvenance {
		return false
	}
	for _, r := range f.Reasons {
		if r.Code == "skills_sh_audit_fail" {
			return true
		}
	}
	return false
}
