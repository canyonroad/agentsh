package pkgcheck

import (
	"fmt"
	"path"
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
)

// Evaluator applies policy rules to findings and produces a Verdict.
// Rules are evaluated in order; first-match-wins per finding.
type Evaluator struct {
	rules []policy.PackageRule
}

// NewEvaluator creates a new Evaluator with the given rules.
func NewEvaluator(rules []policy.PackageRule) *Evaluator {
	return &Evaluator{rules: rules}
}

// Evaluate applies the configured rules to the provided findings and returns
// a Verdict. For each finding, rules are evaluated in order and the first
// matching rule determines the action. Per-package verdicts use the strictest
// action across all findings for that package. The overall verdict action is
// the strictest across all packages.
func (e *Evaluator) Evaluate(findings []Finding, ecosystem Ecosystem) *Verdict {
	if len(findings) == 0 {
		return e.noFindingsVerdict()
	}

	// Per-package tracking: package key -> (action, findings)
	type pkgState struct {
		action   VerdictAction
		findings []Finding
	}
	pkgMap := make(map[string]*pkgState)

	for _, f := range findings {
		action := e.evaluateFinding(f, ecosystem)
		key := f.Package.String()

		st, ok := pkgMap[key]
		if !ok {
			st = &pkgState{action: action}
			pkgMap[key] = st
		} else if action.weight() > st.action.weight() {
			st.action = action
		}
		st.findings = append(st.findings, f)
	}

	// Build per-package verdicts and compute overall strictest action.
	packages := make(map[string]PackageVerdict, len(pkgMap))
	overall := VerdictAllow

	for key, st := range pkgMap {
		packages[key] = PackageVerdict{
			Package:  st.findings[0].Package,
			Action:   st.action,
			Findings: st.findings,
		}
		if st.action.weight() > overall.weight() {
			overall = st.action
		}
	}

	return &Verdict{
		Action:   overall,
		Findings: findings,
		Summary:  buildSummary(overall, findings),
		Packages: packages,
	}
}

// evaluateFinding returns the action for a single finding by applying rules
// in order (first-match-wins). If no rule matches, it defaults to VerdictBlock
// (fail closed).
func (e *Evaluator) evaluateFinding(f Finding, ecosystem Ecosystem) VerdictAction {
	for _, rule := range e.rules {
		if matchesRule(f, ecosystem, rule.Match) {
			return mapAction(rule.Action)
		}
	}
	// No rule matched -- fail closed.
	return VerdictBlock
}

// matchesRule returns true if the finding matches all non-empty conditions in the match.
func matchesRule(f Finding, ecosystem Ecosystem, m policy.PackageMatch) bool {
	// FindingType check
	if m.FindingType != "" && string(f.Type) != m.FindingType {
		return false
	}

	// Severity check
	if m.Severity != "" && string(f.Severity) != m.Severity {
		return false
	}

	// Packages check (exact name match)
	if len(m.Packages) > 0 {
		found := false
		for _, p := range m.Packages {
			if p == f.Package.Name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Ecosystem check
	if m.Ecosystem != "" && string(ecosystem) != m.Ecosystem {
		return false
	}

	// Reasons check: at least one of the finding's reason codes must appear in the rule's list
	if len(m.Reasons) > 0 {
		found := false
		for _, fr := range f.Reasons {
			for _, mr := range m.Reasons {
				if fr.Code == mr {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// LicenseSPDX check
	if m.LicenseSPDX != nil {
		spdx := ""
		if f.Metadata != nil {
			spdx = f.Metadata["spdx"]
		}
		if len(m.LicenseSPDX.Allow) > 0 {
			if !stringInSlice(spdx, m.LicenseSPDX.Allow) {
				return false
			}
		}
		if len(m.LicenseSPDX.Deny) > 0 {
			if !stringInSlice(spdx, m.LicenseSPDX.Deny) {
				return false
			}
		}
	}

	// NamePatterns check: if specified, the finding's package name must match
	// at least one pattern (using path.Match for glob-style matching).
	if len(m.NamePatterns) > 0 {
		matched := false
		for _, pattern := range m.NamePatterns {
			if ok, _ := path.Match(pattern, f.Package.Name); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Options check: Options is not yet implemented. Rules with non-empty
	// Options are rejected at validation time (Policy.Validate), so this
	// code path should never be hit in practice. Return false (non-match)
	// as a safe fallback.
	if len(m.Options) > 0 {
		return false
	}

	return true
}

// mapAction converts a policy action string to a VerdictAction.
func mapAction(action string) VerdictAction {
	switch strings.ToLower(action) {
	case "deny", "block":
		return VerdictBlock
	case "approve":
		return VerdictApprove
	case "warn":
		return VerdictWarn
	case "allow":
		return VerdictAllow
	default:
		return VerdictBlock // unknown actions fail closed
	}
}

// noFindingsVerdict returns a verdict when there are no findings.
// It applies the last rule as the default.
func (e *Evaluator) noFindingsVerdict() *Verdict {
	action := VerdictAllow
	if len(e.rules) > 0 {
		action = mapAction(e.rules[len(e.rules)-1].Action)
	}
	return &Verdict{
		Action:  action,
		Summary: fmt.Sprintf("no findings, default action: %s", action),
	}
}

// stringInSlice checks if s is in the slice (case-sensitive).
func stringInSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// buildSummary generates a human-readable summary for a verdict.
func buildSummary(action VerdictAction, findings []Finding) string {
	return fmt.Sprintf("%d finding(s), overall action: %s", len(findings), action)
}
