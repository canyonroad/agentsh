package pkgcheck

import (
	"fmt"
	"strings"
	"time"
)

// Ecosystem identifies a package ecosystem.
type Ecosystem string

const (
	EcosystemNPM  Ecosystem = "npm"
	EcosystemPyPI Ecosystem = "pypi"
)

// PackageRef identifies a single package within an ecosystem.
type PackageRef struct {
	Name     string `json:"name" yaml:"name"`
	Version  string `json:"version,omitempty" yaml:"version,omitempty"`
	Registry string `json:"registry,omitempty" yaml:"registry,omitempty"`
	Direct   bool   `json:"direct,omitempty" yaml:"direct,omitempty"`
}

// String returns "name@version" or just "name" if no version is set.
func (p PackageRef) String() string {
	if p.Version == "" {
		return p.Name
	}
	return p.Name + "@" + p.Version
}

// InstallPlan describes a pending package installation.
type InstallPlan struct {
	Tool       string       `json:"tool" yaml:"tool"`
	Ecosystem  Ecosystem    `json:"ecosystem" yaml:"ecosystem"`
	WorkDir    string       `json:"work_dir" yaml:"work_dir"`
	Command    []string     `json:"command" yaml:"command"`
	Direct     []PackageRef `json:"direct" yaml:"direct"`
	Transitive []PackageRef `json:"transitive,omitempty" yaml:"transitive,omitempty"`
	Registry   string       `json:"registry,omitempty" yaml:"registry,omitempty"`
	ResolvedAt time.Time    `json:"resolved_at" yaml:"resolved_at"`
}

// AllPackages returns all direct and transitive packages combined.
func (p InstallPlan) AllPackages() []PackageRef {
	all := make([]PackageRef, 0, len(p.Direct)+len(p.Transitive))
	all = append(all, p.Direct...)
	all = append(all, p.Transitive...)
	return all
}

// FindingType classifies the kind of issue found during a package check.
type FindingType string

const (
	FindingVulnerability FindingType = "vulnerability"
	FindingLicense       FindingType = "license"
	FindingProvenance    FindingType = "provenance"
	FindingReputation    FindingType = "reputation"
	FindingMalware       FindingType = "malware"
)

// Severity indicates how serious a finding is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Weight returns a numeric weight for severity ordering.
// Higher values indicate more severe findings.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	default:
		return 5 // unknown severities fail closed (stricter than critical)
	}
}

// Reason provides a machine-readable code and human-readable message for a finding.
type Reason struct {
	Code    string `json:"code" yaml:"code"`
	Message string `json:"message" yaml:"message"`
}

// Finding represents a single issue discovered by a check provider.
type Finding struct {
	Type     FindingType       `json:"type" yaml:"type"`
	Provider string            `json:"provider" yaml:"provider"`
	Package  PackageRef        `json:"package" yaml:"package"`
	Severity Severity          `json:"severity" yaml:"severity"`
	Title    string            `json:"title" yaml:"title"`
	Detail   string            `json:"detail,omitempty" yaml:"detail,omitempty"`
	Reasons  []Reason          `json:"reasons,omitempty" yaml:"reasons,omitempty"`
	Links    []string          `json:"links,omitempty" yaml:"links,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// VerdictAction indicates what action to take for a package or install plan.
type VerdictAction string

const (
	VerdictAllow   VerdictAction = "allow"
	VerdictWarn    VerdictAction = "warn"
	VerdictApprove VerdictAction = "approve"
	VerdictBlock   VerdictAction = "block"
)

// weight returns the internal priority of a verdict action.
// Higher values take precedence when combining verdicts.
func (v VerdictAction) weight() int {
	switch v {
	case VerdictAllow:
		return 0
	case VerdictWarn:
		return 1
	case VerdictApprove:
		return 2
	case VerdictBlock:
		return 3
	default:
		return 4 // unknown actions fail closed (stricter than block)
	}
}

// String returns the string representation of a VerdictAction.
func (v VerdictAction) String() string {
	return string(v)
}

// PackageVerdict holds the verdict for a single package.
type PackageVerdict struct {
	Package  PackageRef `json:"package" yaml:"package"`
	Action   VerdictAction `json:"action" yaml:"action"`
	Findings []Finding     `json:"findings,omitempty" yaml:"findings,omitempty"`
}

// Verdict holds the overall result of checking an install plan.
type Verdict struct {
	Action   VerdictAction             `json:"action" yaml:"action"`
	Findings []Finding                 `json:"findings,omitempty" yaml:"findings,omitempty"`
	Summary  string                    `json:"summary" yaml:"summary"`
	Packages map[string]PackageVerdict `json:"packages,omitempty" yaml:"packages,omitempty"`
}

// HighestAction returns the most restrictive action across all package verdicts.
// If there are no packages, it returns the verdict's own action.
func (v Verdict) HighestAction() VerdictAction {
	highest := v.Action
	for _, pv := range v.Packages {
		if pv.Action.weight() > highest.weight() {
			highest = pv.Action
		}
	}
	return highest
}

// String returns a human-readable summary of the verdict.
func (v Verdict) String() string {
	parts := []string{fmt.Sprintf("action=%s", v.Action)}
	if v.Summary != "" {
		parts = append(parts, v.Summary)
	}
	if len(v.Findings) > 0 {
		parts = append(parts, fmt.Sprintf("findings=%d", len(v.Findings)))
	}
	return strings.Join(parts, " ")
}
