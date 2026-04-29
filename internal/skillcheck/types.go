package skillcheck

import (
	"fmt"
	"strings"
	"time"
)

// SkillRef identifies a single skill on disk.
type SkillRef struct {
	Name     string        `json:"name" yaml:"name"`
	Source   string        `json:"source" yaml:"source"` // "user" | "plugin:<name>" | "explicit"
	Path     string        `json:"path" yaml:"path"`     // absolute
	SHA256   string        `json:"sha256" yaml:"sha256"` // canonical file-tree hash; cache key
	Origin   *GitOrigin    `json:"origin,omitempty" yaml:"origin,omitempty"`
	Manifest SkillManifest `json:"manifest" yaml:"manifest"`
}

// String returns "name@SHA256" for log/error messages.
func (r SkillRef) String() string {
	return r.Name + "@" + r.SHA256
}

// GitOrigin records the upstream URL and commit a skill was cloned from.
type GitOrigin struct {
	URL string `json:"url" yaml:"url"` // canonical https URL, e.g. https://github.com/owner/repo
	Ref string `json:"ref" yaml:"ref"` // commit SHA at scan time
}

// SkillManifest holds the parsed SKILL.md frontmatter.
type SkillManifest struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Allowed     []string `json:"allowed,omitempty" yaml:"allowed,omitempty"`
	Source      string   `json:"source,omitempty" yaml:"source,omitempty"` // optional fallback for Origin
}

// ScanRequest describes one skill to scan.
type ScanRequest struct {
	Skill  SkillRef          `json:"skill" yaml:"skill"`
	Files  map[string][]byte `json:"-" yaml:"-"` // not serialized; size-capped
	Config map[string]string `json:"config,omitempty" yaml:"config,omitempty"`
}

// ScanResponse holds one provider's results.
type ScanResponse struct {
	Provider string           `json:"provider" yaml:"provider"`
	Findings []Finding        `json:"findings,omitempty" yaml:"findings,omitempty"`
	Metadata ResponseMetadata `json:"metadata" yaml:"metadata"`
}

// ResponseMetadata holds operational details about a provider response.
type ResponseMetadata struct {
	Duration    time.Duration `json:"duration" yaml:"duration"`
	FromCache   bool          `json:"from_cache,omitempty" yaml:"from_cache,omitempty"`
	RateLimited bool          `json:"rate_limited,omitempty" yaml:"rate_limited,omitempty"`
	Partial     bool          `json:"partial,omitempty" yaml:"partial,omitempty"`
	Error       string        `json:"error,omitempty" yaml:"error,omitempty"`
}

// FindingType classifies the kind of issue (or positive signal) found.
type FindingType string

const (
	FindingPromptInjection FindingType = "prompt_injection"
	FindingExfiltration    FindingType = "exfiltration"
	FindingHiddenUnicode   FindingType = "hidden_unicode"
	FindingMalware         FindingType = "malware"
	FindingPolicyViolation FindingType = "policy_violation"
	FindingCredentialLeak  FindingType = "credential_leak"
	FindingProvenance      FindingType = "provenance" // positive signal
)

// Severity indicates how serious a finding is.
type Severity string

// Severity levels ordered from least to most severe.
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
	Skill    SkillRef          `json:"skill" yaml:"skill"`
	Severity Severity          `json:"severity" yaml:"severity"`
	Title    string            `json:"title" yaml:"title"`
	Detail   string            `json:"detail,omitempty" yaml:"detail,omitempty"`
	Reasons  []Reason          `json:"reasons,omitempty" yaml:"reasons,omitempty"`
	Links    []string          `json:"links,omitempty" yaml:"links,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// VerdictAction indicates what action to take for a skill or scan result.
type VerdictAction string

// VerdictAction values ordered from least to most restrictive.
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

func (v VerdictAction) String() string { return string(v) }

// SkillVerdict holds the verdict for a single skill.
type SkillVerdict struct {
	Skill    SkillRef      `json:"skill" yaml:"skill"`
	Action   VerdictAction `json:"action" yaml:"action"`
	Findings []Finding     `json:"findings,omitempty" yaml:"findings,omitempty"`
}

// Verdict holds the overall result of scanning a set of skills.
type Verdict struct {
	Action   VerdictAction           `json:"action" yaml:"action"`
	Findings []Finding               `json:"findings,omitempty" yaml:"findings,omitempty"`
	Summary  string                  `json:"summary" yaml:"summary"`
	Skills   map[string]SkillVerdict `json:"skills,omitempty" yaml:"skills,omitempty"`
}

// HighestAction returns the strictest action across all per-skill verdicts.
func (v Verdict) HighestAction() VerdictAction {
	highest := v.Action
	if highest == "" {
		highest = VerdictAllow
	}
	for _, sv := range v.Skills {
		if sv.Action.weight() > highest.weight() {
			highest = sv.Action
		}
	}
	return highest
}

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
