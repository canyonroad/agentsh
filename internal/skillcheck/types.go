package skillcheck

import (
	"fmt"
	"strings"
	"time"
)

// SkillRef identifies a single skill on disk.
type SkillRef struct {
	Name     string        `json:"name"`
	Source   string        `json:"source"` // "user" | "plugin:<name>" | "explicit"
	Path     string        `json:"path"`   // absolute
	SHA256   string        `json:"sha256"` // canonical file-tree hash; cache key
	Origin   *GitOrigin    `json:"origin,omitempty"`
	Manifest SkillManifest `json:"manifest"`
}

// String returns "name@<short-sha>" for log/error messages.
func (r SkillRef) String() string {
	return r.Name + "@" + r.SHA256
}

// GitOrigin records the upstream URL and commit a skill was cloned from.
type GitOrigin struct {
	URL string `json:"url"` // canonical https URL, e.g. https://github.com/owner/repo
	Ref string `json:"ref"` // commit SHA at scan time
}

// SkillManifest holds the parsed SKILL.md frontmatter.
type SkillManifest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Allowed     []string `json:"allowed,omitempty"`
	Source      string   `json:"source,omitempty"` // optional fallback for Origin
}

// ScanRequest describes one skill to scan.
type ScanRequest struct {
	Skill  SkillRef          `json:"skill"`
	Files  map[string][]byte `json:"-"` // not serialized; size-capped
	Config map[string]string `json:"config,omitempty"`
}

// ScanResponse holds one provider's results.
type ScanResponse struct {
	Provider string           `json:"provider"`
	Findings []Finding        `json:"findings,omitempty"`
	Metadata ResponseMetadata `json:"metadata"`
}

type ResponseMetadata struct {
	Duration    time.Duration `json:"duration"`
	FromCache   bool          `json:"from_cache,omitempty"`
	RateLimited bool          `json:"rate_limited,omitempty"`
	Partial     bool          `json:"partial,omitempty"`
	Error       string        `json:"error,omitempty"`
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

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

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
		return 5 // unknown fails closed
	}
}

type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Finding struct {
	Type     FindingType       `json:"type"`
	Provider string            `json:"provider"`
	Skill    SkillRef          `json:"skill"`
	Severity Severity          `json:"severity"`
	Title    string            `json:"title"`
	Detail   string            `json:"detail,omitempty"`
	Reasons  []Reason          `json:"reasons,omitempty"`
	Links    []string          `json:"links,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type VerdictAction string

const (
	VerdictAllow   VerdictAction = "allow"
	VerdictWarn    VerdictAction = "warn"
	VerdictApprove VerdictAction = "approve"
	VerdictBlock   VerdictAction = "block"
)

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
		return 4 // unknown fails closed
	}
}

func (v VerdictAction) String() string { return string(v) }

type SkillVerdict struct {
	Skill    SkillRef      `json:"skill"`
	Action   VerdictAction `json:"action"`
	Findings []Finding     `json:"findings,omitempty"`
}

type Verdict struct {
	Action   VerdictAction           `json:"action"`
	Findings []Finding               `json:"findings,omitempty"`
	Summary  string                  `json:"summary"`
	Skills   map[string]SkillVerdict `json:"skills,omitempty"`
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
