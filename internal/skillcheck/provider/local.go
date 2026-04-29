package provider

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

type localProvider struct{}

// NewLocalProvider returns the built-in offline rule engine. It runs
// without network access, fails closed via OnFailure, and detects the
// rule set documented in the spec.
func NewLocalProvider() skillcheck.CheckProvider { return &localProvider{} }

func (p *localProvider) Name() string { return "local" }

func (p *localProvider) Capabilities() []skillcheck.FindingType {
	return []skillcheck.FindingType{
		skillcheck.FindingHiddenUnicode,
		skillcheck.FindingExfiltration,
		skillcheck.FindingPolicyViolation,
		skillcheck.FindingPromptInjection,
		skillcheck.FindingCredentialLeak,
	}
}

var (
	reEvalEnv         = regexp.MustCompile(`(?m)\beval\s+["']?\$\{?[A-Z_][A-Z0-9_]*`)
	rePromptInjection = regexp.MustCompile(`(?i)ignore (all )?(previous|prior) instructions|<system>|<\|system\|>`)
	reBase64Blob      = regexp.MustCompile(`[A-Za-z0-9+/]{1000,}={0,2}`)
	reShellWriteVerbs = regexp.MustCompile(`(?m)\b(rm\s+-rf|curl\s+-X\s+POST|wget\s+--post|chmod\s+\+x)\b`)
)

func (p *localProvider) Scan(ctx context.Context, req skillcheck.ScanRequest) (*skillcheck.ScanResponse, error) {
	start := time.Now()
	var findings []skillcheck.Finding

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for path, data := range req.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if hidden := scanHiddenUnicode(data); hidden != "" {
			findings = append(findings, skillcheck.Finding{
				Type:     skillcheck.FindingHiddenUnicode,
				Provider: p.Name(),
				Skill:    req.Skill,
				Severity: skillcheck.SeverityHigh,
				Title:    "Hidden Unicode characters in " + path,
				Detail:   "Detected " + hidden,
				Reasons:  []skillcheck.Reason{{Code: "hidden_unicode"}},
			})
		}
		text := string(data)
		if reEvalEnv.MatchString(text) {
			findings = append(findings, skillcheck.Finding{
				Type:     skillcheck.FindingExfiltration,
				Provider: p.Name(),
				Skill:    req.Skill,
				Severity: skillcheck.SeverityHigh,
				Title:    "eval of environment variable in " + path,
				Reasons:  []skillcheck.Reason{{Code: "eval_env"}},
			})
		}
		if rePromptInjection.MatchString(text) {
			findings = append(findings, skillcheck.Finding{
				Type:     skillcheck.FindingPromptInjection,
				Provider: p.Name(),
				Skill:    req.Skill,
				Severity: skillcheck.SeverityMedium,
				Title:    "Prompt-injection markers in " + path,
				Reasons:  []skillcheck.Reason{{Code: "prompt_injection_marker"}},
			})
		}
		if reBase64Blob.MatchString(text) {
			findings = append(findings, skillcheck.Finding{
				Type:     skillcheck.FindingCredentialLeak,
				Provider: p.Name(),
				Skill:    req.Skill,
				Severity: skillcheck.SeverityMedium,
				Title:    "Large base64 blob in " + path,
				Reasons:  []skillcheck.Reason{{Code: "base64_blob"}},
			})
		}
		if scopeMismatch(req.Skill.Manifest, text) {
			findings = append(findings, skillcheck.Finding{
				Type:     skillcheck.FindingPolicyViolation,
				Provider: p.Name(),
				Skill:    req.Skill,
				Severity: skillcheck.SeverityHigh,
				Title:    "Skill body exceeds declared scope in " + path,
				Detail:   "manifest declares only: " + strings.Join(req.Skill.Manifest.Allowed, ","),
				Reasons:  []skillcheck.Reason{{Code: "scope_mismatch"}},
			})
		}
	}

	return &skillcheck.ScanResponse{
		Provider: p.Name(),
		Findings: findings,
		Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start)},
	}, nil
}

// scanHiddenUnicode returns a non-empty description if the data contains
// Tag chars (U+E0000–U+E007F), bidi overrides (U+202A–U+202E), or zero-width
// joiners that are not in the ASCII whitespace set.
func scanHiddenUnicode(data []byte) string {
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			return "Unicode Tag characters (U+E0000 range)"
		case r >= 0x202A && r <= 0x202E:
			return "bidi override characters"
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF:
			return "zero-width characters"
		}
		i += size
	}
	return ""
}

// scopeMismatch returns true if the manifest declares only read-equivalent
// permissions (or none) but the body contains shell write/network verbs.
func scopeMismatch(m skillcheck.SkillManifest, text string) bool {
	if !reShellWriteVerbs.MatchString(text) {
		return false
	}
	if len(m.Allowed) == 0 {
		return true // no permissions declared at all but body writes/network
	}
	for _, a := range m.Allowed {
		switch strings.ToLower(a) {
		case "bash", "shell", "exec", "write", "network":
			return false // explicitly allowed
		}
	}
	return true
}
