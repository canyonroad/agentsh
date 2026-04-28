package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

// SnykConfig configures the Snyk subprocess provider.
type SnykConfig struct {
	BinaryPath   string                            // optional override
	PathLookup   func(name string) (string, error) // injected for tests; defaults to exec.LookPath
	UvxAvailable func() bool                       // injected for tests; defaults to checking exec.LookPath("uvx")
}

type snykProvider struct {
	cfg SnykConfig
}

// NewSnykProvider returns the Snyk Agent Scan subprocess wrapper.
func NewSnykProvider(cfg SnykConfig) skillcheck.CheckProvider {
	if cfg.PathLookup == nil {
		cfg.PathLookup = exec.LookPath
	}
	if cfg.UvxAvailable == nil {
		cfg.UvxAvailable = func() bool {
			_, err := exec.LookPath("uvx")
			return err == nil
		}
	}
	return &snykProvider{cfg: cfg}
}

func (p *snykProvider) Name() string { return "snyk" }

func (p *snykProvider) Capabilities() []skillcheck.FindingType {
	return []skillcheck.FindingType{
		skillcheck.FindingPromptInjection,
		skillcheck.FindingExfiltration,
		skillcheck.FindingMalware,
		skillcheck.FindingCredentialLeak,
		skillcheck.FindingPolicyViolation,
	}
}

// resolveCommand returns argv ([]string) for invoking snyk-agent-scan
// against the given skill directory. Returns an error if no executable
// can be found.
func (p *snykProvider) resolveCommand(skillDir string) ([]string, error) {
	if p.cfg.BinaryPath != "" {
		return []string{p.cfg.BinaryPath, "--skills", skillDir, "--json"}, nil
	}
	if path, err := p.cfg.PathLookup("snyk-agent-scan"); err == nil {
		return []string{path, "--skills", skillDir, "--json"}, nil
	}
	if p.cfg.UvxAvailable() {
		return []string{"uvx", "snyk-agent-scan@latest", "--skills", skillDir, "--json"}, nil
	}
	return nil, fmt.Errorf("snyk: no executable found (set providers.snyk.binary_path, install snyk-agent-scan on PATH, or install uvx)")
}

func (p *snykProvider) Scan(ctx context.Context, req skillcheck.ScanRequest) (*skillcheck.ScanResponse, error) {
	start := time.Now()
	argv, err := p.resolveCommand(req.Skill.Path)
	if err != nil {
		return &skillcheck.ScanResponse{
			Provider: p.Name(),
			Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start), Error: err.Error()},
		}, nil
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.Output()
	if err != nil {
		return &skillcheck.ScanResponse{
			Provider: p.Name(),
			Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start), Error: err.Error()},
		}, nil
	}
	findings, partial := parseSnykOutput(out, req.Skill, p.Name())
	return &skillcheck.ScanResponse{
		Provider: p.Name(),
		Findings: findings,
		Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start), Partial: partial},
	}, nil
}

type snykJSON struct {
	Findings []snykFinding `json:"findings"`
}

type snykFinding struct {
	Type       string            `json:"type"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Detail     string            `json:"detail,omitempty"`
	ReasonCode string            `json:"reason_code,omitempty"`
	Links      []string          `json:"links,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func parseSnykOutput(out []byte, skill skillcheck.SkillRef, providerName string) (findings []skillcheck.Finding, partial bool) {
	var doc snykJSON
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, true
	}
	for _, f := range doc.Findings {
		findings = append(findings, skillcheck.Finding{
			Type:     mapSnykType(f.Type),
			Provider: providerName,
			Skill:    skill,
			Severity: mapSnykSeverity(f.Severity),
			Title:    f.Title,
			Detail:   f.Detail,
			Reasons:  []skillcheck.Reason{{Code: f.ReasonCode}},
			Links:    f.Links,
			Metadata: f.Metadata,
		})
	}
	return findings, false
}

func mapSnykType(t string) skillcheck.FindingType {
	switch strings.ToLower(t) {
	case "prompt_injection":
		return skillcheck.FindingPromptInjection
	case "exfiltration":
		return skillcheck.FindingExfiltration
	case "malware":
		return skillcheck.FindingMalware
	case "credential_leak", "secret":
		return skillcheck.FindingCredentialLeak
	case "policy_violation":
		return skillcheck.FindingPolicyViolation
	default:
		return skillcheck.FindingPolicyViolation
	}
}

func mapSnykSeverity(s string) skillcheck.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return skillcheck.SeverityCritical
	case "high":
		return skillcheck.SeverityHigh
	case "medium":
		return skillcheck.SeverityMedium
	case "low":
		return skillcheck.SeverityLow
	default:
		return skillcheck.SeverityInfo
	}
}
