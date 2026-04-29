package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

// SkillsShConfig configures the skills.sh provenance provider.
type SkillsShConfig struct {
	BaseURL     string        // default https://skills.sh
	Timeout     time.Duration // default 10s
	ProbeAudits bool          // opt-in __NEXT_DATA__ parsing (not implemented in v1)
	HTTPClient  *http.Client  // injected for tests
}

type skillsShProvider struct {
	baseURL string
	client  *http.Client
	probe   bool
}

// NewSkillsShProvider returns the skills.sh provenance HTTP provider.
// It issues a HEAD request to https://skills.sh/<owner>/<repo>/<skill-name>.
// 200 OK emits a FindingProvenance/SeverityInfo finding; 404 is neutral.
// Other HTTP errors are soft-failed (stored in Metadata.Error) so that
// network failures don't block skill installs by default.
func NewSkillsShProvider(cfg SkillsShConfig) skillcheck.CheckProvider {
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://skills.sh"
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &skillsShProvider{baseURL: base, client: client, probe: cfg.ProbeAudits}
}

func (p *skillsShProvider) Name() string { return "skills_sh" }

func (p *skillsShProvider) Capabilities() []skillcheck.FindingType {
	return []skillcheck.FindingType{skillcheck.FindingProvenance}
}

func (p *skillsShProvider) Scan(ctx context.Context, req skillcheck.ScanRequest) (*skillcheck.ScanResponse, error) {
	start := time.Now()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if req.Skill.Origin == nil {
		return &skillcheck.ScanResponse{
			Provider: p.Name(),
			Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start)},
		}, nil
	}

	owner, repo, ok := parseGitHubOriginPath(req.Skill.Origin.URL)
	if !ok {
		return &skillcheck.ScanResponse{
			Provider: p.Name(),
			Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start)},
		}, nil
	}

	target := fmt.Sprintf("%s/%s/%s/%s", p.baseURL, owner, repo, url.PathEscape(req.Skill.Name))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return &skillcheck.ScanResponse{
			Provider: p.Name(),
			Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start), Error: err.Error()},
		}, nil
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		// Propagate context cancellation/deadline so the orchestrator's timeout
		// path fires correctly. Other HTTP errors stay soft-fail (network
		// unreachable should not block skill installs by default).
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return &skillcheck.ScanResponse{
			Provider: p.Name(),
			Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start), Error: err.Error()},
		}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return &skillcheck.ScanResponse{
			Provider: p.Name(),
			Findings: []skillcheck.Finding{{
				Type:     skillcheck.FindingProvenance,
				Provider: p.Name(),
				Skill:    req.Skill,
				Severity: skillcheck.SeverityInfo,
				Title:    "Registered on skills.sh",
				Reasons:  []skillcheck.Reason{{Code: "skills_sh_registered"}},
				Links:    []string{target},
			}},
			Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start)},
		}, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		// 404: skill genuinely not in registry — neutral, no finding.
		return &skillcheck.ScanResponse{
			Provider: p.Name(),
			Metadata: skillcheck.ResponseMetadata{Duration: time.Since(start)},
		}, nil
	}
	// Any other status (5xx, 429, etc.): soft-fail so operators can see the issue.
	return &skillcheck.ScanResponse{
		Provider: p.Name(),
		Metadata: skillcheck.ResponseMetadata{
			Duration: time.Since(start),
			Error:    fmt.Sprintf("skills.sh: unexpected status %d", resp.StatusCode),
		},
	}, nil
}

// parseGitHubOriginPath extracts (owner, repo) from an https GitHub URL.
func parseGitHubOriginPath(rawURL string) (string, string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}
	if u.Host != "github.com" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", false
	}
	repo := strings.TrimSuffix(parts[1], ".git")
	return parts[0], repo, true
}
