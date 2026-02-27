package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

const (
	defaultSnykBaseURL = "https://api.snyk.io"
	defaultSnykTimeout = 30 * time.Second
)

// SnykConfig configures the Snyk vulnerability and license provider.
type SnykConfig struct {
	BaseURL string
	Timeout time.Duration
	APIKey  string
	OrgID   string
}

// snykProvider queries the Snyk API for vulnerability and license findings.
type snykProvider struct {
	baseURL string
	client  *http.Client
	apiKey  string
	orgID   string
}

// NewSnykProvider returns a CheckProvider that queries Snyk for vulnerabilities
// and license issues.
func NewSnykProvider(cfg SnykConfig) pkgcheck.CheckProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultSnykBaseURL
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultSnykTimeout
	}
	return &snykProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
		apiKey:  cfg.APIKey,
		orgID:   cfg.OrgID,
	}
}

func (p *snykProvider) Name() string {
	return "snyk"
}

func (p *snykProvider) Capabilities() []pkgcheck.FindingType {
	return []pkgcheck.FindingType{pkgcheck.FindingVulnerability, pkgcheck.FindingLicense}
}

// snykIssuesResponse represents the Snyk REST API response for package issues.
type snykIssuesResponse struct {
	Data []snykIssue `json:"data"`
}

type snykIssue struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Attributes snykAttributes  `json:"attributes"`
}

type snykAttributes struct {
	Title       string       `json:"title"`
	Description string       `json:"description,omitempty"`
	Severity    string       `json:"severity"`
	Type        string       `json:"type"`
	CVSS        *snykCVSS    `json:"cvss,omitempty"`
	Slots       *snykSlots   `json:"slots,omitempty"`
}

type snykCVSS struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector,omitempty"`
}

type snykSlots struct {
	References []snykReference `json:"references,omitempty"`
	License    string          `json:"license,omitempty"`
}

type snykReference struct {
	URL   string `json:"url"`
	Title string `json:"title,omitempty"`
}

func (p *snykProvider) CheckBatch(ctx context.Context, req pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("snyk: API key is required")
	}
	if p.orgID == "" {
		return nil, fmt.Errorf("snyk: org ID is required")
	}

	start := time.Now()
	ecosystem := mapEcosystemSnyk(req.Ecosystem)

	var allFindings []pkgcheck.Finding
	var partial bool

	for _, pkg := range req.Packages {
		findings, err := p.fetchIssues(ctx, ecosystem, pkg)
		if err != nil {
			partial = true
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return &pkgcheck.CheckResponse{
		Provider: p.Name(),
		Findings: allFindings,
		Metadata: pkgcheck.ResponseMetadata{
			Duration: time.Since(start),
			Partial:  partial,
		},
	}, nil
}

func (p *snykProvider) fetchIssues(ctx context.Context, ecosystem string, pkg pkgcheck.PackageRef) ([]pkgcheck.Finding, error) {
	reqURL := fmt.Sprintf("%s/rest/orgs/%s/packages/%s%%2F%s/issues?version=%s",
		p.baseURL,
		url.PathEscape(p.orgID),
		url.PathEscape(ecosystem),
		url.PathEscape(pkg.Name),
		url.QueryEscape(pkg.Version),
	)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("snyk: create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "token "+p.apiKey)
	httpReq.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("snyk: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("snyk: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var issuesResp snykIssuesResponse
	if err := json.NewDecoder(resp.Body).Decode(&issuesResp); err != nil {
		return nil, fmt.Errorf("snyk: decode response: %w", err)
	}

	return p.mapIssues(pkg, &issuesResp), nil
}

func (p *snykProvider) mapIssues(pkg pkgcheck.PackageRef, resp *snykIssuesResponse) []pkgcheck.Finding {
	var findings []pkgcheck.Finding

	for _, issue := range resp.Data {
		findingType, severity := p.classifyIssue(issue)

		var links []string
		if issue.Attributes.Slots != nil {
			for _, ref := range issue.Attributes.Slots.References {
				links = append(links, ref.URL)
			}
		}

		metadata := map[string]string{
			"snyk_id": issue.ID,
		}
		if issue.Attributes.Slots != nil && issue.Attributes.Slots.License != "" {
			metadata["license"] = issue.Attributes.Slots.License
		}

		findings = append(findings, pkgcheck.Finding{
			Type:     findingType,
			Provider: p.Name(),
			Package:  pkg,
			Severity: severity,
			Title:    issue.Attributes.Title,
			Detail:   issue.Attributes.Description,
			Reasons: []pkgcheck.Reason{
				{Code: mapSnykIssueCode(issue.Attributes.Type), Message: issue.ID},
			},
			Links:    links,
			Metadata: metadata,
		})
	}

	return findings
}

func (p *snykProvider) classifyIssue(issue snykIssue) (pkgcheck.FindingType, pkgcheck.Severity) {
	// Determine finding type from the Snyk issue type.
	findingType := pkgcheck.FindingVulnerability
	switch issue.Attributes.Type {
	case "license", "license_issue":
		findingType = pkgcheck.FindingLicense
	case "vulnerability", "vuln":
		findingType = pkgcheck.FindingVulnerability
	}

	// Map severity.
	severity := pkgcheck.SeverityMedium
	switch strings.ToLower(issue.Attributes.Severity) {
	case "critical":
		severity = pkgcheck.SeverityCritical
	case "high":
		severity = pkgcheck.SeverityHigh
	case "medium":
		severity = pkgcheck.SeverityMedium
	case "low":
		severity = pkgcheck.SeverityLow
	}

	// Use CVSS score if available for more accurate severity.
	if findingType == pkgcheck.FindingVulnerability && issue.Attributes.CVSS != nil {
		score := issue.Attributes.CVSS.Score
		if score >= 9.0 {
			severity = pkgcheck.SeverityCritical
		} else if score >= 7.0 {
			severity = pkgcheck.SeverityHigh
		} else if score >= 4.0 {
			severity = pkgcheck.SeverityMedium
		} else {
			severity = pkgcheck.SeverityLow
		}
	}

	return findingType, severity
}

// mapSnykIssueCode converts a Snyk issue type to a reason code.
func mapSnykIssueCode(issueType string) string {
	switch issueType {
	case "license", "license_issue":
		return "license_issue"
	default:
		return "known_vulnerability"
	}
}

// mapEcosystemSnyk converts our Ecosystem type to the Snyk ecosystem string.
func mapEcosystemSnyk(eco pkgcheck.Ecosystem) string {
	switch eco {
	case pkgcheck.EcosystemNPM:
		return "npm"
	case pkgcheck.EcosystemPyPI:
		return "pip"
	default:
		return string(eco)
	}
}
