package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

const (
	defaultSnykBaseURL    = "https://api.snyk.io"
	defaultSnykTimeout    = 30 * time.Second
	defaultSnykConcurrency = 16
)

// SnykConfig configures the Snyk vulnerability and license provider.
type SnykConfig struct {
	BaseURL     string
	Timeout     time.Duration
	APIKey      string
	OrgID       string
	Concurrency int // max concurrent per-package fetches; default 16
}

// snykProvider queries the Snyk API for vulnerability and license findings.
type snykProvider struct {
	baseURL     string
	client      *retryClient
	breaker     *circuitBreaker
	apiKey      string
	orgID       string
	timeout     time.Duration
	concurrency int
}

// NewSnykProvider returns a CheckProvider that queries Snyk for vulnerabilities
// and license issues.
func NewSnykProvider(cfg SnykConfig) pkgcheck.CheckProvider {
	return newSnykProviderForTest(cfg, circuitBreakerConfig{})
}

// newSnykProviderForTest constructs a snykProvider with a custom breaker
// config, allowing tests to inject short thresholds and windows.
func newSnykProviderForTest(cfg SnykConfig, breakerCfg circuitBreakerConfig) *snykProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultSnykBaseURL
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultSnykTimeout
	}
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = defaultSnykConcurrency
	}
	return &snykProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: newRetryClient(retryConfig{
			MaxAttempts:       3,
			BaseBackoff:       200 * time.Millisecond,
			MaxBackoff:        2 * time.Second,
			RespectRetryAfter: true,
		}),
		breaker:     newCircuitBreaker(breakerCfg),
		apiKey:      cfg.APIKey,
		orgID:       cfg.OrgID,
		timeout:     timeout,
		concurrency: concurrency,
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
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Attributes snykAttributes `json:"attributes"`
}

type snykAttributes struct {
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Severity    string     `json:"severity"`
	Type        string     `json:"type"`
	CVSS        *snykCVSS  `json:"cvss,omitempty"`
	Slots       *snykSlots `json:"slots,omitempty"`
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

// pkgResult holds the per-package outcome from the concurrent fan-out.
type pkgResult struct {
	findings []pkgcheck.Finding
	err      error
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

	n := len(req.Packages)
	results := make([]pkgResult, n)

	// Semaphore channel for bounded concurrency.
	sem := make(chan struct{}, p.concurrency)

	var wg sync.WaitGroup
	wg.Add(n)

	for i, pkg := range req.Packages {
		i, pkg := i, pkg // capture
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			// Apply per-request timeout only on the HTTP call, NOT on callWithBreaker.
			reqCtx := ctx
			var cancel context.CancelFunc
			if p.timeout > 0 {
				reqCtx, cancel = context.WithTimeout(ctx, p.timeout)
				defer cancel()
			}

			var findings []pkgcheck.Finding
			err := callWithBreaker(p.breaker, ctx, func() error {
				var ferr error
				findings, ferr = p.fetchIssues(reqCtx, ecosystem, pkg)
				return ferr
			})
			results[i] = pkgResult{findings: findings, err: err}
		}()
	}
	wg.Wait()

	// Merge results; detect auth errors and breaker-open conditions.
	var allFindings []pkgcheck.Finding
	var partial bool
	var errCount int
	var breakerErr error

	for _, r := range results {
		if r.err != nil {
			// Auth errors are fail-fast — return immediately.
			if isSnykAuthError(r.err) {
				return nil, fmt.Errorf("snyk: authentication failed: %w", r.err)
			}
			errCount++
			partial = true
			if errors.Is(r.err, errBreakerOpen) {
				breakerErr = r.err
			}
			continue
		}
		allFindings = append(allFindings, r.findings...)
	}

	// If ALL packages failed, return an error instead of a partial empty response.
	if errCount > 0 && errCount == n {
		if breakerErr != nil {
			return &pkgcheck.CheckResponse{
				Provider: p.Name(),
				Metadata: pkgcheck.ResponseMetadata{
					Duration: time.Since(start),
					Partial:  true,
					Error:    "circuit breaker open",
				},
			}, breakerErr
		}
		return nil, fmt.Errorf("snyk: all %d packages failed checks", errCount)
	}

	errMsg := ""
	if breakerErr != nil {
		errMsg = "circuit breaker open"
	}

	return &pkgcheck.CheckResponse{
		Provider: p.Name(),
		Findings: allFindings,
		Metadata: pkgcheck.ResponseMetadata{
			Duration: time.Since(start),
			Partial:  partial,
			Error:    errMsg,
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
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &snykAuthError{status: resp.StatusCode, body: string(body)}
		}
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

// snykAuthError represents an authentication failure from the Snyk API.
type snykAuthError struct {
	status int
	body   string
}

func (e *snykAuthError) Error() string {
	return fmt.Sprintf("snyk: auth error status %d: %s", e.status, e.body)
}

// isSnykAuthError checks if an error is a Snyk authentication error (401/403).
func isSnykAuthError(err error) bool {
	var authErr *snykAuthError
	return errors.As(err, &authErr)
}
