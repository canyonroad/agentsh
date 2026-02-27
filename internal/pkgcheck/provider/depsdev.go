package provider

import (
	"context"
	"encoding/json"
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
	defaultDepsDevBaseURL = "https://api.deps.dev"
	defaultDepsDevTimeout = 30 * time.Second
	defaultScorecardThreshold = 4.0
)

// DepsDevConfig configures the deps.dev provider.
type DepsDevConfig struct {
	BaseURL           string
	Timeout           time.Duration
	ScorecardThreshold float64 // minimum acceptable OpenSSF Scorecard score (default 4.0)
}

// depsDevProvider queries the deps.dev API for license and reputation data.
type depsDevProvider struct {
	baseURL            string
	client             *http.Client
	scorecardThreshold float64
}

// NewDepsDevProvider returns a CheckProvider that queries deps.dev for license
// and OpenSSF Scorecard information.
func NewDepsDevProvider(cfg DepsDevConfig) pkgcheck.CheckProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultDepsDevBaseURL
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultDepsDevTimeout
	}
	threshold := cfg.ScorecardThreshold
	if threshold == 0 {
		threshold = defaultScorecardThreshold
	}
	return &depsDevProvider{
		baseURL:            strings.TrimRight(baseURL, "/"),
		client:             &http.Client{Timeout: timeout},
		scorecardThreshold: threshold,
	}
}

func (p *depsDevProvider) Name() string {
	return "depsdev"
}

func (p *depsDevProvider) Capabilities() []pkgcheck.FindingType {
	return []pkgcheck.FindingType{pkgcheck.FindingLicense, pkgcheck.FindingReputation}
}

// depsDevVersionResponse represents the relevant fields from the deps.dev version API.
type depsDevVersionResponse struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	Licenses      []string `json:"licenses"`
	PublishedAt   string   `json:"publishedAt,omitempty"`
	ScorecardV2   *depsDevScorecard `json:"scorecardV2,omitempty"`
}

type depsDevScorecard struct {
	OverallScore float64 `json:"overallScore"`
	Date         string  `json:"date,omitempty"`
}

type depsDevResult struct {
	pkg      pkgcheck.PackageRef
	response *depsDevVersionResponse
	err      error
}

func (p *depsDevProvider) CheckBatch(ctx context.Context, req pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
	start := time.Now()
	ecosystem := mapEcosystemDepsDev(req.Ecosystem)

	// Query deps.dev for each package concurrently.
	results := make([]depsDevResult, len(req.Packages))
	var wg sync.WaitGroup
	for i, pkg := range req.Packages {
		wg.Add(1)
		go func(idx int, pkg pkgcheck.PackageRef) {
			defer wg.Done()
			resp, err := p.fetchVersion(ctx, ecosystem, pkg.Name, pkg.Version)
			results[idx] = depsDevResult{pkg: pkg, response: resp, err: err}
		}(i, pkg)
	}
	wg.Wait()

	var findings []pkgcheck.Finding
	var partial bool
	for _, result := range results {
		if result.err != nil {
			partial = true
			continue
		}
		findings = append(findings, p.extractFindings(result.pkg, result.response)...)
	}

	return &pkgcheck.CheckResponse{
		Provider: p.Name(),
		Findings: findings,
		Metadata: pkgcheck.ResponseMetadata{
			Duration: time.Since(start),
			Partial:  partial,
		},
	}, nil
}

func (p *depsDevProvider) fetchVersion(ctx context.Context, ecosystem, name, version string) (*depsDevVersionResponse, error) {
	reqURL := fmt.Sprintf("%s/v3alpha/systems/%s/packages/%s/versions/%s",
		p.baseURL,
		url.PathEscape(ecosystem),
		url.PathEscape(name),
		url.PathEscape(version),
	)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("depsdev: create request: %w", err)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("depsdev: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("depsdev: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var versionResp depsDevVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&versionResp); err != nil {
		return nil, fmt.Errorf("depsdev: decode response: %w", err)
	}

	return &versionResp, nil
}

func (p *depsDevProvider) extractFindings(pkg pkgcheck.PackageRef, resp *depsDevVersionResponse) []pkgcheck.Finding {
	var findings []pkgcheck.Finding

	// License findings.
	if len(resp.Licenses) == 0 {
		findings = append(findings, pkgcheck.Finding{
			Type:     pkgcheck.FindingLicense,
			Provider: p.Name(),
			Package:  pkg,
			Severity: pkgcheck.SeverityInfo,
			Title:    "No license detected",
			Reasons: []pkgcheck.Reason{
				{Code: "license_unknown", Message: "deps.dev reports no license for this version"},
			},
		})
	} else {
		spdx := strings.Join(resp.Licenses, " AND ")
		findings = append(findings, pkgcheck.Finding{
			Type:     pkgcheck.FindingLicense,
			Provider: p.Name(),
			Package:  pkg,
			Severity: pkgcheck.SeverityInfo,
			Title:    "License: " + spdx,
			Metadata: map[string]string{
				"spdx": spdx,
			},
		})
	}

	// Scorecard reputation findings.
	if resp.ScorecardV2 != nil {
		score := resp.ScorecardV2.OverallScore
		if score < p.scorecardThreshold {
			findings = append(findings, pkgcheck.Finding{
				Type:     pkgcheck.FindingReputation,
				Provider: p.Name(),
				Package:  pkg,
				Severity: pkgcheck.SeverityMedium,
				Title:    fmt.Sprintf("Low OpenSSF Scorecard score: %.1f", score),
				Reasons: []pkgcheck.Reason{
					{Code: "low_scorecard", Message: fmt.Sprintf("Score %.1f is below threshold %.1f", score, p.scorecardThreshold)},
				},
				Metadata: map[string]string{
					"scorecard_score": fmt.Sprintf("%.1f", score),
				},
			})
		}
	}

	// Check for very recent publish date (package_too_new).
	if resp.PublishedAt != "" {
		publishedAt, err := time.Parse(time.RFC3339, resp.PublishedAt)
		if err == nil {
			if time.Since(publishedAt) < 7*24*time.Hour {
				findings = append(findings, pkgcheck.Finding{
					Type:     pkgcheck.FindingReputation,
					Provider: p.Name(),
					Package:  pkg,
					Severity: pkgcheck.SeverityLow,
					Title:    "Package version published recently",
					Detail:   fmt.Sprintf("Published at %s", resp.PublishedAt),
					Reasons: []pkgcheck.Reason{
						{Code: "package_too_new", Message: "Version was published less than 7 days ago"},
					},
					Metadata: map[string]string{
						"published_at": resp.PublishedAt,
					},
				})
			}
		}
	}

	return findings
}

// mapEcosystemDepsDev converts our Ecosystem type to the deps.dev system string.
func mapEcosystemDepsDev(eco pkgcheck.Ecosystem) string {
	switch eco {
	case pkgcheck.EcosystemNPM:
		return "npm"
	case pkgcheck.EcosystemPyPI:
		return "pypi"
	default:
		return string(eco)
	}
}
