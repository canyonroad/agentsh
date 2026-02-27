package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

const (
	defaultOSVBaseURL = "https://api.osv.dev"
	defaultOSVTimeout = 30 * time.Second
)

// OSVConfig configures the OSV.dev vulnerability provider.
type OSVConfig struct {
	BaseURL string
	Timeout time.Duration
}

// osvProvider queries the OSV.dev batch API for known vulnerabilities.
type osvProvider struct {
	baseURL string
	client  *http.Client
}

// NewOSVProvider returns a CheckProvider that queries OSV.dev for vulnerabilities.
func NewOSVProvider(cfg OSVConfig) pkgcheck.CheckProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultOSVBaseURL
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultOSVTimeout
	}
	return &osvProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (p *osvProvider) Name() string {
	return "osv"
}

func (p *osvProvider) Capabilities() []pkgcheck.FindingType {
	return []pkgcheck.FindingType{pkgcheck.FindingVulnerability}
}

// osvBatchRequest is the top-level request to POST /v1/querybatch.
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvBatchResponse is the top-level response from /v1/querybatch.
type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns,omitempty"`
}

type osvVuln struct {
	ID         string          `json:"id"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details"`
	Severity   []osvSeverity   `json:"severity,omitempty"`
	References []osvReference  `json:"references,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func (p *osvProvider) CheckBatch(ctx context.Context, req pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
	start := time.Now()

	ecosystem := mapEcosystemOSV(req.Ecosystem)
	queries := make([]osvQuery, len(req.Packages))
	for i, pkg := range req.Packages {
		queries[i] = osvQuery{
			Package: osvPackage{
				Name:      pkg.Name,
				Ecosystem: ecosystem,
			},
			Version: pkg.Version,
		}
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("osv: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("osv: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("osv: decode response: %w", err)
	}

	// Validate that the response has the expected number of results.
	// If OSV returns fewer results than requested, mark as partial and
	// only iterate the results we received.
	partial := false
	resultCount := len(batchResp.Results)
	if resultCount != len(req.Packages) {
		partial = true
	}
	iterCount := resultCount
	if iterCount > len(req.Packages) {
		iterCount = len(req.Packages)
	}

	var findings []pkgcheck.Finding
	for i := 0; i < iterCount; i++ {
		result := batchResp.Results[i]
		pkg := req.Packages[i]
		for _, vuln := range result.Vulns {
			severity := mapOSVSeverity(vuln.Severity)
			var links []string
			for _, ref := range vuln.References {
				links = append(links, ref.URL)
			}
			findings = append(findings, pkgcheck.Finding{
				Type:     pkgcheck.FindingVulnerability,
				Provider: p.Name(),
				Package:  pkg,
				Severity: severity,
				Title:    vuln.Summary,
				Detail:   vuln.Details,
				Reasons: []pkgcheck.Reason{
					{Code: "known_vulnerability", Message: vuln.ID},
				},
				Links: links,
				Metadata: map[string]string{
					"vuln_id": vuln.ID,
				},
			})
		}
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

// mapEcosystemOSV converts our Ecosystem type to the OSV ecosystem string.
func mapEcosystemOSV(eco pkgcheck.Ecosystem) string {
	switch eco {
	case pkgcheck.EcosystemNPM:
		return "npm"
	case pkgcheck.EcosystemPyPI:
		return "PyPI"
	default:
		return string(eco)
	}
}

// mapOSVSeverity extracts a CVSS v3 base score and maps it to our Severity type.
func mapOSVSeverity(severities []osvSeverity) pkgcheck.Severity {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			score := parseCVSSBaseScore(s.Score)
			if score >= 9.0 {
				return pkgcheck.SeverityCritical
			}
			if score >= 7.0 {
				return pkgcheck.SeverityHigh
			}
			if score >= 4.0 {
				return pkgcheck.SeverityMedium
			}
			return pkgcheck.SeverityLow
		}
	}
	// No CVSS v3 severity info — default to medium.
	return pkgcheck.SeverityMedium
}

// parseCVSSBaseScore attempts to extract the base score from a CVSS v3 vector
// string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") or a
// plain numeric score string (e.g., "9.8").
func parseCVSSBaseScore(s string) float64 {
	// Try parsing as a plain numeric score first.
	if score, err := strconv.ParseFloat(s, 64); err == nil {
		return score
	}

	// Parse CVSS vector string — calculate base score from metrics.
	if strings.HasPrefix(s, "CVSS:3") {
		return calculateCVSS3BaseScore(s)
	}

	return 0
}

// calculateCVSS3BaseScore computes a simplified CVSS v3.x base score from
// the vector string. This implements the standard CVSS v3.1 equations.
func calculateCVSS3BaseScore(vector string) float64 {
	metrics := parseCVSSMetrics(vector)

	av := cvssMetricValue(metrics["AV"], map[string]float64{
		"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20,
	})
	ac := cvssMetricValue(metrics["AC"], map[string]float64{
		"L": 0.77, "H": 0.44,
	})
	pr := cvssMetricValue(metrics["PR"], map[string]float64{
		"N": 0.85, "L": 0.62, "H": 0.27,
	})
	// Adjust PR for scope change.
	if metrics["S"] == "C" {
		pr = cvssMetricValue(metrics["PR"], map[string]float64{
			"N": 0.85, "L": 0.68, "H": 0.50,
		})
	}
	ui := cvssMetricValue(metrics["UI"], map[string]float64{
		"N": 0.85, "R": 0.62,
	})

	conf := cvssMetricValue(metrics["C"], map[string]float64{
		"H": 0.56, "L": 0.22, "N": 0.0,
	})
	integ := cvssMetricValue(metrics["I"], map[string]float64{
		"H": 0.56, "L": 0.22, "N": 0.0,
	})
	avail := cvssMetricValue(metrics["A"], map[string]float64{
		"H": 0.56, "L": 0.22, "N": 0.0,
	})

	// ISS = 1 - [(1 - Confidentiality) * (1 - Integrity) * (1 - Availability)]
	iss := 1 - ((1 - conf) * (1 - integ) * (1 - avail))

	if iss <= 0 {
		return 0
	}

	var impact float64
	scopeChanged := metrics["S"] == "C"
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var score float64
	if scopeChanged {
		score = roundUp(min(1.08*(impact+exploitability), 10))
	} else {
		score = roundUp(min(impact+exploitability, 10))
	}

	return score
}

// parseCVSSMetrics extracts metric key/value pairs from a CVSS vector string.
func parseCVSSMetrics(vector string) map[string]string {
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		if kv := strings.SplitN(part, ":", 2); len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}
	return metrics
}

// cvssMetricValue looks up a metric abbreviation in the value map, returning 0 if not found.
func cvssMetricValue(abbrev string, values map[string]float64) float64 {
	if v, ok := values[abbrev]; ok {
		return v
	}
	return 0
}

// pow computes base^exp using repeated multiplication (for small integer exponents).
func pow(base float64, exp int) float64 {
	result := 1.0
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}

// roundUp rounds a float64 up to the nearest tenth (CVSS standard rounding).
func roundUp(val float64) float64 {
	v := int(val * 100000)
	if v%10000 == 0 {
		return float64(v) / 100000.0
	}
	return float64(v/10000+1) / 10.0
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
