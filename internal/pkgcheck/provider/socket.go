package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

const (
	defaultSocketBaseURL = "https://api.socket.dev"
	defaultSocketTimeout = 30 * time.Second
)

// SocketConfig configures the Socket.dev supply-chain provider.
type SocketConfig struct {
	BaseURL string
	Timeout time.Duration
	APIKey  string
}

// socketProvider queries the Socket.dev API for supply-chain security findings.
type socketProvider struct {
	baseURL string
	client  *http.Client
	apiKey  string
}

// NewSocketProvider returns a CheckProvider that queries Socket.dev for malware
// and reputation findings.
func NewSocketProvider(cfg SocketConfig) pkgcheck.CheckProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultSocketBaseURL
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultSocketTimeout
	}
	return &socketProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
		apiKey:  cfg.APIKey,
	}
}

func (p *socketProvider) Name() string {
	return "socket"
}

func (p *socketProvider) Capabilities() []pkgcheck.FindingType {
	return []pkgcheck.FindingType{pkgcheck.FindingMalware, pkgcheck.FindingReputation}
}

// socketRequest is the request body for the Socket.dev scan API.
type socketRequest struct {
	Packages []socketPackage `json:"packages"`
}

type socketPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// socketResponse is the top-level response from Socket.dev.
type socketResponse struct {
	Packages []socketPackageResult `json:"packages"`
}

type socketPackageResult struct {
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Alerts  []socketAlert  `json:"alerts,omitempty"`
	Score   *socketScore   `json:"score,omitempty"`
}

type socketAlert struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Key      string `json:"key,omitempty"`
}

type socketScore struct {
	Overall      float64 `json:"overall"`
	Supply       float64 `json:"supply"`
	Quality      float64 `json:"quality"`
	Maintenance  float64 `json:"maintenance"`
	Vulnerability float64 `json:"vulnerability"`
	License      float64 `json:"license"`
}

func (p *socketProvider) CheckBatch(ctx context.Context, req pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("socket: API key is required")
	}

	start := time.Now()
	ecosystem := mapEcosystemSocket(req.Ecosystem)

	packages := make([]socketPackage, len(req.Packages))
	for i, pkg := range req.Packages {
		packages[i] = socketPackage{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: ecosystem,
		}
	}

	body, err := json.Marshal(socketRequest{Packages: packages})
	if err != nil {
		return nil, fmt.Errorf("socket: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v0/scan/batch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("socket: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("socket: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("socket: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var socketResp socketResponse
	if err := json.NewDecoder(resp.Body).Decode(&socketResp); err != nil {
		return nil, fmt.Errorf("socket: decode response: %w", err)
	}

	findings := p.mapFindings(req.Packages, &socketResp)

	return &pkgcheck.CheckResponse{
		Provider: p.Name(),
		Findings: findings,
		Metadata: pkgcheck.ResponseMetadata{
			Duration: time.Since(start),
		},
	}, nil
}

func (p *socketProvider) mapFindings(packages []pkgcheck.PackageRef, resp *socketResponse) []pkgcheck.Finding {
	var findings []pkgcheck.Finding

	// Build lookup from name@version -> PackageRef.
	pkgMap := make(map[string]pkgcheck.PackageRef, len(packages))
	for _, pkg := range packages {
		pkgMap[pkg.Name+"@"+pkg.Version] = pkg
	}

	for _, result := range resp.Packages {
		pkg, ok := pkgMap[result.Name+"@"+result.Version]
		if !ok {
			continue
		}

		for _, alert := range result.Alerts {
			findingType, severity := mapSocketAlert(alert)
			findings = append(findings, pkgcheck.Finding{
				Type:     findingType,
				Provider: p.Name(),
				Package:  pkg,
				Severity: severity,
				Title:    alert.Title,
				Detail:   alert.Detail,
				Reasons: []pkgcheck.Reason{
					{Code: alert.Type, Message: alert.Title},
				},
				Metadata: map[string]string{
					"alert_type": alert.Type,
				},
			})
		}
	}

	return findings
}

// mapSocketAlert maps a Socket.dev alert to our finding type and severity.
func mapSocketAlert(alert socketAlert) (pkgcheck.FindingType, pkgcheck.Severity) {
	// Map alert type to finding type.
	findingType := pkgcheck.FindingReputation
	switch alert.Type {
	case "malware", "malicious_code":
		findingType = pkgcheck.FindingMalware
	case "typosquat", "typo_squatting":
		findingType = pkgcheck.FindingMalware
	case "install_script", "network_access", "shell_access", "filesystem_access":
		findingType = pkgcheck.FindingReputation
	}

	// Map severity.
	severity := pkgcheck.SeverityMedium
	switch strings.ToLower(alert.Severity) {
	case "critical":
		severity = pkgcheck.SeverityCritical
	case "high":
		severity = pkgcheck.SeverityHigh
	case "medium":
		severity = pkgcheck.SeverityMedium
	case "low":
		severity = pkgcheck.SeverityLow
	}

	return findingType, severity
}

// mapEcosystemSocket converts our Ecosystem type to the Socket ecosystem string.
func mapEcosystemSocket(eco pkgcheck.Ecosystem) string {
	switch eco {
	case pkgcheck.EcosystemNPM:
		return "npm"
	case pkgcheck.EcosystemPyPI:
		return "pypi"
	default:
		return string(eco)
	}
}
