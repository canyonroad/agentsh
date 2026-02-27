package provider

import (
	"context"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// localProvider checks package metadata locally without any network calls.
type localProvider struct{}

// NewLocalProvider returns a CheckProvider that inspects local package metadata.
// It never makes network calls and always succeeds.
func NewLocalProvider() pkgcheck.CheckProvider {
	return &localProvider{}
}

func (p *localProvider) Name() string {
	return "local"
}

func (p *localProvider) Capabilities() []pkgcheck.FindingType {
	return []pkgcheck.FindingType{pkgcheck.FindingLicense}
}

func (p *localProvider) CheckBatch(_ context.Context, req pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
	start := time.Now()
	var findings []pkgcheck.Finding

	for _, pkg := range req.Packages {
		// Check if license metadata is available in the config (which acts as
		// a metadata cache when populated by the caller).
		if license, ok := req.Config["license:"+pkg.Name]; ok && license != "" {
			continue
		}

		// No license metadata available — report as unknown.
		findings = append(findings, pkgcheck.Finding{
			Type:     pkgcheck.FindingLicense,
			Provider: p.Name(),
			Package:  pkg,
			Severity: pkgcheck.SeverityInfo,
			Title:    "License unknown",
			Detail:   "No license metadata available for " + pkg.String(),
			Reasons: []pkgcheck.Reason{
				{Code: "license_unknown", Message: "Could not determine license from local metadata"},
			},
		})
	}

	return &pkgcheck.CheckResponse{
		Provider: p.Name(),
		Findings: findings,
		Metadata: pkgcheck.ResponseMetadata{
			Duration: time.Since(start),
		},
	}, nil
}
