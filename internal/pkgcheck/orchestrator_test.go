package pkgcheck

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// slowMockProvider is a test provider with configurable delay that respects ctx.Done().
type slowMockProvider struct {
	name     string
	delay    time.Duration
	findings []Finding
}

func (s *slowMockProvider) Name() string                { return s.name }
func (s *slowMockProvider) Capabilities() []FindingType { return nil }
func (s *slowMockProvider) CheckBatch(ctx context.Context, _ CheckRequest) (*CheckResponse, error) {
	select {
	case <-time.After(s.delay):
		return &CheckResponse{
			Provider: s.name,
			Findings: s.findings,
			Metadata: ResponseMetadata{Duration: s.delay},
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestOrchestratorParallelExecution(t *testing.T) {
	p1 := &mockProvider{
		name:         "provider-a",
		capabilities: []FindingType{FindingVulnerability},
		findings: []Finding{
			{
				Type:     FindingVulnerability,
				Provider: "provider-a",
				Package:  PackageRef{Name: "lodash", Version: "4.17.20"},
				Severity: SeverityHigh,
				Title:    "Prototype Pollution",
			},
		},
	}
	p2 := &mockProvider{
		name:         "provider-b",
		capabilities: []FindingType{FindingLicense},
		findings: []Finding{
			{
				Type:     FindingLicense,
				Provider: "provider-b",
				Package:  PackageRef{Name: "lodash", Version: "4.17.20"},
				Severity: SeverityMedium,
				Title:    "Non-permissive license",
			},
		},
	}

	orch := NewOrchestrator(OrchestratorConfig{
		Providers: map[string]ProviderEntry{
			"provider-a": {Provider: p1, Timeout: 5 * time.Second, OnFailure: "warn"},
			"provider-b": {Provider: p2, Timeout: 5 * time.Second, OnFailure: "warn"},
		},
	})

	findings, errs := orch.CheckAll(context.Background(), CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages:  []PackageRef{{Name: "lodash", Version: "4.17.20"}},
	})

	assert.Empty(t, errs)
	require.Len(t, findings, 2)

	// Sort findings by provider for deterministic assertion
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Provider < findings[j].Provider
	})

	assert.Equal(t, "provider-a", findings[0].Provider)
	assert.Equal(t, FindingVulnerability, findings[0].Type)
	assert.Equal(t, "provider-b", findings[1].Provider)
	assert.Equal(t, FindingLicense, findings[1].Type)
}

func TestOrchestratorProviderFailure(t *testing.T) {
	good := &mockProvider{
		name:         "good-provider",
		capabilities: []FindingType{FindingVulnerability},
		findings: []Finding{
			{
				Type:     FindingVulnerability,
				Provider: "good-provider",
				Package:  PackageRef{Name: "express", Version: "4.18.0"},
				Severity: SeverityCritical,
				Title:    "RCE in express",
			},
		},
	}
	bad := &mockProvider{
		name: "bad-provider",
		err:  errors.New("connection refused"),
	}

	orch := NewOrchestrator(OrchestratorConfig{
		Providers: map[string]ProviderEntry{
			"good-provider": {Provider: good, Timeout: 5 * time.Second, OnFailure: "warn"},
			"bad-provider":  {Provider: bad, Timeout: 5 * time.Second, OnFailure: "deny"},
		},
	})

	findings, errs := orch.CheckAll(context.Background(), CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages:  []PackageRef{{Name: "express", Version: "4.18.0"}},
	})

	require.Len(t, findings, 1)
	assert.Equal(t, "good-provider", findings[0].Provider)
	assert.Equal(t, SeverityCritical, findings[0].Severity)

	require.Len(t, errs, 1)
	assert.Equal(t, "bad-provider", errs[0].Provider)
	assert.Equal(t, "deny", errs[0].OnFailure)
	assert.Contains(t, errs[0].Error(), "connection refused")
}

func TestOrchestratorTimeout(t *testing.T) {
	fast := &mockProvider{
		name:         "fast-provider",
		capabilities: []FindingType{FindingVulnerability},
		findings: []Finding{
			{
				Type:     FindingVulnerability,
				Provider: "fast-provider",
				Package:  PackageRef{Name: "pkg"},
				Severity: SeverityLow,
				Title:    "Low vuln",
			},
		},
	}
	slow := &slowMockProvider{
		name:  "slow-provider",
		delay: 5 * time.Second,
		findings: []Finding{
			{
				Type:     FindingMalware,
				Provider: "slow-provider",
				Package:  PackageRef{Name: "pkg"},
				Severity: SeverityCritical,
				Title:    "Malware detected",
			},
		},
	}

	orch := NewOrchestrator(OrchestratorConfig{
		Providers: map[string]ProviderEntry{
			"fast-provider": {Provider: fast, Timeout: 5 * time.Second, OnFailure: "warn"},
			"slow-provider": {Provider: slow, Timeout: 50 * time.Millisecond, OnFailure: "warn"},
		},
	})

	start := time.Now()
	findings, errs := orch.CheckAll(context.Background(), CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages:  []PackageRef{{Name: "pkg"}},
	})
	elapsed := time.Since(start)

	// Should complete quickly, not wait for the slow provider's full delay
	assert.Less(t, elapsed, 2*time.Second)

	require.Len(t, findings, 1)
	assert.Equal(t, "fast-provider", findings[0].Provider)

	require.Len(t, errs, 1)
	assert.Equal(t, "slow-provider", errs[0].Provider)
	assert.ErrorIs(t, errs[0].Err, context.DeadlineExceeded)
}

func TestOrchestratorEmpty(t *testing.T) {
	orch := NewOrchestrator(OrchestratorConfig{
		Providers: map[string]ProviderEntry{},
	})

	findings, errs := orch.CheckAll(context.Background(), CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages:  []PackageRef{{Name: "anything"}},
	})

	assert.Nil(t, findings)
	assert.Nil(t, errs)
}
