package pkgcheck

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider is a test implementation of CheckProvider.
type mockProvider struct {
	name         string
	capabilities []FindingType
	findings     []Finding
	err          error
}

func (m *mockProvider) Name() string                { return m.name }
func (m *mockProvider) Capabilities() []FindingType { return m.capabilities }
func (m *mockProvider) CheckBatch(_ context.Context, _ CheckRequest) (*CheckResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &CheckResponse{
		Provider: m.name,
		Findings: m.findings,
		Metadata: ResponseMetadata{
			Duration: 50 * time.Millisecond,
		},
	}, nil
}

// mockResolver is a test implementation of Resolver.
type mockResolver struct {
	name       string
	canResolve bool
	plan       *InstallPlan
	err        error
}

func (m *mockResolver) Name() string                          { return m.name }
func (m *mockResolver) CanResolve(_ string, _ []string) bool  { return m.canResolve }
func (m *mockResolver) Resolve(_ context.Context, _ string, _ []string) (*InstallPlan, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.plan, nil
}

func TestCheckProvider_Interface(t *testing.T) {
	p := &mockProvider{
		name:         "test-provider",
		capabilities: []FindingType{FindingVulnerability, FindingMalware},
		findings: []Finding{
			{
				Type:     FindingVulnerability,
				Provider: "test-provider",
				Package:  PackageRef{Name: "lodash", Version: "4.17.20"},
				Severity: SeverityHigh,
				Title:    "Prototype Pollution",
			},
		},
	}

	// Verify the interface is satisfied
	var _ CheckProvider = p

	assert.Equal(t, "test-provider", p.Name())
	assert.Equal(t, []FindingType{FindingVulnerability, FindingMalware}, p.Capabilities())

	resp, err := p.CheckBatch(context.Background(), CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages:  []PackageRef{{Name: "lodash", Version: "4.17.20"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "test-provider", resp.Provider)
	assert.Len(t, resp.Findings, 1)
	assert.Equal(t, SeverityHigh, resp.Findings[0].Severity)
}

func TestCheckProvider_Error(t *testing.T) {
	p := &mockProvider{
		name: "error-provider",
		err:  assert.AnError,
	}

	resp, err := p.CheckBatch(context.Background(), CheckRequest{})
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestResolver_Interface(t *testing.T) {
	r := &mockResolver{
		name:       "npm-resolver",
		canResolve: true,
		plan: &InstallPlan{
			Tool:      "npm",
			Ecosystem: EcosystemNPM,
			Direct: []PackageRef{
				{Name: "express", Version: "4.18.0", Direct: true},
			},
		},
	}

	// Verify the interface is satisfied
	var _ Resolver = r

	assert.Equal(t, "npm-resolver", r.Name())
	assert.True(t, r.CanResolve("npm", []string{"install", "express"}))

	plan, err := r.Resolve(context.Background(), "/tmp", []string{"npm", "install", "express"})
	require.NoError(t, err)
	assert.Equal(t, EcosystemNPM, plan.Ecosystem)
	assert.Len(t, plan.Direct, 1)
}

func TestResolver_CannotResolve(t *testing.T) {
	r := &mockResolver{
		name:       "npm-resolver",
		canResolve: false,
	}

	assert.False(t, r.CanResolve("pip", []string{"install", "requests"}))
}

func TestResolver_Error(t *testing.T) {
	r := &mockResolver{
		name:       "failing-resolver",
		canResolve: true,
		err:        assert.AnError,
	}

	plan, err := r.Resolve(context.Background(), "/tmp", []string{"npm", "install"})
	assert.Error(t, err)
	assert.Nil(t, plan)
}

func TestResponseMetadata_Fields(t *testing.T) {
	m := ResponseMetadata{
		Duration:    100 * time.Millisecond,
		FromCache:   true,
		RateLimited: false,
		Partial:     false,
		Error:       "",
	}

	assert.Equal(t, 100*time.Millisecond, m.Duration)
	assert.True(t, m.FromCache)
	assert.False(t, m.RateLimited)
}
