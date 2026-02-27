package provider

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalProvider_Name(t *testing.T) {
	p := NewLocalProvider()
	assert.Equal(t, "local", p.Name())
}

func TestLocalProvider_Capabilities(t *testing.T) {
	p := NewLocalProvider()
	assert.Equal(t, []pkgcheck.FindingType{pkgcheck.FindingLicense}, p.Capabilities())
}

func TestLocalProvider_Interface(t *testing.T) {
	var _ pkgcheck.CheckProvider = NewLocalProvider()
}

func TestLocalProvider_LicenseUnknown(t *testing.T) {
	p := NewLocalProvider()
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.18.0"},
			{Name: "lodash", Version: "4.17.21"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "local", resp.Provider)
	assert.Len(t, resp.Findings, 2)

	for _, f := range resp.Findings {
		assert.Equal(t, pkgcheck.FindingLicense, f.Type)
		assert.Equal(t, pkgcheck.SeverityInfo, f.Severity)
		assert.Equal(t, "License unknown", f.Title)
		require.Len(t, f.Reasons, 1)
		assert.Equal(t, "license_unknown", f.Reasons[0].Code)
	}
}

func TestLocalProvider_WithMetadata(t *testing.T) {
	p := NewLocalProvider()
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.18.0"},
			{Name: "lodash", Version: "4.17.21"},
		},
		Config: map[string]string{
			"license:express": "MIT",
		},
	})
	require.NoError(t, err)

	// express has license metadata, so only lodash should have a finding.
	assert.Len(t, resp.Findings, 1)
	assert.Equal(t, "lodash", resp.Findings[0].Package.Name)
}

func TestLocalProvider_EmptyPackages(t *testing.T) {
	p := NewLocalProvider()
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Findings)
}

func TestLocalProvider_AllHaveMetadata(t *testing.T) {
	p := NewLocalProvider()
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.18.0"},
		},
		Config: map[string]string{
			"license:express": "MIT",
		},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Findings)
}
