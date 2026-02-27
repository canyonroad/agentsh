package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDepsDevProvider_Name(t *testing.T) {
	p := NewDepsDevProvider(DepsDevConfig{})
	assert.Equal(t, "depsdev", p.Name())
}

func TestDepsDevProvider_Capabilities(t *testing.T) {
	p := NewDepsDevProvider(DepsDevConfig{})
	caps := p.Capabilities()
	assert.Contains(t, caps, pkgcheck.FindingLicense)
	assert.Contains(t, caps, pkgcheck.FindingReputation)
}

func TestDepsDevProvider_Interface(t *testing.T) {
	var _ pkgcheck.CheckProvider = NewDepsDevProvider(DepsDevConfig{})
}

func TestDepsDevProvider_LicenseExtraction(t *testing.T) {
	fixture, err := os.ReadFile(testdataPath("depsdev_version_response.json"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Contains(t, r.URL.Path, "/v3alpha/systems/npm/packages/express/versions/4.18.0")

		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer server.Close()

	p := NewDepsDevProvider(DepsDevConfig{BaseURL: server.URL})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.18.0"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "depsdev", resp.Provider)

	// Should have a license finding with SPDX MIT.
	var licenseFinding *pkgcheck.Finding
	for i, f := range resp.Findings {
		if f.Type == pkgcheck.FindingLicense {
			licenseFinding = &resp.Findings[i]
			break
		}
	}
	require.NotNil(t, licenseFinding)
	assert.Equal(t, "License: MIT", licenseFinding.Title)
	assert.Equal(t, "MIT", licenseFinding.Metadata["spdx"])
}

func TestDepsDevProvider_LowScorecardScore(t *testing.T) {
	fixture, err := os.ReadFile(testdataPath("depsdev_low_score_response.json"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer server.Close()

	p := NewDepsDevProvider(DepsDevConfig{BaseURL: server.URL})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "sketchy-pkg", Version: "1.0.0"},
		},
	})
	require.NoError(t, err)

	// Should have low_scorecard finding (score 2.1 < threshold 4.0).
	var reputationFinding *pkgcheck.Finding
	for i, f := range resp.Findings {
		if f.Type == pkgcheck.FindingReputation && hasReasonCode(f, "low_scorecard") {
			reputationFinding = &resp.Findings[i]
			break
		}
	}
	require.NotNil(t, reputationFinding, "expected a low_scorecard reputation finding")
	assert.Equal(t, pkgcheck.SeverityMedium, reputationFinding.Severity)
	assert.Equal(t, "2.1", reputationFinding.Metadata["scorecard_score"])
}

func TestDepsDevProvider_PackageTooNew(t *testing.T) {
	// Generate a dynamic publishedAt timestamp (yesterday) so this test
	// does not depend on a hardcoded date in the fixture file.
	yesterday := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	dynamicResponse := fmt.Sprintf(`{
  "versionKey": {
    "system": "npm",
    "name": "sketchy-pkg",
    "version": "1.0.0"
  },
  "licenses": [],
  "publishedAt": %q,
  "scorecardV2": {
    "overallScore": 2.1,
    "date": "2026-02-20"
  }
}`, yesterday)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(dynamicResponse))
	}))
	defer server.Close()

	p := NewDepsDevProvider(DepsDevConfig{BaseURL: server.URL})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "sketchy-pkg", Version: "1.0.0"},
		},
	})
	require.NoError(t, err)

	// The dynamic publishedAt is yesterday — should be "too new".
	var tooNewFinding *pkgcheck.Finding
	for i, f := range resp.Findings {
		if f.Type == pkgcheck.FindingReputation && hasReasonCode(f, "package_too_new") {
			tooNewFinding = &resp.Findings[i]
			break
		}
	}
	require.NotNil(t, tooNewFinding, "expected a package_too_new reputation finding")
	assert.Equal(t, pkgcheck.SeverityLow, tooNewFinding.Severity)
}

func TestDepsDevProvider_NoLicense(t *testing.T) {
	fixture, err := os.ReadFile(testdataPath("depsdev_low_score_response.json"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer server.Close()

	p := NewDepsDevProvider(DepsDevConfig{BaseURL: server.URL})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "sketchy-pkg", Version: "1.0.0"},
		},
	})
	require.NoError(t, err)

	// The fixture has empty licenses => should get "No license detected".
	var licenseFinding *pkgcheck.Finding
	for i, f := range resp.Findings {
		if f.Type == pkgcheck.FindingLicense {
			licenseFinding = &resp.Findings[i]
			break
		}
	}
	require.NotNil(t, licenseFinding)
	assert.Equal(t, "No license detected", licenseFinding.Title)
}

func TestDepsDevProvider_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	p := NewDepsDevProvider(DepsDevConfig{BaseURL: server.URL})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.18.0"},
		},
	})
	// Per-package errors result in partial response, not a top-level error.
	require.NoError(t, err)
	assert.True(t, resp.Metadata.Partial)
	assert.Empty(t, resp.Findings)
}

func TestDepsDevProvider_PyPIEcosystem(t *testing.T) {
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"versionKey":{"system":"pypi","name":"requests","version":"2.28.0"},"licenses":["Apache-2.0"]}`))
	}))
	defer server.Close()

	p := NewDepsDevProvider(DepsDevConfig{BaseURL: server.URL})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemPyPI,
		Packages: []pkgcheck.PackageRef{
			{Name: "requests", Version: "2.28.0"},
		},
	})
	require.NoError(t, err)
	assert.Contains(t, receivedPath, "/systems/pypi/")
}

func TestDepsDevProvider_MultiplePackages(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"versionKey":{"system":"npm","name":"test","version":"1.0.0"},"licenses":["MIT"]}`))
	}))
	defer server.Close()

	p := NewDepsDevProvider(DepsDevConfig{BaseURL: server.URL})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "pkg-a", Version: "1.0.0"},
			{Name: "pkg-b", Version: "2.0.0"},
			{Name: "pkg-c", Version: "3.0.0"},
		},
	})
	require.NoError(t, err)
	// Should make one request per package.
	assert.Equal(t, int32(3), requestCount.Load())
	// Each package gets a license finding.
	assert.Len(t, resp.Findings, 3)
}

// hasReasonCode checks if a finding contains the given reason code.
func hasReasonCode(f pkgcheck.Finding, code string) bool {
	for _, r := range f.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}
