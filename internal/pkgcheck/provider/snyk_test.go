package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnykProvider_Name(t *testing.T) {
	p := NewSnykProvider(SnykConfig{APIKey: "test", OrgID: "org-1"})
	assert.Equal(t, "snyk", p.Name())
}

func TestSnykProvider_Capabilities(t *testing.T) {
	p := NewSnykProvider(SnykConfig{APIKey: "test", OrgID: "org-1"})
	caps := p.Capabilities()
	assert.Contains(t, caps, pkgcheck.FindingVulnerability)
	assert.Contains(t, caps, pkgcheck.FindingLicense)
}

func TestSnykProvider_Interface(t *testing.T) {
	var _ pkgcheck.CheckProvider = NewSnykProvider(SnykConfig{APIKey: "test", OrgID: "org-1"})
}

func TestSnykProvider_NoAPIKey(t *testing.T) {
	p := NewSnykProvider(SnykConfig{OrgID: "org-1"})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestSnykProvider_NoOrgID(t *testing.T) {
	p := NewSnykProvider(SnykConfig{APIKey: "test"})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "org ID is required")
}

func TestSnykProvider_VulnAndLicenseFindings(t *testing.T) {
	fixture, err := os.ReadFile(testdataPath("snyk_issues_response.json"))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		// The %2F in the URL is decoded by the HTTP server to /, so we check
		// that the path contains the expected components.
		assert.Contains(t, r.URL.Path, "/rest/orgs/org-123/packages/npm")
		assert.Contains(t, r.URL.Path, "express/issues")
		assert.Equal(t, "4.17.1", r.URL.Query().Get("version"))
		assert.Equal(t, "token test-key", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.Write(fixture)
	}))
	defer server.Close()

	p := NewSnykProvider(SnykConfig{
		BaseURL: server.URL,
		APIKey:  "test-key",
		OrgID:   "org-123",
	})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.17.1"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "snyk", resp.Provider)
	require.Len(t, resp.Findings, 2)

	// Find the vulnerability finding.
	var vulnFinding, licenseFinding *pkgcheck.Finding
	for i, f := range resp.Findings {
		switch f.Type {
		case pkgcheck.FindingVulnerability:
			vulnFinding = &resp.Findings[i]
		case pkgcheck.FindingLicense:
			licenseFinding = &resp.Findings[i]
		}
	}

	require.NotNil(t, vulnFinding)
	assert.Equal(t, "Denial of Service (DoS)", vulnFinding.Title)
	assert.Equal(t, pkgcheck.SeverityHigh, vulnFinding.Severity) // CVSS 7.5 => high
	assert.Equal(t, "SNYK-JS-EXPRESS-1234567", vulnFinding.Metadata["snyk_id"])
	require.Len(t, vulnFinding.Links, 1)
	assert.Contains(t, vulnFinding.Links[0], "security.snyk.io")

	require.NotNil(t, licenseFinding)
	assert.Equal(t, "Non-OSI approved license", licenseFinding.Title)
	assert.Equal(t, pkgcheck.SeverityMedium, licenseFinding.Severity)
	assert.Equal(t, "SSPL-1.0", licenseFinding.Metadata["license"])
	assert.Equal(t, "license_issue", licenseFinding.Reasons[0].Code)
}

func TestSnykProvider_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	p := NewSnykProvider(SnykConfig{
		BaseURL: server.URL,
		APIKey:  "bad-key",
		OrgID:   "org-123",
	})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	})
	// Auth errors (401/403) now return immediately with an error.
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestSnykProvider_NoIssues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.Write([]byte(`{"data": []}`))
	}))
	defer server.Close()

	p := NewSnykProvider(SnykConfig{
		BaseURL: server.URL,
		APIKey:  "test-key",
		OrgID:   "org-123",
	})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Findings)
}

func TestSnykProvider_MultiplePackages(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.Write([]byte(`{"data": []}`))
	}))
	defer server.Close()

	p := NewSnykProvider(SnykConfig{
		BaseURL: server.URL,
		APIKey:  "test-key",
		OrgID:   "org-123",
	})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "pkg-a", Version: "1.0.0"},
			{Name: "pkg-b", Version: "2.0.0"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, requestCount) // One request per package.
}
