package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSocketProvider_Name(t *testing.T) {
	p := NewSocketProvider(SocketConfig{APIKey: "test"})
	assert.Equal(t, "socket", p.Name())
}

func TestSocketProvider_Capabilities(t *testing.T) {
	p := NewSocketProvider(SocketConfig{APIKey: "test"})
	caps := p.Capabilities()
	assert.Contains(t, caps, pkgcheck.FindingMalware)
	assert.Contains(t, caps, pkgcheck.FindingReputation)
}

func TestSocketProvider_Interface(t *testing.T) {
	var _ pkgcheck.CheckProvider = NewSocketProvider(SocketConfig{APIKey: "test"})
}

func TestSocketProvider_NoAPIKey(t *testing.T) {
	p := NewSocketProvider(SocketConfig{})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestSocketProvider_MalwareAndTyposquat(t *testing.T) {
	fixture, err := os.ReadFile(testdataPath("socket_response.json"))
	require.NoError(t, err)

	var receivedBody socketRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v0/scan/batch", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &receivedBody))

		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer server.Close()

	p := NewSocketProvider(SocketConfig{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "evil-pkg", Version: "1.0.0"},
			{Name: "safe-pkg", Version: "2.0.0"},
		},
	})
	require.NoError(t, err)

	// Verify request was correctly formed.
	require.Len(t, receivedBody.Packages, 2)
	assert.Equal(t, "evil-pkg", receivedBody.Packages[0].Name)
	assert.Equal(t, "npm", receivedBody.Packages[0].Ecosystem)

	// Only evil-pkg should have findings (2 alerts).
	assert.Equal(t, "socket", resp.Provider)
	require.Len(t, resp.Findings, 2)

	// First finding: malware.
	malwareFound := false
	typosquatFound := false
	for _, f := range resp.Findings {
		assert.Equal(t, "evil-pkg", f.Package.Name)
		if f.Metadata["alert_type"] == "malware" {
			malwareFound = true
			assert.Equal(t, pkgcheck.FindingMalware, f.Type)
			assert.Equal(t, pkgcheck.SeverityCritical, f.Severity)
			assert.Equal(t, "Known malware detected", f.Title)
		}
		if f.Metadata["alert_type"] == "typosquat" {
			typosquatFound = true
			assert.Equal(t, pkgcheck.FindingMalware, f.Type)
			assert.Equal(t, pkgcheck.SeverityHigh, f.Severity)
		}
	}
	assert.True(t, malwareFound, "expected a malware finding")
	assert.True(t, typosquatFound, "expected a typosquat finding")
}

func TestSocketProvider_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	p := NewSocketProvider(SocketConfig{
		BaseURL: server.URL,
		APIKey:  "bad-key",
	})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status 403")
}

func TestSocketProvider_NoAlerts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"packages": [{"name": "express", "version": "4.18.0", "alerts": []}]}`))
	}))
	defer server.Close()

	p := NewSocketProvider(SocketConfig{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Findings)
}
