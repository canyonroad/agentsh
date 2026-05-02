package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func TestSnykProvider_RetriesOn5xx(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
			return
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.Write([]byte(`{"data": []}`))
	}))
	defer server.Close()

	p := newSnykProviderForTest(SnykConfig{
		BaseURL: server.URL,
		APIKey:  "test-key",
		OrgID:   "org-123",
	}, circuitBreakerConfig{Threshold: 5, Window: time.Second, OpenPeriod: 200 * time.Millisecond})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Findings)
	assert.Equal(t, 3, attempts, "expected 3 server hits (2 failures + 1 success)")
}

func TestSnyk_Contract(t *testing.T) {
	cleanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer cleanSrv.Close()

	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer slowSrv.Close()

	factory := func(t *testing.T, baseURL string) pkgcheck.CheckProvider {
		return NewSnykProvider(SnykConfig{
			BaseURL:     baseURL,
			APIKey:      "test",
			OrgID:       "test",
			Timeout:     2 * time.Second,
			Concurrency: 4,
		})
	}
	runContractSuite(t, "snyk", factory, contractFixture{
		cleanServerURL: cleanSrv.URL,
		slowServerURL:  slowSrv.URL,
	})
}

func TestSnykProvider_BreakerOpensAfterRepeatedFailures(t *testing.T) {
	serverHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	p := newSnykProviderForTest(SnykConfig{
		BaseURL: server.URL,
		APIKey:  "test-key",
		OrgID:   "org-123",
	}, circuitBreakerConfig{Threshold: 2, Window: time.Second, OpenPeriod: 200 * time.Millisecond})

	req := pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	}

	// First call: retryClient exhausts all 3 attempts → server hits → RecordFailure x1 from breaker perspective.
	// With Threshold=2, after 2 CheckBatch calls the breaker opens.
	_, err1 := p.CheckBatch(context.Background(), req)
	require.Error(t, err1)

	_, err2 := p.CheckBatch(context.Background(), req)
	require.Error(t, err2)

	hitsAfterTwoCalls := serverHits

	// Third call: breaker must be open — no server hit.
	resp3, err3 := p.CheckBatch(context.Background(), req)
	require.Error(t, err3)
	assert.True(t, errors.Is(err3, errBreakerOpen), "expected errBreakerOpen, got: %v", err3)
	require.NotNil(t, resp3)
	assert.True(t, resp3.Metadata.Partial, "expected Partial=true when breaker is open")
	assert.Contains(t, resp3.Metadata.Error, "circuit breaker open")
	assert.Equal(t, hitsAfterTwoCalls, serverHits, "third call must not hit the server")
}

func TestSnykProvider_ConcurrentFanOut(t *testing.T) {
	var mu sync.Mutex
	inFlight := 0
	maxConcurrent := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlight++
		if inFlight > maxConcurrent {
			maxConcurrent = inFlight
		}
		mu.Unlock()

		// Small delay to allow concurrency to build up.
		time.Sleep(10 * time.Millisecond)

		mu.Lock()
		inFlight--
		mu.Unlock()

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.Write([]byte(`{"data": []}`))
	}))
	defer server.Close()

	packages := make([]pkgcheck.PackageRef, 32)
	for i := range packages {
		packages[i] = pkgcheck.PackageRef{Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0"}
	}

	p := newSnykProviderForTest(SnykConfig{
		BaseURL:     server.URL,
		APIKey:      "test-key",
		OrgID:       "org-123",
		Concurrency: 8,
	}, circuitBreakerConfig{})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  packages,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, maxConcurrent, 2, "expected at least 2 simultaneous in-flight requests")
}

func TestSnykProvider_AuthErrorIsFailFast(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Slow on first request so the test can observe early-cancel.
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"unauthorized"}]}`))
	}))
	defer srv.Close()

	p := NewSnykProvider(SnykConfig{
		BaseURL:     srv.URL,
		APIKey:      "bad",
		OrgID:       "org",
		Concurrency: 8,
	})

	pkgs := make([]pkgcheck.PackageRef, 64)
	for i := range pkgs {
		pkgs[i] = pkgcheck.PackageRef{Name: fmt.Sprintf("pkg-%d", i), Version: "1"}
	}
	start := time.Now()
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  pkgs,
	})
	elapsed := time.Since(start)

	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("want authentication failed error, got %v", err)
	}
	// Without fail-fast: 64 pkgs × ~3 retries each at concurrency 8 ≫ 1s.
	// With fail-fast: ~50ms (first hit) + a small drain → well under 1s.
	if elapsed > 1*time.Second {
		t.Errorf("auth error must fail fast; elapsed=%v", elapsed)
	}
	// Most workers should bail before sending a request — assert we did
	// not hit the server with all 64 packages.
	if int(hits.Load()) > 32 {
		t.Errorf("auth error must short-circuit fan-out; hits=%d (want < 32)", hits.Load())
	}
}

func TestSnykProvider_AuthErrorDoesNotPoisonBreaker(t *testing.T) {
	// All requests return 401. Configure breaker with threshold=2 — without
	// the neutral-error predicate, two concurrent auth errors would open the
	// breaker. With the fix, auth errors are neutral and the breaker stays
	// closed; subsequent calls return the auth error, not "circuit breaker open."
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"unauthorized"}]}`))
	}))
	defer srv.Close()

	p := newSnykProviderForTest(SnykConfig{
		BaseURL:     srv.URL,
		APIKey:      "bad",
		OrgID:       "org",
		Concurrency: 4,
	}, circuitBreakerConfig{
		Threshold:  2,
		Window:     time.Second,
		OpenPeriod: 200 * time.Millisecond,
	})

	// Three back-to-back batches with bad creds. Each must surface an
	// authentication error, never "circuit breaker open."
	for i := 0; i < 3; i++ {
		_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
			Ecosystem: pkgcheck.EcosystemNPM,
			Packages: []pkgcheck.PackageRef{
				{Name: "foo", Version: "1"},
				{Name: "bar", Version: "1"},
				{Name: "baz", Version: "1"},
			},
		})
		if err == nil {
			t.Fatalf("iteration %d: expected error", i)
		}
		if !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("iteration %d: want authentication error, got %v", i, err)
		}
		if errors.Is(err, errBreakerOpen) {
			t.Fatalf("iteration %d: auth error must not open breaker; got %v", i, err)
		}
	}
}

func TestSnykProvider_FindingsOrderMatchesInputOrder(t *testing.T) {
	// Different per-package response delays force concurrent workers to
	// complete in a different order than they started. The merged findings
	// must still come out in input order.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The package name is in the URL path: /rest/orgs/{org}/packages/npm%2F{name}/issues
		var sleepMs time.Duration
		if strings.Contains(r.URL.Path, "fast") {
			sleepMs = 5 * time.Millisecond
		} else {
			sleepMs = 60 * time.Millisecond
		}
		time.Sleep(sleepMs)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		// One finding per package, with the package name embedded in the title
		// so we can assert ordering at the finding level.
		_, _ = w.Write([]byte(`{"data":[{
			"id":"X",
			"type":"issue",
			"attributes":{"title":"` + r.URL.Path + `","severity":"low","type":"package_vulnerability"}
		}]}`))
	}))
	defer srv.Close()

	p := NewSnykProvider(SnykConfig{
		BaseURL:     srv.URL,
		APIKey:      "test",
		OrgID:       "org",
		Concurrency: 4,
	})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "slow-1", Version: "1"},
			{Name: "fast-1", Version: "1"},
			{Name: "slow-2", Version: "1"},
			{Name: "fast-2", Version: "1"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Findings) != 4 {
		t.Fatalf("want 4 findings, got %d", len(resp.Findings))
	}
	wantOrder := []string{"slow-1", "fast-1", "slow-2", "fast-2"}
	for i, want := range wantOrder {
		if resp.Findings[i].Package.Name != want {
			t.Errorf("findings[%d]: want package %q, got %q", i, want, resp.Findings[i].Package.Name)
		}
	}
}
