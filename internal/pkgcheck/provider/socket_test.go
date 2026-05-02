package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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
	assert.Contains(t, err.Error(), "authentication failed")
	assert.Contains(t, err.Error(), "403")
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

func TestSocketProvider_RetriesOn5xx(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"packages": [{"name": "express", "version": "4.18.0", "alerts": []}]}`))
	}))
	defer server.Close()

	p := newSocketProviderForTest(SocketConfig{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}, circuitBreakerConfig{Threshold: 5, Window: time.Second, OpenPeriod: 200 * time.Millisecond})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Findings)
	assert.Equal(t, 3, attempts, "expected 3 server hits (2 failures + 1 success)")
}

func TestSocket_Contract(t *testing.T) {
	cleanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"packages":[]}`))
	}))
	defer cleanSrv.Close()

	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"packages":[]}`))
	}))
	defer slowSrv.Close()

	factory := func(t *testing.T, baseURL string) pkgcheck.CheckProvider {
		return NewSocketProvider(SocketConfig{
			BaseURL: baseURL,
			APIKey:  "test",
			Timeout: 2 * time.Second,
		})
	}
	runContractSuite(t, "socket", factory, contractFixture{
		cleanServerURL: cleanSrv.URL,
		slowServerURL:  slowSrv.URL,
	})
}

func TestSocketProvider_BreakerOpensAfterRepeatedFailures(t *testing.T) {
	serverHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	p := newSocketProviderForTest(SocketConfig{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}, circuitBreakerConfig{Threshold: 2, Window: time.Second, OpenPeriod: 200 * time.Millisecond})

	req := pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.18.0"}},
	}

	// First call: retryClient exhausts all 3 attempts → 3 server hits → RecordFailure x1 from breaker perspective.
	// But since retryClient retries internally and only returns 1 error to callWithBreaker,
	// the breaker records 1 failure per CheckBatch call.
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
	assert.Equal(t, "circuit breaker open", resp3.Metadata.Error)
	assert.Equal(t, hitsAfterTwoCalls, serverHits, "third call must not hit the server")
}


func TestSocketProvider_MalformedResponseTripsBreaker(t *testing.T) {
	// Server always returns 200 with garbage body — every CheckBatch fails
	// with a decode error. Decode is now inside callWithBreaker, so two
	// failures should trip a threshold-2 breaker.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json {{"))
	}))
	defer srv.Close()

	p := newSocketProviderForTest(SocketConfig{
		BaseURL: srv.URL,
		APIKey:  "test",
		Timeout: 2 * time.Second,
	}, circuitBreakerConfig{
		Threshold:  2,
		Window:     time.Second,
		OpenPeriod: 200 * time.Millisecond,
	})

	for i := 0; i < 2; i++ {
		_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
			Ecosystem: pkgcheck.EcosystemNPM,
			Packages:  []pkgcheck.PackageRef{{Name: "foo", Version: "1"}},
		})
		if err == nil {
			t.Fatalf("iteration %d: expected decode error", i)
		}
	}
	// Third call must short-circuit via the breaker.
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "foo", Version: "1"}},
	})
	if err == nil || !errors.Is(err, errBreakerOpen) {
		t.Fatalf("third call should be short-circuited by breaker; got err=%v", err)
	}
	if resp == nil || !resp.Metadata.Partial || resp.Metadata.Error != "circuit breaker open" {
		t.Errorf("response should be Partial with circuit breaker open marker; got %+v", resp)
	}
}

func TestSocketProvider_RejectsTrailingGarbageOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Valid JSON followed by garbage. Strict Unmarshal must reject this.
		_, _ = w.Write([]byte(`{"packages":[]} not-json`))
	}))
	defer srv.Close()

	p := NewSocketProvider(SocketConfig{BaseURL: srv.URL, APIKey: "test", Timeout: 2 * time.Second})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "foo", Version: "1"}},
	})
	if err == nil {
		t.Fatal("expected decode error from trailing garbage; got nil")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode error, got: %v", err)
	}
}

func TestSocketProvider_AuthErrorDoesNotPoisonBreaker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()

	p := newSocketProviderForTest(SocketConfig{
		BaseURL: srv.URL,
		APIKey:  "bad",
		Timeout: 2 * time.Second,
	}, circuitBreakerConfig{
		Threshold:  2,
		Window:     time.Second,
		OpenPeriod: 200 * time.Millisecond,
	})

	for i := 0; i < 3; i++ {
		_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
			Ecosystem: pkgcheck.EcosystemNPM,
			Packages:  []pkgcheck.PackageRef{{Name: "foo", Version: "1"}},
		})
		if err == nil {
			t.Fatalf("iteration %d: expected error", i)
		}
		if !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("iteration %d: want authentication failure, got %v", i, err)
		}
		if errors.Is(err, errBreakerOpen) {
			t.Fatalf("iteration %d: auth error must not open breaker; got %v", i, err)
		}
	}
}
