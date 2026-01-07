package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/auth"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

func TestApprovalsEndpointsRequireApproverRole(t *testing.T) {
	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.yaml")
	if err := os.WriteFile(keysPath, []byte(`
- id: agent
  key: sk-agent
  role: agent
- id: approver
  key: sk-approver
  role: approver
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Auth.Type = "api_key"
	cfg.Auth.APIKey.KeysFile = keysPath
	cfg.Auth.APIKey.HeaderName = "X-API-Key"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	apiKeyAuth, err := auth.LoadAPIKeys(keysPath, "X-API-Key")
	if err != nil {
		t.Fatal(err)
	}

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), apiKeyAuth, nil, nil, metrics.New(), nil)
	h := app.Router()

	// Agent key: forbidden.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req.Header.Set("X-API-Key", "sk-agent")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent key, got %d", rr.Code)
	}

	// Approver key: allowed (even if approvals mgr is nil -> 503 from handler is ok, but not 401/403).
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req2.Header.Set("X-API-Key", "sk-approver")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code == http.StatusUnauthorized || rr2.Code == http.StatusForbidden {
		t.Fatalf("expected non-401/403 for approver key, got %d", rr2.Code)
	}
}

func TestApprovalsEndpointsForbiddenWhenAuthDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Type = "none"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, nil, nil, metrics.New(), nil)
	h := app.Router()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when auth disabled, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-1", nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when auth disabled, got %d", rr2.Code)
	}
}

func TestApprovalsEndpointsForbiddenWhenDevelopmentDisableAuth(t *testing.T) {
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Auth.Type = "api_key"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, nil, nil, metrics.New(), nil)
	h := app.Router()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when development.disable_auth=true, got %d", rr.Code)
	}
}

func TestOIDCAuthModeWithValidToken(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Type = "oidc"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	// Create a mock OIDC auth with a pre-cached token
	oidcAuth := auth.NewOIDCAuthForTesting()
	oidcAuth.InjectTokenForTesting("test-token-approver", &auth.OIDCClaims{
		Subject:   "user-123",
		Groups:    []string{"approvers"},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	oidcAuth.InjectTokenForTesting("test-token-agent", &auth.OIDCClaims{
		Subject:   "user-456",
		Groups:    []string{"developers"},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	oidcAuth.InjectTokenForTesting("test-token-admin", &auth.OIDCClaims{
		Subject:   "user-789",
		Groups:    []string{"admins"},
		ExpiresAt: time.Now().Add(time.Hour),
	})

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, oidcAuth, nil, metrics.New(), nil)
	h := app.Router()

	// Agent token: forbidden for approvals endpoint
	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req.Header.Set("Authorization", "Bearer test-token-agent")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent OIDC token, got %d", rr.Code)
	}

	// Approver token: allowed for approvals endpoint
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req2.Header.Set("Authorization", "Bearer test-token-approver")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code == http.StatusUnauthorized || rr2.Code == http.StatusForbidden {
		t.Fatalf("expected non-401/403 for approver OIDC token, got %d", rr2.Code)
	}

	// Admin token: allowed for approvals endpoint
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req3.Header.Set("Authorization", "Bearer test-token-admin")
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, req3)
	if rr3.Code == http.StatusUnauthorized || rr3.Code == http.StatusForbidden {
		t.Fatalf("expected non-401/403 for admin OIDC token, got %d", rr3.Code)
	}
}

func TestOIDCAuthMissingToken(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Type = "oidc"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	oidcAuth := auth.NewOIDCAuthForTesting()

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, oidcAuth, nil, metrics.New(), nil)
	h := app.Router()

	// No Authorization header
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rr.Code)
	}
}

func TestOIDCAuthEmptyToken(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Type = "oidc"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	oidcAuth := auth.NewOIDCAuthForTesting()

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, oidcAuth, nil, metrics.New(), nil)
	h := app.Router()

	// Empty Bearer token
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for empty token, got %d", rr.Code)
	}

	// Just "Bearer" without token
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req2.Header.Set("Authorization", "Bearer")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for 'Bearer' without token, got %d", rr2.Code)
	}
}

func TestOIDCAuthInvalidToken(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Type = "oidc"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	oidcAuth := auth.NewOIDCAuthForTesting()

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, oidcAuth, nil, metrics.New(), nil)
	h := app.Router()

	// Token not in cache (invalid)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", rr.Code)
	}
}

func TestHybridAuthModeAPIKeyFirst(t *testing.T) {
	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.yaml")
	if err := os.WriteFile(keysPath, []byte(`
- id: agent
  key: sk-agent
  role: agent
- id: approver
  key: sk-approver
  role: approver
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Auth.Type = "hybrid"
	cfg.Auth.APIKey.KeysFile = keysPath
	cfg.Auth.APIKey.HeaderName = "X-API-Key"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	apiKeyAuth, err := auth.LoadAPIKeys(keysPath, "X-API-Key")
	if err != nil {
		t.Fatal(err)
	}

	oidcAuth := auth.NewOIDCAuthForTesting()
	oidcAuth.InjectTokenForTesting("test-token-admin", &auth.OIDCClaims{
		Subject:   "user-789",
		Groups:    []string{"admins"},
		ExpiresAt: time.Now().Add(time.Hour),
	})

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), apiKeyAuth, oidcAuth, nil, metrics.New(), nil)
	h := app.Router()

	// API key takes precedence in hybrid mode
	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req.Header.Set("X-API-Key", "sk-approver")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Fatalf("expected non-401/403 for approver API key in hybrid mode, got %d", rr.Code)
	}

	// Agent API key should be forbidden for approvals
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req2.Header.Set("X-API-Key", "sk-agent")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent API key in hybrid mode, got %d", rr2.Code)
	}
}

func TestHybridAuthModeOIDCFallback(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Type = "hybrid"
	cfg.Auth.APIKey.HeaderName = "X-API-Key"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	// No API keys configured, only OIDC
	oidcAuth := auth.NewOIDCAuthForTesting()
	oidcAuth.InjectTokenForTesting("test-token-approver", &auth.OIDCClaims{
		Subject:   "user-123",
		Groups:    []string{"approvers"},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	oidcAuth.InjectTokenForTesting("test-token-agent", &auth.OIDCClaims{
		Subject:   "user-456",
		Groups:    []string{"developers"},
		ExpiresAt: time.Now().Add(time.Hour),
	})

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, oidcAuth, nil, metrics.New(), nil)
	h := app.Router()

	// OIDC should work when API key not provided
	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req.Header.Set("Authorization", "Bearer test-token-approver")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Fatalf("expected non-401/403 for OIDC approver in hybrid mode, got %d", rr.Code)
	}

	// OIDC agent token should be forbidden for approvals
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	req2.Header.Set("Authorization", "Bearer test-token-agent")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for OIDC agent in hybrid mode, got %d", rr2.Code)
	}
}

func TestHybridAuthModeNeitherSucceeds(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Type = "hybrid"
	cfg.Auth.APIKey.HeaderName = "X-API-Key"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Metrics.Enabled = false

	oidcAuth := auth.NewOIDCAuthForTesting()
	// No tokens injected, so OIDC validation will fail

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, oidcAuth, nil, metrics.New(), nil)
	h := app.Router()

	// No valid credentials - should fail
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no credentials in hybrid mode, got %d", rr.Code)
	}

	// Invalid OIDC token
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req2.Header.Set("Authorization", "Bearer invalid-token")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid OIDC token in hybrid mode, got %d", rr2.Code)
	}
}
