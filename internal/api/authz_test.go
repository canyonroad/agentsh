package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), apiKeyAuth, nil, metrics.New(), nil)
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
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, nil, metrics.New(), nil)
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
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, nil, metrics.New(), nil)
	h := app.Router()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when development.disable_auth=true, got %d", rr.Code)
	}
}
