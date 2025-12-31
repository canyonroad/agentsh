package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

func TestRouter_MetricsEnabledServesPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = "/metrics"
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"

	sessions := session.NewManager(10)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, composite.New(nil, nil), engine, events.NewBroker(), nil, nil, metrics.New(), nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "agentsh_") {
		t.Fatalf("expected metrics body, got %q", rr.Body.String())
	}
}
