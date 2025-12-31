package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

func TestListProfiles_Empty(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	// Create config with no mount profiles
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, metrics.New(), nil)
	h := app.Router()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ProfilesResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Profiles == nil {
		t.Error("expected profiles to be non-nil (empty array)")
	}
	if len(resp.Profiles) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(resp.Profiles))
	}
}

func TestListProfiles_MultipleProfiles(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	temp := t.TempDir()
	workspace := filepath.Join(temp, "workspace")
	configDir := filepath.Join(temp, "config")

	// Create config with multiple mount profiles
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.MountProfiles = map[string]config.MountProfile{
		"dev-profile": {
			BasePolicy: "development",
			Mounts: []config.MountSpec{
				{Path: workspace, Policy: "workspace-rw"},
				{Path: configDir, Policy: "config-readonly"},
			},
		},
		"prod-profile": {
			BasePolicy: "production",
			Mounts: []config.MountSpec{
				{Path: workspace, Policy: "workspace-readonly"},
			},
		},
	}

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, metrics.New(), nil)
	h := app.Router()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ProfilesResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if len(resp.Profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(resp.Profiles))
	}

	// Create a map for easier lookup
	profilesByName := make(map[string]ProfileInfo)
	for _, p := range resp.Profiles {
		profilesByName[p.Name] = p
	}

	// Check dev-profile
	devProfile, ok := profilesByName["dev-profile"]
	if !ok {
		t.Error("expected dev-profile to be present")
	} else {
		if devProfile.BasePolicy != "development" {
			t.Errorf("dev-profile: expected base_policy=development, got %s", devProfile.BasePolicy)
		}
		if len(devProfile.Mounts) != 2 {
			t.Errorf("dev-profile: expected 2 mounts, got %d", len(devProfile.Mounts))
		}
	}

	// Check prod-profile
	prodProfile, ok := profilesByName["prod-profile"]
	if !ok {
		t.Error("expected prod-profile to be present")
	} else {
		if prodProfile.BasePolicy != "production" {
			t.Errorf("prod-profile: expected base_policy=production, got %s", prodProfile.BasePolicy)
		}
		if len(prodProfile.Mounts) != 1 {
			t.Errorf("prod-profile: expected 1 mount, got %d", len(prodProfile.Mounts))
		}
		if len(prodProfile.Mounts) > 0 {
			if prodProfile.Mounts[0].Path != workspace {
				t.Errorf("prod-profile: expected mount path=%s, got %s", workspace, prodProfile.Mounts[0].Path)
			}
			if prodProfile.Mounts[0].Policy != "workspace-readonly" {
				t.Errorf("prod-profile: expected mount policy=workspace-readonly, got %s", prodProfile.Mounts[0].Policy)
			}
		}
	}
}

func TestListProfiles_ContentType(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, metrics.New(), nil)
	h := app.Router()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %s", contentType)
	}
}
