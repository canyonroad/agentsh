package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestCreateSessionWithProfile(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	// Create temp directories for mount paths
	temp := t.TempDir()
	workspace := filepath.Join(temp, "workspace")
	configDir := filepath.Join(temp, "config")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create config with mount profile
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.Network.Transparent.Enabled = false
	cfg.Policies.Default = "default"
	cfg.Policies.Dir = temp
	cfg.MountProfiles = map[string]config.MountProfile{
		"test-profile": {
			BasePolicy: "default",
			Mounts: []config.MountSpec{
				{Path: workspace, Policy: "workspace-rw"},
				{Path: configDir, Policy: "config-readonly"},
			},
		},
	}

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, metrics.New(), nil)
	h := app.Router()

	body := `{"profile":"test-profile"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var out types.Session
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	if out.Profile != "test-profile" {
		t.Errorf("expected profile=test-profile, got %q", out.Profile)
	}

	// Session should have primary workspace set from first mount
	if out.Workspace != workspace {
		t.Errorf("expected workspace=%q, got %q", workspace, out.Workspace)
	}
}

func TestCreateSessionWithProfile_ProfileNotFound(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	// Create config without mount profiles
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.Network.Transparent.Enabled = false
	cfg.Policies.Default = "default"

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, metrics.New(), nil)
	h := app.Router()

	body := `{"profile":"nonexistent-profile"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestResolveProfile(t *testing.T) {
	temp := t.TempDir()
	workspace := filepath.Join(temp, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		MountProfiles: map[string]config.MountProfile{
			"test-profile": {
				BasePolicy: "default",
				Mounts: []config.MountSpec{
					{Path: workspace, Policy: "workspace-rw"},
				},
			},
			"empty-profile": {
				BasePolicy: "default",
				Mounts:     []config.MountSpec{},
			},
		},
	}

	app := &App{cfg: cfg}

	// Test: valid profile
	profile, err := app.resolveProfile("test-profile")
	if err != nil {
		t.Errorf("resolveProfile(test-profile) error: %v", err)
	}
	if profile == nil {
		t.Error("resolveProfile(test-profile) returned nil")
	} else if profile.BasePolicy != "default" {
		t.Errorf("expected base_policy=default, got %s", profile.BasePolicy)
	}

	// Test: profile not found
	_, err = app.resolveProfile("nonexistent")
	if err == nil {
		t.Error("resolveProfile(nonexistent) should return error")
	}

	// Test: empty profile (no mounts)
	_, err = app.resolveProfile("empty-profile")
	if err == nil {
		t.Error("resolveProfile(empty-profile) should return error for profile with no mounts")
	}

	// Test: no profiles configured
	app2 := &App{cfg: &config.Config{}}
	_, err = app2.resolveProfile("any")
	if err == nil {
		t.Error("resolveProfile should return error when no profiles configured")
	}
}
