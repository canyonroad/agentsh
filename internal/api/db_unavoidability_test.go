//go:build linux

package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
	appevents "github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestDBServiceConfigFromProxyServices(t *testing.T) {
	services := []dbProxyService{
		{
			Name:       "appdb",
			DBService:  dbPolicyService("appdb", "db.example.com:5432"),
			ListenKind: "unix",
			ListenPath: filepath.Join(t.TempDir(), "appdb.sock"),
		},
		{
			Name:       "analytics",
			DBService:  dbPolicyService("analytics", "127.0.0.1:15432"),
			ListenKind: "tcp",
			ListenHost: "127.0.0.1",
			ListenPort: 25432,
		},
	}

	cfg, err := dbServiceConfigFromProxyServices(services)
	if err != nil {
		t.Fatalf("dbServiceConfigFromProxyServices: %v", err)
	}
	if len(cfg.Services) != 2 {
		t.Fatalf("len(Services) = %d, want 2", len(cfg.Services))
	}
	if got := cfg.Services[0]; got.Name != "appdb" || got.Upstream.Host != "db.example.com" || got.Upstream.Port != 5432 || got.Listen.Kind != "unix" || got.Listen.Path != services[0].ListenPath {
		t.Fatalf("first service = %+v", got)
	}
	if got := cfg.Services[1]; got.Name != "analytics" || got.Upstream.Host != "127.0.0.1" || got.Upstream.Port != 15432 || got.Listen.Kind != "tcp" || got.Listen.Host != "127.0.0.1" || got.Listen.Port != 25432 {
		t.Fatalf("second service = %+v", got)
	}
}

func TestMergeDBUnavoidabilityBundle_SessionLocalCopy(t *testing.T) {
	base := &policy.Policy{
		Version: 1,
		Name:    "base",
		NetworkRules: []policy.NetworkRule{{
			Name:     "base-net",
			Domains:  []string{"example.com"},
			Decision: "allow",
		}},
	}
	bundle := dbservice.Bundle{
		Policy: policy.Policy{
			NetworkRules: []policy.NetworkRule{{
				Name:     "db-appdb-deny-direct",
				Domains:  []string{"db.example.com"},
				Ports:    []int{5432},
				Decision: "deny",
			}},
			ConnectRedirectRules: []policy.ConnectRedirectRule{{
				Name:           "db-appdb-redirect",
				Match:          "^db.example.com:5432$",
				RedirectToUnix: filepath.Join(t.TempDir(), "appdb.sock"),
			}},
		},
		Metadata: []policy.RuleMetadata{{
			RuleName:  "db-appdb-deny-direct",
			Source:    dbservice.RuleSourceDBUnavoidability,
			DBService: "appdb",
		}},
	}

	merged := mergeDBUnavoidabilityBundle(base, bundle)
	if merged == base {
		t.Fatal("mergeDBUnavoidabilityBundle returned base pointer")
	}
	if len(base.NetworkRules) != 1 || len(base.ConnectRedirectRules) != 0 || len(base.Metadata) != 0 {
		t.Fatalf("base policy was mutated: %+v", base)
	}
	if len(merged.NetworkRules) != 2 {
		t.Fatalf("len(merged.NetworkRules) = %d, want 2", len(merged.NetworkRules))
	}
	if len(merged.ConnectRedirectRules) != 1 {
		t.Fatalf("len(merged.ConnectRedirectRules) = %d, want 1", len(merged.ConnectRedirectRules))
	}
	if len(merged.Metadata) != 1 || merged.Metadata[0].Source != dbservice.RuleSourceDBUnavoidability || merged.Metadata[0].DBService != "appdb" {
		t.Fatalf("merged metadata = %+v", merged.Metadata)
	}
}

func TestCreateSessionCore_DBUnavoidabilityAddsGeneratedMetadataAndStartsProxy(t *testing.T) {
	app, mgr := newDBUnavoidabilityTestApp(t, dbObservePolicyYAML())
	app.dbProxySessionResolverForTest = fixedDBSessionResolver{sessionID: "sess-db"}

	snap, code, err := app.createSessionCore(context.Background(), types.CreateSessionRequest{
		ID:        "sess-db",
		Workspace: t.TempDir(),
		Policy:    "default",
	})
	if err != nil {
		t.Fatalf("createSessionCore: code=%d err=%v", code, err)
	}
	if code != http.StatusCreated {
		t.Fatalf("code = %d, want %d", code, http.StatusCreated)
	}
	s, ok := mgr.Get(snap.ID)
	if !ok {
		t.Fatalf("session %q not found", snap.ID)
	}
	defer app.cleanupCreatedSession(s)

	pol := s.PolicyEngine().Policy()
	found := false
	for _, meta := range pol.Metadata {
		if meta.Source == dbservice.RuleSourceDBUnavoidability && meta.DBService == "appdb" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("policy metadata missing db_unavoidability appdb entry: %+v", pol.Metadata)
	}
	if s.DBProxySocketDir() == "" {
		t.Fatal("DBProxySocketDir is empty")
	}
	waitForPath(t, filepath.Join(s.DBProxySocketDir(), "appdb.sock"), 2*time.Second)
}

func TestCreateSessionCore_DBUnavoidabilityMissingResolverFailsClosed(t *testing.T) {
	app, mgr := newDBUnavoidabilityTestApp(t, dbObservePolicyYAML())

	_, code, err := app.createSessionCore(context.Background(), types.CreateSessionRequest{
		ID:        "sess-no-resolver",
		Workspace: t.TempDir(),
		Policy:    "default",
	})
	if err == nil {
		t.Fatal("createSessionCore: want error, got nil")
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want %d", code, http.StatusInternalServerError)
	}
	if !strings.Contains(err.Error(), "DB proxy session resolver") {
		t.Fatalf("error = %v, want missing resolver", err)
	}
	if _, ok := mgr.Get("sess-no-resolver"); ok {
		t.Fatal("failed session remained in manager")
	}
}

type fixedDBSessionResolver struct {
	sessionID string
}

func (r fixedDBSessionResolver) ResolveSessionID(pid int32) (string, bool) {
	return r.sessionID, true
}

func newDBUnavoidabilityTestApp(t *testing.T, policyYAML string) (*App, *session.Manager) {
	t.Helper()
	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "default.yaml"), []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.Network.Transparent.Enabled = false
	cfg.Policies.Dir = policyDir
	cfg.Policies.Default = "default"
	sessionBase, err := os.MkdirTemp("", "adb")
	if err != nil {
		t.Fatalf("temp session base: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sessionBase) })
	cfg.Sessions.BaseDir = sessionBase

	mgr := session.NewManager(10)
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	app := NewApp(cfg, mgr, store, nil, appevents.NewBroker(), nil, nil, nil, metrics.New(), nil, nil)
	return app, mgr
}

func dbObservePolicyYAML() string {
	return `
version: 1
name: db-observe
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: ["*"]
    decision: allow
network_rules:
  - name: allow-all
    domains: ["**"]
    decision: allow
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: 127.0.0.1:5432
    tls_mode: terminate_reissue
database_rules:
  - name: audit-appdb
    db_service: appdb
    operations: ["*"]
    decision: audit
policies:
  db:
    unavoidability: observe
`
}

func dbPolicyService(name, upstream string) dbpolicy.DBService {
	return dbpolicy.DBService{
		Name:     name,
		Family:   "postgres",
		Dialect:  "postgres",
		Upstream: upstream,
		TLSMode:  "terminate_reissue",
	}
}

func waitForPath(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("path never appeared: %s", path)
}
