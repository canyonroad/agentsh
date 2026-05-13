//go:build linux

package api

import (
	"context"
	"errors"
	"net"
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

func TestMergeDBUnavoidabilityBundle_GeneratedRulesTakePrecedenceOverBroadAllows(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "appdb.sock")
	base := &policy.Policy{
		Version: 1,
		Name:    "base",
		NetworkRules: []policy.NetworkRule{{
			Name:     "allow-all-network",
			Domains:  []string{"**"},
			Decision: "allow",
		}},
		CommandRules: []policy.CommandRule{{
			Name:     "allow-all-commands",
			Commands: []string{"*"},
			Decision: "allow",
		}},
		UnixRules: []policy.UnixSocketRule{{
			Name:       "allow-all-unix",
			Paths:      []string{"**"},
			Operations: []string{"connect"},
			Decision:   "allow",
		}},
		ConnectRedirectRules: []policy.ConnectRedirectRule{{
			Name:       "base-connect-redirect",
			Match:      ".*",
			RedirectTo: "base-proxy:5432",
		}},
	}
	bundle, err := dbservice.GenerateBundle(dbservice.Config{
		Services: []dbservice.Service{{
			Name:    "appdb",
			Family:  "postgres",
			Dialect: "postgres",
			Upstream: dbservice.Endpoint{
				Host: "db.example.com",
				Port: 5432,
			},
			Listen: dbservice.Listener{
				Kind: "unix",
				Path: socketPath,
			},
			TLSMode: "terminate_reissue",
		}},
	}, dbservice.BundleOptions{
		SessionID:        "sess-db",
		ProxySessionID:   dbProxySessionIdentity,
		SocketBaseDir:    filepath.Dir(socketPath),
		IncludeToolRules: true,
		Mode:             dbservice.UnavoidabilityObserve,
		Resolver:         staticDBResolver{ips: []net.IP{net.ParseIP("10.0.0.15")}},
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	merged := mergeDBUnavoidabilityBundle(base, bundle)
	engine, err := policy.NewEngine(merged, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	netDecision := engine.CheckNetworkIP("db.example.com", nil, 5432)
	if netDecision.PolicyDecision != types.DecisionDeny || netDecision.Rule != "db-appdb-deny-direct" {
		t.Fatalf("network decision = %+v, want generated deny before broad allow", netDecision)
	}

	cmdDecision := engine.CheckCommand("ssh", []string{"-L", "15432:db.example.com:5432", "bastion"})
	if cmdDecision.PolicyDecision != types.DecisionDeny || cmdDecision.Rule != "db-bypass-ssh-forward" {
		t.Fatalf("command decision = %+v, want generated deny before broad allow", cmdDecision)
	}

	unixDecision := engine.CheckUnixSocket("/var/run/postgresql/.s.PGSQL.5432", "connect")
	if unixDecision.PolicyDecision != types.DecisionDeny || unixDecision.Rule != "db-appdb-deny-local-postgres-sockets" {
		t.Fatalf("unix decision = %+v, want generated deny before broad allow", unixDecision)
	}

	redirectDecision := engine.EvaluateConnectRedirect("db.example.com:5432")
	if !redirectDecision.Matched || redirectDecision.Rule != "db-appdb-redirect" || redirectDecision.RedirectToUnix != socketPath {
		t.Fatalf("connect redirect decision = %+v, want generated Unix redirect before broad redirect", redirectDecision)
	}
}

func TestMergeDBUnavoidabilityBundle_PrecedenceForDNSRedirectRules(t *testing.T) {
	base := &policy.Policy{
		Version: 1,
		Name:    "base",
		DnsRedirectRules: []policy.DnsRedirectRule{{
			Name:      "base-dns-redirect",
			Match:     ".*",
			ResolveTo: "192.0.2.10",
		}},
	}
	bundle := dbservice.Bundle{
		Policy: policy.Policy{
			DnsRedirectRules: []policy.DnsRedirectRule{{
				Name:      "db-generated-dns-redirect",
				Match:     "^db\\.example\\.com$",
				ResolveTo: "127.0.0.1",
			}},
		},
	}

	merged := mergeDBUnavoidabilityBundle(base, bundle)
	engine, err := policy.NewEngine(merged, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	decision := engine.EvaluateDnsRedirect("db.example.com")
	if !decision.Matched || decision.Rule != "db-generated-dns-redirect" || decision.ResolveTo != "127.0.0.1" {
		t.Fatalf("dns redirect decision = %+v, want bundle rule before broad base redirect", decision)
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

func TestCreateSessionCore_DBUnavoidabilityRegularFileListenerFailsClosed(t *testing.T) {
	app, mgr := newDBUnavoidabilityTestApp(t, dbObservePolicyYAML())
	app.dbProxySessionResolverForTest = fixedDBSessionResolver{sessionID: "sess-db-regular-file"}

	listenPath := filepath.Join(app.cfg.Sessions.BaseDir, "sess-db-regular-file", "db-proxy", "db-services", "appdb.sock")
	if err := os.MkdirAll(filepath.Dir(listenPath), 0o700); err != nil {
		t.Fatalf("mkdir listener parent: %v", err)
	}
	if err := os.WriteFile(listenPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write listener placeholder: %v", err)
	}

	_, code, err := app.createSessionCore(context.Background(), types.CreateSessionRequest{
		ID:        "sess-db-regular-file",
		Workspace: t.TempDir(),
		Policy:    "default",
	})
	if err == nil {
		t.Fatal("createSessionCore: want error, got nil")
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want %d", code, http.StatusInternalServerError)
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("error = %v, want non-socket listener error", err)
	}
	if _, ok := mgr.Get("sess-db-regular-file"); ok {
		t.Fatal("failed session remained in manager")
	}
}

func TestCreateSessionCore_DBUnavoidabilityStartErrorDuringReadinessFailsClosed(t *testing.T) {
	app, mgr := newDBUnavoidabilityTestApp(t, dbObservePolicyYAML())
	sessionID := "s" + strings.Repeat("x", 127)
	app.dbProxySessionResolverForTest = fixedDBSessionResolver{sessionID: sessionID}

	_, code, err := app.createSessionCore(context.Background(), types.CreateSessionRequest{
		ID:        sessionID,
		Workspace: t.TempDir(),
		Policy:    "default",
	})
	if err == nil {
		t.Fatal("createSessionCore: want error, got nil")
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want %d", code, http.StatusInternalServerError)
	}
	if !strings.Contains(err.Error(), "bind listener") {
		t.Fatalf("error = %v, want proxy start bind error", err)
	}
	if _, ok := mgr.Get(sessionID); ok {
		t.Fatal("failed session remained in manager")
	}
}

func TestMonitorSessionDBProxyStartClosesProxyOnUnexpectedExit(t *testing.T) {
	mgr := session.NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	closed := make(chan struct{})
	s.SetDBProxy(filepath.Join(t.TempDir(), "db-services"), func() error {
		close(closed)
		return nil
	})

	proxyCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startErrCh := make(chan error, 1)
	monitorSessionDBProxyStart(s, proxyCtx, startErrCh)
	startErrCh <- errors.New("accept loop failed")

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("DB proxy close function was not called")
	}
	if got := s.DBProxySocketDir(); got != "" {
		t.Fatalf("DBProxySocketDir after unexpected exit = %q, want empty", got)
	}
}

func TestCreateSessionCore_NoPolicyDirUsesGlobalEngine(t *testing.T) {
	globalEngine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "global",
		CommandRules: []policy.CommandRule{{
			Name:     "allow-all",
			Commands: []string{"*"},
			Decision: "allow",
		}},
		FileRules: []policy.FileRule{{
			Name:       "allow-all",
			Paths:      []string{"/**"},
			Operations: []string{"*"},
			Decision:   "allow",
		}},
		NetworkRules: []policy.NetworkRule{{
			Name:     "allow-all",
			Domains:  []string{"**"},
			Decision: "allow",
		}},
	}, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.Network.Transparent.Enabled = false
	cfg.Sessions.BaseDir = t.TempDir()
	mgr := session.NewManager(10)
	store := composite.New(mockEventStore{}, nil)
	app := NewApp(cfg, mgr, store, globalEngine, appevents.NewBroker(), nil, nil, nil, metrics.New(), nil, nil)

	snap, code, err := app.createSessionCore(context.Background(), types.CreateSessionRequest{
		ID:        "sess-global-engine",
		Workspace: t.TempDir(),
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
	if got := s.PolicyEngine(); got != globalEngine {
		t.Fatalf("session policy engine = %p, want global engine %p", got, globalEngine)
	}
}

type fixedDBSessionResolver struct {
	sessionID string
}

func (r fixedDBSessionResolver) ResolveSessionID(pid int32) (string, bool) {
	return r.sessionID, true
}

type staticDBResolver struct {
	ips []net.IP
}

func (r staticDBResolver) LookupIP(context.Context, string) ([]net.IP, error) {
	return append([]net.IP(nil), r.ips...), nil
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
