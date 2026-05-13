# DB Plan 07b Runtime Auth Events Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire DB unavoidability bundles into session-local runtime policy, authorize DB proxy listeners by owning session ID, and emit deduplicated DB bypass audit events.

**Architecture:** The DB proxy becomes session-scoped for unavoidability-enabled sessions because listener authorization requires a concrete owning session ID. Session creation loads the base policy, creates the session, generates and merges the DB bundle with that session ID, compiles the session-local policy engine, and starts a per-session DB proxy bound to the same generated socket paths. DB bypass event mapping is centralized in `internal/db/events` so ptrace and network proxy paths can share rule-metadata lookup and dedupe.

**Tech Stack:** Go, existing `internal/policy` engine and metadata, existing `internal/db/service.GenerateBundle`, existing `internal/db/proxy/postgres` proxy, existing ptrace tracer, table-driven Go tests.

---

## File Structure

**Created:**

- `internal/api/db_unavoidability.go` - session DB state path, DB service conversion, bundle merge, policy compile helper, per-session DB proxy startup.
- `internal/api/db_lifecycle_sink.go` - adapter from DB proxy lifecycle events to the existing `types.Event` audit store/broker pipeline.
- `internal/api/db_unavoidability_test.go` - runtime bundle merge, session cleanup, and per-session proxy config tests.
- `internal/db/events/bypass.go` - DB bypass metadata lookup, event construction, and 60 second in-memory dedupe.
- `internal/db/events/bypass_test.go` - bypass event and dedupe tests.

**Modified:**

- `internal/session/manager.go` - add DB proxy cleanup state and methods.
- `internal/api/app.go` - initialize the DB bypass emitter, close session DB proxies on destroy, and use the new session-create compile/start sequence.
- `internal/api/app_ptrace_linux.go` - pass the DB bypass emitter into the ptrace router.
- `internal/api/app_ptrace_other.go` - keep non-Linux helpers compiling.
- `internal/api/db_proxy.go` - pass `AgentSessionID` and `SessionResolver` into Postgres proxy config.
- `internal/api/db_proxy_test.go` - update proxy startup tests for required session resolver fields.
- `internal/api/ptrace_handlers.go` - emit DB bypass attempts for DB-generated exec and network denials.
- `internal/api/ptrace_handlers_test.go` - assert DB bypass event emission and non-DB denials.
- `internal/db/events/lifecycle.go` - add listener peer session and bypass event JSON fields.
- `internal/db/events/lifecycle_test.go` - round-trip and omitempty coverage for new lifecycle fields.
- `internal/db/proxy/postgres/server.go` - replace UID authorization with session resolver authorization.
- `internal/db/proxy/postgres/stub_other.go` - keep new config fields available on non-Linux builds.
- `internal/db/proxy/postgres/peercred_linux_test.go` - update auth tests for session resolver success, miss, and mismatch.
- `internal/db/proxy/postgres/server_test.go` - provide default resolver/session config in non-auth-focused tests.
- `internal/ptrace/tracer.go` - expose `ResolveSessionID(pid int32)`.
- `internal/ptrace/tracer_test.go` - cover exact TID, TGID scan, and unknown PID lookup.
- `internal/netmonitor/proxy.go` - add optional DB bypass emitter and emit on DB-generated CONNECT/HTTP denials.
- `internal/netmonitor/transparent_tcp.go` - add optional DB bypass emitter and emit on DB-generated transparent TCP denials.
- `internal/netmonitor/proxy_test.go` - unit-test DB bypass emission from explicit proxy decision paths.
- `internal/server/server.go` - stop constructing the old global DB proxy; 07b starts DB proxies per session.

---

### Task 1: Add Session DB Proxy Lifecycle State

**Files:**
- Modify: `internal/session/manager.go`
- Test: `internal/session/manager_test.go`

- [ ] **Step 1: Write failing session DB proxy lifecycle test**

Append this test to `internal/session/manager_test.go`:

```go
func TestSession_DBProxyLifecycle(t *testing.T) {
	mgr := NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var closed int
	s.SetDBProxy("/tmp/agentsh-db-test", func() error {
		closed++
		return nil
	})

	if got := s.DBProxySocketDir(); got != "/tmp/agentsh-db-test" {
		t.Fatalf("DBProxySocketDir = %q, want /tmp/agentsh-db-test", got)
	}
	if err := s.CloseDBProxy(); err != nil {
		t.Fatalf("CloseDBProxy: %v", err)
	}
	if closed != 1 {
		t.Fatalf("closed = %d, want 1", closed)
	}
	if got := s.DBProxySocketDir(); got != "" {
		t.Fatalf("DBProxySocketDir after close = %q, want empty", got)
	}
	if err := s.CloseDBProxy(); err != nil {
		t.Fatalf("second CloseDBProxy: %v", err)
	}
	if closed != 1 {
		t.Fatalf("closed after second close = %d, want 1", closed)
	}
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
go test ./internal/session -run TestSession_DBProxyLifecycle -count=1
```

Expected: FAIL with undefined methods `SetDBProxy`, `DBProxySocketDir`, and `CloseDBProxy`.

- [ ] **Step 3: Add DB proxy fields to `Session`**

In `internal/session/manager.go`, add these fields near `netnsName`:

```go
	dbProxySocketDir string
	dbProxyClose     func() error
```

- [ ] **Step 4: Add DB proxy lifecycle methods**

Add these methods near `SetNetNS` / `CloseNetNS`:

```go
func (s *Session) SetDBProxy(socketDir string, closeFn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dbProxySocketDir = socketDir
	s.dbProxyClose = closeFn
}

func (s *Session) DBProxySocketDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dbProxySocketDir
}

func (s *Session) CloseDBProxy() error {
	s.mu.Lock()
	fn := s.dbProxyClose
	s.dbProxyClose = nil
	s.dbProxySocketDir = ""
	s.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return nil
}
```

- [ ] **Step 5: Run and commit**

Run:

```bash
go test ./internal/session -run TestSession_DBProxyLifecycle -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/session/manager.go internal/session/manager_test.go
git commit -m "feat: track session db proxy lifecycle"
```

---

### Task 2: Add Runtime Bundle Helpers

**Files:**
- Create: `internal/api/db_unavoidability.go`
- Create: `internal/api/db_unavoidability_test.go`

- [ ] **Step 1: Write failing tests for service conversion and bundle merge**

Create `internal/api/db_unavoidability_test.go` with:

```go
package api

import (
	"path/filepath"
	"testing"

	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

func TestDBServiceConfigFromProxyServices(t *testing.T) {
	stateDir := t.TempDir()
	services := []dbProxyService{{
		Name: "appdb",
		DBService: dbpolicy.DBService{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
		},
		ListenKind: "unix",
		ListenPath: filepath.Join(stateDir, "db-services", "appdb.sock"),
	}}

	got, err := dbServiceConfigFromProxyServices(services)
	if err != nil {
		t.Fatalf("dbServiceConfigFromProxyServices: %v", err)
	}
	if len(got.Services) != 1 {
		t.Fatalf("services len = %d, want 1", len(got.Services))
	}
	svc := got.Services[0]
	if svc.Name != "appdb" || svc.Family != "postgres" || svc.Dialect != "postgres" {
		t.Fatalf("unexpected service identity: %+v", svc)
	}
	if svc.Upstream.Host != "db.internal" || svc.Upstream.Port != 5432 {
		t.Fatalf("unexpected upstream: %+v", svc.Upstream)
	}
	if svc.Listen.Kind != "unix" || svc.Listen.Path != filepath.Join(stateDir, "db-services", "appdb.sock") {
		t.Fatalf("unexpected listener: %+v", svc.Listen)
	}
}

func TestMergeDBUnavoidabilityBundle_SessionLocalCopy(t *testing.T) {
	base := &rootpolicy.Policy{
		Version: 1,
		Name:    "base",
		NetworkRules: []rootpolicy.NetworkRule{{
			Name:     "base-allow",
			Domains:  []string{"example.com"},
			Decision: "allow",
		}},
	}
	bundle := dbservice.Bundle{
		Policy: rootpolicy.Policy{
			NetworkRules: []rootpolicy.NetworkRule{{
				Name:     "db-appdb-deny-direct",
				Domains:  []string{"db.internal"},
				Ports:    []int{5432},
				Decision: "deny",
			}},
			ConnectRedirectRules: []rootpolicy.ConnectRedirectRule{{
				Name:           "db-appdb-redirect",
				Match:          "^db\\.internal:5432$",
				RedirectToUnix: "/tmp/appdb.sock",
			}},
		},
		Metadata: []rootpolicy.RuleMetadata{{
			RuleName:    "db-appdb-deny-direct",
			Source:      dbservice.RuleSourceDBUnavoidability,
			DBService:   "appdb",
			BypassMode:  dbservice.BypassModeTCPDirect,
			Destination: "db.internal:5432",
		}},
	}

	merged := mergeDBUnavoidabilityBundle(base, bundle)
	if merged == base {
		t.Fatal("merge returned base pointer; want session-local copy")
	}
	if len(base.NetworkRules) != 1 {
		t.Fatalf("base mutated: network rules len = %d, want 1", len(base.NetworkRules))
	}
	if len(merged.NetworkRules) != 2 {
		t.Fatalf("merged network rules len = %d, want 2", len(merged.NetworkRules))
	}
	if len(merged.ConnectRedirectRules) != 1 {
		t.Fatalf("merged connect redirects len = %d, want 1", len(merged.ConnectRedirectRules))
	}
	if len(merged.Metadata) != 1 || merged.Metadata[0].Source != dbservice.RuleSourceDBUnavoidability {
		t.Fatalf("merged metadata = %+v", merged.Metadata)
	}
}
```

- [ ] **Step 2: Run failing tests**

Run:

```bash
go test ./internal/api -run 'TestDBServiceConfigFromProxyServices|TestMergeDBUnavoidabilityBundle_SessionLocalCopy' -count=1
```

Expected: FAIL with undefined helper functions.

- [ ] **Step 3: Implement helper file**

Create `internal/api/db_unavoidability.go`:

```go
package api

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

const dbProxySessionIdentity = "agentsh-db-proxy"

type defaultDBResolver struct{}

func (defaultDBResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func sessionDBProxyStateDir(baseDir, sessionID string) string {
	return filepath.Join(baseDir, sessionID, "db-proxy")
}

func dbServiceConfigFromProxyServices(services []dbProxyService) (dbservice.Config, error) {
	out := dbservice.Config{Services: make([]dbservice.Service, 0, len(services))}
	for _, svc := range services {
		host, portString, err := net.SplitHostPort(svc.DBService.Upstream)
		if err != nil {
			return dbservice.Config{}, fmt.Errorf("service %q upstream %q: %w", svc.Name, svc.DBService.Upstream, err)
		}
		port, err := strconv.Atoi(portString)
		if err != nil || port <= 0 {
			return dbservice.Config{}, fmt.Errorf("service %q upstream port %q is invalid", svc.Name, portString)
		}
		out.Services = append(out.Services, dbservice.Service{
			Name:    svc.Name,
			Family:  svc.DBService.Family,
			Dialect: svc.DBService.Dialect,
			Upstream: dbservice.Endpoint{
				Host: host,
				Port: port,
			},
			Listen: dbservice.Listener{
				Kind: svc.ListenKind,
				Path: svc.ListenPath,
				Host: svc.ListenHost,
				Port: svc.ListenPort,
			},
			TLSMode: svc.DBService.TLSMode,
		})
	}
	return out, nil
}

func mergeDBUnavoidabilityBundle(base *policy.Policy, bundle dbservice.Bundle) *policy.Policy {
	if base == nil {
		return nil
	}
	merged := *base
	merged.NetworkRules = append(append([]policy.NetworkRule(nil), base.NetworkRules...), bundle.Policy.NetworkRules...)
	merged.CommandRules = append(append([]policy.CommandRule(nil), base.CommandRules...), bundle.Policy.CommandRules...)
	merged.UnixRules = append(append([]policy.UnixSocketRule(nil), base.UnixRules...), bundle.Policy.UnixRules...)
	merged.DnsRedirectRules = append(append([]policy.DnsRedirectRule(nil), base.DnsRedirectRules...), bundle.Policy.DnsRedirectRules...)
	merged.ConnectRedirectRules = append(append([]policy.ConnectRedirectRule(nil), base.ConnectRedirectRules...), bundle.Policy.ConnectRedirectRules...)
	merged.Metadata = append(append([]policy.RuleMetadata(nil), base.Metadata...), bundle.Metadata...)
	return &merged
}

func collectSortedDBProxyServices(rs *dbpolicy.RuleSet, stateDir string) []dbProxyService {
	services := collectDBProxyServices(rs, stateDir)
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	return services
}

func (a *App) compileDBPolicyForSession(_ context.Context, s *session.Session, base *policy.Policy, policyVars map[string]string, enforceApprovals bool) (*policy.Engine, *dbpolicy.RuleSet, string, error) {
	if base == nil {
		return a.policy, nil, "", nil
	}
	rs, err := loadDBRuleSet(base)
	if err != nil {
		return nil, nil, "", err
	}
	sessionStateDir := sessionDBProxyStateDir(a.cfg.Sessions.BaseDir, s.ID)
	pol := base
	if rs != nil && rs.Unavoidability() != dbservice.UnavoidabilityOff && len(rs.AllServices()) > 0 {
		services := collectSortedDBProxyServices(rs, sessionStateDir)
		serviceCfg, err := dbServiceConfigFromProxyServices(services)
		if err != nil {
			return nil, nil, "", err
		}
		bundle, err := dbservice.GenerateBundle(serviceCfg, dbservice.BundleOptions{
			SessionID:                  s.ID,
			ProxySessionID:             dbProxySessionIdentity,
			SocketBaseDir:              filepath.Join(sessionStateDir, "db-services"),
			IncludeToolRules:           true,
			Mode:                       rs.Unavoidability(),
			AllowHostnameOnlyInEnforce: false,
			Resolver:                   defaultDBResolver{},
		})
		if err != nil {
			return nil, nil, "", err
		}
		for _, w := range bundle.Warnings {
			_ = w
		}
		pol = mergeDBUnavoidabilityBundle(base, bundle)
	}
	engine, err := policy.NewEngineWithVariables(pol, enforceApprovals, true, policyVars)
	if err != nil {
		return nil, nil, "", fmt.Errorf("compile policy: %w", err)
	}
	return engine, rs, sessionStateDir, nil
}

func (a *App) startSessionDBProxy(ctx context.Context, s *session.Session, rs *dbpolicy.RuleSet, stateDir string) error {
	if rs == nil || rs.Unavoidability() == dbservice.UnavoidabilityOff || len(rs.AllServices()) == 0 {
		return nil
	}
	resolver := a.dbProxySessionResolver()
	if resolver == nil {
		return fmt.Errorf("db proxy session resolver is required when DB unavoidability is %s", rs.Unavoidability())
	}
	proxyCtx, cancel := context.WithCancel(context.Background())
	deps := dbProxyDeps{
		Unavoidability:  rs.Unavoidability(),
		Services:        collectSortedDBProxyServices(rs, stateDir),
		StateDir:        stateDir,
		Sink:            dbAuditSink{store: a.store, broker: a.broker},
		Policy:          rs,
		AgentSessionID:  s.ID,
		SessionResolver: resolver,
	}
	srv, err := startDBProxy(proxyCtx, deps)
	if err != nil {
		cancel()
		return err
	}
	s.SetDBProxy(filepath.Join(stateDir, "db-services"), func() error {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	})
	return nil
}

func (a *App) cleanupCreatedSession(s *session.Session) {
	if s == nil {
		return
	}
	_ = s.CloseDBProxy()
	_ = s.CloseNetNS()
	_ = s.CloseProxy()
	_ = s.CloseLLMProxy()
	_ = s.UnmountWorkspace()
	_ = a.sessions.Destroy(s.ID)
}
```

- [ ] **Step 4: Create DB lifecycle audit sink**

Create `internal/api/db_lifecycle_sink.go`:

```go
package api

import (
	"context"
	"time"

	dbevents "github.com/agentsh/agentsh/internal/db/events"
	appevents "github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

type dbAuditSink struct {
	store  *composite.Store
	broker *appevents.Broker
}

func (s dbAuditSink) EmitStatement(context.Context, dbevents.DBEvent) error {
	return nil
}

func (s dbAuditSink) EmitLifecycle(ctx context.Context, ev dbevents.LifecycleEvent) error {
	if s.store == nil {
		return nil
	}
	out := dbLifecycleToEvent(ev)
	if out.Timestamp.IsZero() {
		out.Timestamp = time.Now().UTC()
	}
	if err := s.store.AppendEvent(ctx, out); err != nil {
		return err
	}
	if s.broker != nil {
		s.broker.Publish(out)
	}
	return nil
}

func dbLifecycleToEvent(ev dbevents.LifecycleEvent) types.Event {
	fields := map[string]any{
		"kind": ev.Kind,
	}
	if ev.DBService != "" {
		fields["db_service"] = ev.DBService
	}
	if ev.ClientIdentity != "" {
		fields["client_identity"] = ev.ClientIdentity
	}
	if ev.Reason != "" {
		fields["reason"] = ev.Reason
	}
	if ev.PeerUID != 0 {
		fields["peer_uid"] = ev.PeerUID
	}
	if ev.PeerPID != 0 {
		fields["peer_pid"] = ev.PeerPID
	}
	if ev.PeerSessionID != "" {
		fields["peer_session_id"] = ev.PeerSessionID
	}
	if ev.ErrorCode != "" {
		fields["error_code"] = ev.ErrorCode
	}
	if ev.SNIHostname != "" {
		fields["sni_hostname"] = ev.SNIHostname
	}
	if ev.DegradedReason != "" {
		fields["degraded_reason"] = ev.DegradedReason
	}
	return types.Event{
		ID:        ev.EventID,
		Timestamp: ev.Timestamp,
		Type:      ev.Kind,
		SessionID: ev.SessionID,
		PID:       int(ev.PeerPID),
		Fields:    fields,
	}
}
```

- [ ] **Step 5: Add resolver override field and build-tag helpers**

In `internal/api/app.go`, add this test override field to `App` near `ptraceTracer`:

```go
	dbProxySessionResolverForTest interface {
		ResolveSessionID(pid int32) (string, bool)
	}
```

In `internal/api/app_ptrace_linux.go`, add:

```go
func (a *App) dbProxySessionResolver() interface {
	ResolveSessionID(pid int32) (string, bool)
} {
	if a.dbProxySessionResolverForTest != nil {
		return a.dbProxySessionResolverForTest
	}
	tr, _ := a.ptraceTracer.(*ptrace.Tracer)
	return tr
}
```

In `internal/api/app_ptrace_other.go`, add:

```go
func (a *App) dbProxySessionResolver() interface {
	ResolveSessionID(pid int32) (string, bool)
} {
	if a.dbProxySessionResolverForTest != nil {
		return a.dbProxySessionResolverForTest
	}
	return nil
}
```

- [ ] **Step 6: Run and commit passing helper tests**

Run:

```bash
go test ./internal/api -run 'TestDBServiceConfigFromProxyServices|TestMergeDBUnavoidabilityBundle_SessionLocalCopy' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/api/db_unavoidability.go internal/api/db_lifecycle_sink.go internal/api/db_unavoidability_test.go internal/api/app.go internal/api/app_ptrace_linux.go internal/api/app_ptrace_other.go
git commit -m "feat: prepare db unavoidability runtime helpers"
```

---

### Task 3: Make DB Proxy Startup Session-Scoped

**Files:**
- Modify: `internal/api/db_proxy.go`
- Modify: `internal/api/db_proxy_test.go`
- Modify: `internal/server/server.go`
- Modify: `internal/api/app.go`

- [ ] **Step 1: Write failing API config test**

Append this test to `internal/api/db_proxy_test.go`:

```go
type testDBSessionResolver map[int32]string

func (r testDBSessionResolver) ResolveSessionID(pid int32) (string, bool) {
	v, ok := r[pid]
	return v, ok
}

func TestBuildDBProxyConfig_CarriesSessionAuth(t *testing.T) {
	deps := dbProxyDeps{
		Unavoidability: dbservice.UnavoidabilityObserve,
		AgentSessionID: "session-db",
		SessionResolver: testDBSessionResolver{
			123: "session-db",
		},
		Services: []dbProxyService{{
			Name:       "appdb",
			DBService:  dbpolicy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
			ListenKind: "unix",
			ListenPath: filepath.Join(t.TempDir(), "appdb.sock"),
		}},
		StateDir: t.TempDir(),
		Sink:     &events.SyncSink{},
	}

	cfg, err := buildDBProxyConfig(deps)
	if err != nil {
		t.Fatalf("buildDBProxyConfig: %v", err)
	}
	if cfg.AgentSessionID != "session-db" {
		t.Fatalf("AgentSessionID = %q, want session-db", cfg.AgentSessionID)
	}
	if cfg.SessionResolver == nil {
		t.Fatal("SessionResolver is nil")
	}
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
go test ./internal/api -run TestBuildDBProxyConfig_CarriesSessionAuth -count=1
```

Expected: FAIL with undefined `AgentSessionID` and `SessionResolver` fields.

- [ ] **Step 3: Add auth fields to proxy deps and config wiring**

In `internal/api/db_proxy.go`, extend `dbProxyDeps`:

```go
	AgentSessionID  string
	SessionResolver postgres.SessionResolver
```

In `buildDBProxyConfig`, pass the fields:

```go
	cfg := postgres.Config{
		Unavoidability:  deps.Unavoidability,
		StateDir:        deps.StateDir,
		Sink:            deps.Sink,
		Policy:          deps.Policy,
		AgentSessionID:  deps.AgentSessionID,
		SessionResolver: deps.SessionResolver,
	}
```

- [ ] **Step 4: Remove global DB proxy startup**

In `internal/server/server.go`, remove the block that constructs `api.NewDBProxy(engine.Policy(), dbStateDir, dbevents.NopSink{})` and the associated `dbevents` / `dbproxy` imports. Replace the removed block with this comment:

```go
	// DB proxies are session-scoped as of DB plan 07b because listener
	// authorization requires the owning session ID. Session creation starts
	// the proxy after compiling the session-local DB unavoidability bundle.
```

- [ ] **Step 5: Close DB proxies on session destroy**

In `internal/api/app.go`, update `destroySession` before `CloseNetNS`:

```go
	_ = s.CloseDBProxy()
	_ = s.CloseNetNS()
```

In `createSessionCore`, use `a.cleanupCreatedSession(s)` for error cleanup introduced in Task 2. The concrete session creation reordering lands in Task 6.

- [ ] **Step 6: Update existing DB proxy tests to provide session auth**

In `internal/api/db_proxy_test.go`, each observe-mode `dbProxyDeps` should include:

```go
		AgentSessionID:  "session-test",
		SessionResolver: testDBSessionResolver{},
```

The resolver map may be empty for tests that only assert construction or socket binding; Postgres auth behavior is covered in Task 4.

- [ ] **Step 7: Run and commit**

Run:

```bash
go test ./internal/api -run 'TestStartDBProxy|TestBuildDBProxyConfig_CarriesSessionAuth' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/api/db_proxy.go internal/api/db_proxy_test.go internal/server/server.go internal/api/app.go
git commit -m "feat: make db proxy session scoped"
```

---

### Task 4: Authorize Postgres Listener Peers By Session ID

**Files:**
- Modify: `internal/db/events/lifecycle.go`
- Modify: `internal/db/events/lifecycle_test.go`
- Modify: `internal/db/proxy/postgres/server.go`
- Modify: `internal/db/proxy/postgres/stub_other.go`
- Modify: `internal/db/proxy/postgres/peercred_linux_test.go`
- Modify: `internal/db/proxy/postgres/server_test.go`
- Modify: `internal/ptrace/tracer.go`
- Modify: `internal/ptrace/tracer_test.go`
- Modify: `internal/api/app_ptrace_linux.go`

- [ ] **Step 1: Add failing lifecycle JSON test**

Extend `TestLifecycleEvent_JSONRoundTrip` in `internal/db/events/lifecycle_test.go` by setting these fields on `in`:

```go
		PeerSessionID:   "session-peer",
		RuleName:        "db-appdb-deny-direct",
		BypassMode:      "tcp_direct",
		Destination:     "db.internal:5432",
		ProcessID:       12345,
		ProcessIdentity: "pid:12345",
		SuppressedCount: 7,
```

Expected failure before implementation: struct fields are undefined.

- [ ] **Step 2: Add lifecycle fields**

In `internal/db/events/lifecycle.go`, add fields after `PeerPID`:

```go
	PeerSessionID string `json:"peer_session_id,omitempty"`
```

Add fields near the end of the struct:

```go
	RuleName        string `json:"rule_name,omitempty"`
	BypassMode      string `json:"bypass_mode,omitempty"`
	Destination     string `json:"destination,omitempty"`
	ProcessID       int    `json:"process_id,omitempty"`
	ProcessIdentity string `json:"process_identity,omitempty"`
	SuppressedCount int    `json:"suppressed_count,omitempty"`
```

- [ ] **Step 3: Write failing tracer resolver tests**

Append to `internal/ptrace/tracer_test.go`:

```go
func TestTracerResolveSessionID(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	tr.mu.Lock()
	tr.tracees[101] = &TraceeState{TID: 101, TGID: 201, SessionID: "session-exact"}
	tr.tracees[102] = &TraceeState{TID: 102, TGID: 202, SessionID: "session-tgid"}
	tr.mu.Unlock()

	if got, ok := tr.ResolveSessionID(101); !ok || got != "session-exact" {
		t.Fatalf("ResolveSessionID exact = %q, %v; want session-exact, true", got, ok)
	}
	if got, ok := tr.ResolveSessionID(202); !ok || got != "session-tgid" {
		t.Fatalf("ResolveSessionID tgid = %q, %v; want session-tgid, true", got, ok)
	}
	if got, ok := tr.ResolveSessionID(999); ok || got != "" {
		t.Fatalf("ResolveSessionID unknown = %q, %v; want empty, false", got, ok)
	}
}
```

- [ ] **Step 4: Implement tracer resolver**

In `internal/ptrace/tracer.go`, add after `TraceeCount`:

```go
// ResolveSessionID resolves a Linux PID/TID to the owning AgentSH session.
// It first checks an exact traced thread ID, then scans for a matching TGID.
func (t *Tracer) ResolveSessionID(pid int32) (string, bool) {
	if t == nil || pid <= 0 {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if state := t.tracees[int(pid)]; state != nil && state.SessionID != "" {
		return state.SessionID, true
	}
	for _, state := range t.tracees {
		if state != nil && state.TGID == int(pid) && state.SessionID != "" {
			return state.SessionID, true
		}
	}
	return "", false
}
```

- [ ] **Step 5: Add Postgres session auth API**

In `internal/db/proxy/postgres/server.go`, add near `Config`:

```go
type SessionResolver interface {
	ResolveSessionID(pid int32) (string, bool)
}
```

Add to `Config`:

```go
	AgentSessionID  string
	SessionResolver SessionResolver
```

Remove the `uidAllowed` field from `Server`.

In `New`, after sink/services validation for non-off mode:

```go
	if cfg.AgentSessionID == "" {
		return nil, errors.New("postgres.New: AgentSessionID is required when Unavoidability != off")
	}
	if cfg.SessionResolver == nil {
		return nil, errors.New("postgres.New: SessionResolver is required when Unavoidability != off")
	}
```

Do not require these fields in sentinel off mode.

- [ ] **Step 6: Replace UID check in `handleConn`**

In `internal/db/proxy/postgres/server.go`, change the auth block to:

```go
	uid, pid, err := readPeerCred(conn)
	if err != nil {
		s.emitListenerAuthFail(ctx, svc, 0, 0, "", "peercred_read_failed")
		_ = conn.Close()
		return
	}
	peerSessionID, ok := s.cfg.SessionResolver.ResolveSessionID(pid)
	if !ok {
		s.emitListenerAuthFail(ctx, svc, uid, pid, "", "session_unknown")
		_ = conn.Close()
		return
	}
	if peerSessionID != s.cfg.AgentSessionID {
		s.emitListenerAuthFail(ctx, svc, uid, pid, peerSessionID, "session_mismatch")
		_ = conn.Close()
		return
	}
```

Update `emitListenerAuthFail` signature and event construction:

```go
func (s *Server) emitListenerAuthFail(ctx context.Context, svc Service, uid uint32, pid int32, peerSessionID string, reason string) {
	ev := events.LifecycleEvent{
		EventID:       newEventID(),
		Timestamp:     time.Now().UTC(),
		DBService:     svc.Name,
		Kind:          "db_listener_auth_fail",
		Reason:        reason,
		PeerUID:       uid,
		PeerPID:       pid,
		PeerSessionID: peerSessionID,
	}
	if err := s.cfg.Sink.EmitLifecycle(ctx, ev); err != nil {
		s.logger.Warn("postgres.Server: emit listener auth fail", "error", err)
	}
}
```

- [ ] **Step 7: Keep non-Linux config compiling**

In `internal/db/proxy/postgres/stub_other.go`, add the same `SessionResolver` interface and `AgentSessionID` / `SessionResolver` config fields.

- [ ] **Step 8: Update Postgres tests**

In `internal/db/proxy/postgres/peercred_linux_test.go`, replace the UID mismatch test with resolver-focused tests:

```go
type staticResolver map[int32]string

func (r staticResolver) ResolveSessionID(pid int32) (string, bool) {
	v, ok := r[pid]
	return v, ok
}

func allowCurrentProcessResolver(sessionID string) staticResolver {
	return staticResolver{int32(os.Getpid()): sessionID}
}
```

Use `AgentSessionID: "session-appdb"` and `SessionResolver: allowCurrentProcessResolver("session-appdb")` for success-path tests. Add two auth failure tests:

```go
func TestServer_PeerSessionUnknown_ClosesAndEmitsLifecycle(t *testing.T) {
	// Configure SessionResolver: staticResolver{}.
	// Dial the Unix socket.
	// Assert one lifecycle event with Kind "db_listener_auth_fail" and Reason "session_unknown".
}

func TestServer_PeerSessionMismatch_ClosesAndEmitsLifecycle(t *testing.T) {
	// Configure AgentSessionID "session-appdb" and resolver mapping current pid to "session-other".
	// Dial the Unix socket.
	// Assert Reason "session_mismatch" and PeerSessionID "session-other".
}
```

Use the same wait/drain pattern already present in `TestServer_PeercredMismatch_ClosesAndEmitsLifecycle`.

- [ ] **Step 9: Run and commit**

Run:

```bash
go test ./internal/db/events ./internal/ptrace ./internal/db/proxy/postgres -run 'TestLifecycleEvent|TestTracerResolveSessionID|TestServer_.*Session' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/db/events/lifecycle.go internal/db/events/lifecycle_test.go internal/db/proxy/postgres/server.go internal/db/proxy/postgres/stub_other.go internal/db/proxy/postgres/peercred_linux_test.go internal/db/proxy/postgres/server_test.go internal/ptrace/tracer.go internal/ptrace/tracer_test.go internal/api/app_ptrace_linux.go
git commit -m "feat: authorize db listener peers by session"
```

---

### Task 5: Add DB Bypass Event Mapper And Dedupe

**Files:**
- Create: `internal/db/events/bypass.go`
- Create: `internal/db/events/bypass_test.go`

- [ ] **Step 1: Write failing bypass event tests**

Create `internal/db/events/bypass_test.go`:

```go
package events

import (
	"context"
	"testing"
	"time"

	dbservice "github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

type captureAuditEmitter struct {
	events []types.Event
}

func (c *captureAuditEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	c.events = append(c.events, ev)
	return nil
}

func (c *captureAuditEmitter) Publish(types.Event) {}

func testEngineWithMetadata(t *testing.T) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		Metadata: []policy.RuleMetadata{{
			RuleName:    "db-appdb-deny-direct",
			Source:      dbservice.RuleSourceDBUnavoidability,
			DBService:   "appdb",
			BypassMode:  dbservice.BypassModeTCPDirect,
			Destination: "db.internal:5432",
		}},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestBypassEmitter_EmitsDBUnavoidabilityDeny(t *testing.T) {
	capture := &captureAuditEmitter{}
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	emitter := NewBypassEmitter(capture, WithBypassNow(func() time.Time { return now }))

	emitted := emitter.EmitIfDBUnavoidabilityDeny(context.Background(), BypassAttempt{
		Engine:          testEngineWithMetadata(t),
		SessionID:       "session-1",
		CommandID:       "cmd-1",
		ProcessID:       4242,
		ProcessIdentity: "pid:4242",
		RuleName:        "db-appdb-deny-direct",
		Reason:          "direct database egress is blocked",
	})
	if !emitted {
		t.Fatal("EmitIfDBUnavoidabilityDeny returned false, want true")
	}
	if len(capture.events) != 1 {
		t.Fatalf("events len = %d, want 1", len(capture.events))
	}
	ev := capture.events[0]
	if ev.Type != "db_bypass_attempt" || ev.SessionID != "session-1" || ev.CommandID != "cmd-1" || ev.PID != 4242 {
		t.Fatalf("unexpected event identity: %+v", ev)
	}
	if ev.Fields["db_service"] != "appdb" || ev.Fields["bypass_mode"] != dbservice.BypassModeTCPDirect {
		t.Fatalf("unexpected fields: %+v", ev.Fields)
	}
	if ev.Fields["destination"] != "db.internal:5432" || ev.Fields["suppressed_count"] != 0 {
		t.Fatalf("unexpected destination/dedupe fields: %+v", ev.Fields)
	}
}

func TestBypassEmitter_IgnoresNonDBRule(t *testing.T) {
	capture := &captureAuditEmitter{}
	emitter := NewBypassEmitter(capture)
	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	emitted := emitter.EmitIfDBUnavoidabilityDeny(context.Background(), BypassAttempt{
		Engine:          engine,
		SessionID:       "session-1",
		ProcessIdentity: "pid:1",
		RuleName:        "ordinary-deny",
	})
	if emitted {
		t.Fatal("emitted non-DB rule")
	}
	if len(capture.events) != 0 {
		t.Fatalf("events len = %d, want 0", len(capture.events))
	}
}

func TestBypassEmitter_DedupesForWindow(t *testing.T) {
	capture := &captureAuditEmitter{}
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	emitter := NewBypassEmitter(capture, WithBypassNow(func() time.Time { return now }))
	engine := testEngineWithMetadata(t)

	attempt := BypassAttempt{
		Engine:          engine,
		SessionID:       "session-1",
		ProcessID:       4242,
		ProcessIdentity: "pid:4242",
		RuleName:        "db-appdb-deny-direct",
	}
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("first event suppressed")
	}
	if emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("duplicate inside window emitted")
	}
	now = now.Add(61 * time.Second)
	if !emitter.EmitIfDBUnavoidabilityDeny(context.Background(), attempt) {
		t.Fatal("event after window suppressed")
	}
	if len(capture.events) != 2 {
		t.Fatalf("events len = %d, want 2", len(capture.events))
	}
	if got := capture.events[1].Fields["suppressed_count"]; got != 1 {
		t.Fatalf("second suppressed_count = %v, want 1", got)
	}
}
```

- [ ] **Step 2: Run failing tests**

Run:

```bash
go test ./internal/db/events -run 'TestBypassEmitter' -count=1
```

Expected: FAIL with undefined `BypassEmitter`, `BypassAttempt`, `NewBypassEmitter`, and `WithBypassNow`.

- [ ] **Step 3: Implement bypass mapper**

Create `internal/db/events/bypass.go`:

```go
package events

import (
	"context"
	"sync"
	"time"

	dbservice "github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

const bypassDedupeWindow = 60 * time.Second

type AuditEmitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

type BypassAttempt struct {
	Engine          *policy.Engine
	SessionID       string
	CommandID       string
	ProcessID       int
	ProcessIdentity string
	RuleName        string
	Reason          string
}

type BypassEmitterOption func(*BypassEmitter)

func WithBypassNow(now func() time.Time) BypassEmitterOption {
	return func(b *BypassEmitter) {
		if now != nil {
			b.now = now
		}
	}
}

type BypassEmitter struct {
	emit AuditEmitter
	now  func() time.Time

	mu      sync.Mutex
	windows map[bypassKey]bypassState
}

type bypassKey struct {
	sessionID       string
	processIdentity string
	destination     string
}

type bypassState struct {
	windowStart time.Time
	suppressed  int
}

func NewBypassEmitter(emit AuditEmitter, opts ...BypassEmitterOption) *BypassEmitter {
	b := &BypassEmitter{
		emit:    emit,
		now:     func() time.Time { return time.Now().UTC() },
		windows: make(map[bypassKey]bypassState),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

func (b *BypassEmitter) EmitIfDBUnavoidabilityDeny(ctx context.Context, in BypassAttempt) bool {
	if b == nil || b.emit == nil || in.Engine == nil || in.SessionID == "" || in.RuleName == "" {
		return false
	}
	meta, ok := RuleMetadataFor(in.Engine, in.RuleName)
	if !ok || meta.Source != dbservice.RuleSourceDBUnavoidability {
		return false
	}
	now := b.now().UTC()
	processIdentity := in.ProcessIdentity
	if processIdentity == "" && in.ProcessID > 0 {
		processIdentity = "pid:" + strconv.Itoa(in.ProcessID)
	}
	if processIdentity == "" {
		processIdentity = "unknown"
	}
	key := bypassKey{sessionID: in.SessionID, processIdentity: processIdentity, destination: meta.Destination}

	suppressedCount, emit := b.record(key, now)
	if !emit {
		return false
	}

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: now,
		Type:      "db_bypass_attempt",
		SessionID: in.SessionID,
		CommandID: in.CommandID,
		PID:       in.ProcessID,
		Fields: map[string]any{
			"process_identity": processIdentity,
			"db_service":       meta.DBService,
			"rule_name":        meta.RuleName,
			"bypass_mode":      meta.BypassMode,
			"destination":      meta.Destination,
			"reason":           in.Reason,
			"suppressed_count": suppressedCount,
		},
		Policy: &types.PolicyInfo{
			Decision:          types.DecisionDeny,
			EffectiveDecision: types.DecisionDeny,
			Rule:              in.RuleName,
		},
	}
	_ = b.emit.AppendEvent(ctx, ev)
	b.emit.Publish(ev)
	return true
}

func (b *BypassEmitter) record(key bypassKey, now time.Time) (int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(now)
	state, ok := b.windows[key]
	if ok && now.Sub(state.windowStart) < bypassDedupeWindow {
		state.suppressed++
		b.windows[key] = state
		return 0, false
	}
	suppressed := 0
	if ok {
		suppressed = state.suppressed
	}
	b.windows[key] = bypassState{windowStart: now}
	return suppressed, true
}

func (b *BypassEmitter) pruneLocked(now time.Time) {
	for key, state := range b.windows {
		if now.Sub(state.windowStart) > 2*bypassDedupeWindow {
			delete(b.windows, key)
		}
	}
}

func RuleMetadataFor(engine *policy.Engine, ruleName string) (policy.RuleMetadata, bool) {
	if engine == nil || ruleName == "" {
		return policy.RuleMetadata{}, false
	}
	pol := engine.Policy()
	if pol == nil {
		return policy.RuleMetadata{}, false
	}
	for _, meta := range pol.Metadata {
		if meta.RuleName == ruleName {
			return meta, true
		}
	}
	return policy.RuleMetadata{}, false
}
```

Add `strconv` to the imports in that file.

- [ ] **Step 4: Run and commit**

Run:

```bash
go test ./internal/db/events -run 'TestBypassEmitter' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/db/events/bypass.go internal/db/events/bypass_test.go
git commit -m "feat: add db bypass event dedupe"
```

---

### Task 6: Wire Session Creation To Generate Bundle And Start Proxy

**Files:**
- Modify: `internal/api/core.go`
- Modify: `internal/api/db_unavoidability_test.go`
- Modify: `internal/api/app.go`

- [ ] **Step 1: Write failing session creation runtime bundle test**

Append to `internal/api/db_unavoidability_test.go`:

```go
func TestCreateSessionCore_DBUnavoidabilityAddsGeneratedMetadata(t *testing.T) {
	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "default.yaml")
	raw := []byte(`
version: 1
name: db-runtime-test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: 127.0.0.1:5432
    tls_mode: terminate_reissue
policies:
  db:
    unavoidability: observe
`)
	if err := os.WriteFile(policyPath, raw, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Sessions.BaseDir = t.TempDir()
	cfg.Policies.Dir = policyDir
	cfg.Policies.Default = "default"

	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	engine, err := rootpolicy.NewEngine(&rootpolicy.Policy{Version: 1, Name: "global"}, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	app := NewApp(cfg, mgr, store, engine, events.NewBroker(), nil, nil, nil, nil, nil, nil)
	app.dbProxySessionResolverForTest = fakeSessionResolver{}

	snap, code, err := app.createSessionCore(context.Background(), types.CreateSessionRequest{
		ID:        "session-db-runtime",
		Workspace: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("createSessionCore: %v", err)
	}
	if code != http.StatusCreated {
		t.Fatalf("code = %d, want %d", code, http.StatusCreated)
	}
	s, ok := mgr.Get(snap.ID)
	if !ok {
		t.Fatal("session not found")
	}
	pol := s.PolicyEngine().Policy()
	found := false
	for _, meta := range pol.Metadata {
		if meta.Source == dbservice.RuleSourceDBUnavoidability && meta.DBService == "appdb" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("generated DB metadata not found: %+v", pol.Metadata)
	}
	if s.DBProxySocketDir() == "" {
		t.Fatal("DBProxySocketDir is empty")
	}
	app.cleanupCreatedSession(s)
}
```

Add this test helper in the same file:

```go
type fakeSessionResolver map[string]string

func (f fakeSessionResolver) ResolveSessionID(pid int32) (string, bool) {
	return "session-db-runtime", true
}
```

Add imports used by the test:

```go
	"context"
	"net/http"
	"os"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
```

- [ ] **Step 2: Run failing test**

Run:

```bash
go test ./internal/api -run TestCreateSessionCore_DBUnavoidabilityAddsGeneratedMetadata -count=1
```

Expected: FAIL because `createSessionCore` still compiles the base policy before the session ID exists and does not call the runtime bundle helper.

- [ ] **Step 3: Reorder `createSessionCore` policy loading and compilation**

In `internal/api/core.go`, replace the local `engine` compile block with:

```go
	var basePolicy *policy.Policy
	if a.cfg.Policies.Dir != "" {
		policyPath, err := policy.ResolvePolicyPath(a.cfg.Policies.Dir, policyName)
		if err != nil {
			return types.Session{}, http.StatusBadRequest, fmt.Errorf("resolve policy: %w", err)
		}
		policyData, err := os.ReadFile(policyPath)
		if err != nil {
			return types.Session{}, http.StatusInternalServerError, fmt.Errorf("read policy: %w", err)
		}
		// Keep the existing signature verification block here unchanged.
		pol, err := policy.LoadFromBytes(policyData)
		if err != nil {
			return types.Session{}, http.StatusInternalServerError, fmt.Errorf("load policy: %w", err)
		}
		basePolicy = pol
	} else if a.policy != nil {
		basePolicy = a.policy.Policy()
	}
```

After session creation and before `s.SetPolicyEngine`, add:

```go
	enforceApprovals := a.cfg.Approvals.Enabled && a.cfg.Approvals.Mode != ""
	engine, dbRules, dbStateDir, err := a.compileDBPolicyForSession(ctx, s, basePolicy, policyVars, enforceApprovals)
	if err != nil {
		a.cleanupCreatedSession(s)
		return types.Session{}, http.StatusBadRequest, err
	}
	s.ProjectRoot = policyVars["PROJECT_ROOT"]
	s.GitRoot = policyVars["GIT_ROOT"]
	s.SetPolicyEngine(engine)
	if err := a.startSessionDBProxy(ctx, s, dbRules, dbStateDir); err != nil {
		a.cleanupCreatedSession(s)
		return types.Session{}, http.StatusInternalServerError, fmt.Errorf("start db proxy: %w", err)
	}
```

Remove the old pre-session `policy.NewEngineWithVariables` call and the old later `s.SetPolicyEngine(engine)` assignment so the engine is compiled exactly once.

- [ ] **Step 4: Make cleanup use the helper**

In `createSessionCore`, replace direct cleanup calls after session creation with `a.cleanupCreatedSession(s)`. The TOTP failure block becomes:

```go
			a.cleanupCreatedSession(s)
			return types.Session{}, http.StatusInternalServerError, fmt.Errorf("generate TOTP secret: %w", err)
```

- [ ] **Step 5: Run and commit**

Run:

```bash
go test ./internal/api -run 'TestDBServiceConfigFromProxyServices|TestMergeDBUnavoidabilityBundle_SessionLocalCopy|TestCreateSessionCore_DBUnavoidabilityAddsGeneratedMetadata' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/api/core.go internal/api/app.go internal/api/db_unavoidability.go internal/api/db_unavoidability_test.go
git commit -m "feat: wire db unavoidability bundle at session runtime"
```

---

### Task 7: Emit DB Bypass Attempts From Ptrace

**Files:**
- Modify: `internal/api/app.go`
- Modify: `internal/api/app_ptrace_linux.go`
- Modify: `internal/api/ptrace_handlers.go`
- Modify: `internal/api/ptrace_handlers_test.go`

- [ ] **Step 1: Add DB bypass emitter to App and router**

In `internal/api/app.go`, add to `App`:

```go
	dbBypass *dbevents.BypassEmitter
```

Add `dbevents "github.com/agentsh/agentsh/internal/db/events"` to imports.

In `NewApp`, initialize:

```go
		dbBypass: dbevents.NewBypassEmitter(storeEmitter{store: store, broker: broker}),
```

In `internal/api/app_ptrace_linux.go`, set the router field:

```go
		dbBypass:           a.dbBypass,
```

In `internal/api/ptrace_handlers.go`, add to `ptraceHandlerRouter`:

```go
	dbBypass *dbevents.BypassEmitter
```

- [ ] **Step 2: Write failing ptrace bypass test**

Append to `internal/api/ptrace_handlers_test.go`:

```go
func TestHandleNetwork_DBUnavoidabilityDenyEmitsBypassAttempt(t *testing.T) {
	router, mgr := newTestRouter(t, "")
	capture := &captureAuditEmitter{}
	router.dbBypass = dbevents.NewBypassEmitter(capture)
	sess, err := mgr.CreateWithID("session-db-bypass", t.TempDir(), "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "db-bypass",
		NetworkRules: []policy.NetworkRule{{
			Name:     "db-appdb-deny-direct",
			Domains:  []string{"db.internal"},
			Ports:    []int{5432},
			Decision: "deny",
		}},
		Metadata: []policy.RuleMetadata{{
			RuleName:    "db-appdb-deny-direct",
			Source:      dbservice.RuleSourceDBUnavoidability,
			DBService:   "appdb",
			BypassMode:  dbservice.BypassModeTCPDirect,
			Destination: "db.internal:5432",
		}},
	}, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	sess.SetPolicyEngine(engine)

	result := router.HandleNetwork(context.Background(), ptrace.NetworkContext{
		SessionID: sess.ID,
		PID:       4242,
		Address:   "db.internal",
		Port:      5432,
		Operation: "connect",
	})
	if result.Allow || result.Action != "deny" {
		t.Fatalf("result = %+v, want deny", result)
	}
	if len(capture.events) != 1 {
		t.Fatalf("bypass events len = %d, want 1", len(capture.events))
	}
	if capture.events[0].Type != "db_bypass_attempt" {
		t.Fatalf("event type = %q, want db_bypass_attempt", capture.events[0].Type)
	}
}
```

Import aliases:

```go
	dbevents "github.com/agentsh/agentsh/internal/db/events"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
```

Use the `captureAuditEmitter` from `internal/db/events/bypass_test.go` as a local copy in this test file because test packages cannot share unexported helpers.

- [ ] **Step 3: Implement ptrace emission helper**

In `internal/api/ptrace_handlers.go`, add:

```go
func (r *ptraceHandlerRouter) emitDBBypassAttempt(ctx context.Context, pe *policy.Engine, sessionID string, commandID string, pid int, ruleName string, reason string) {
	if r == nil || r.dbBypass == nil {
		return
	}
	r.dbBypass.EmitIfDBUnavoidabilityDeny(ctx, dbevents.BypassAttempt{
		Engine:          pe,
		SessionID:       sessionID,
		CommandID:       commandID,
		ProcessID:       pid,
		ProcessIdentity: fmt.Sprintf("pid:%d", pid),
		RuleName:        ruleName,
		Reason:          reason,
	})
}
```

Add imports for `fmt` and `dbevents`.

In `HandleExecve`, before returning a deny result:

```go
		r.emitDBBypassAttempt(ctx, pe, ec.SessionID, "", ec.PID, decision.Rule, decision.Message)
```

In `HandleNetwork`, before returning a deny result:

```go
		r.emitDBBypassAttempt(ctx, pe, nc.SessionID, "", nc.PID, decision.Rule, decision.Message)
```

- [ ] **Step 4: Run and commit**

Run:

```bash
go test ./internal/api -run 'TestHandleNetwork_DBUnavoidabilityDenyEmitsBypassAttempt|TestHandleNetwork_DnsRedirect|TestHandleFile_SoftDelete' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/api/app.go internal/api/app_ptrace_linux.go internal/api/ptrace_handlers.go internal/api/ptrace_handlers_test.go
git commit -m "feat: emit db bypass events from ptrace"
```

---

### Task 8: Emit DB Bypass Attempts From Network Proxies

**Files:**
- Modify: `internal/netmonitor/proxy.go`
- Modify: `internal/netmonitor/transparent_tcp.go`
- Modify: `internal/api/app.go`
- Test: `internal/netmonitor/proxy_test.go`

- [ ] **Step 1: Add optional emitter fields and setters**

In `internal/netmonitor/proxy.go`, import DB events:

```go
	dbevents "github.com/agentsh/agentsh/internal/db/events"
```

Add to `Proxy`:

```go
	dbBypass *dbevents.BypassEmitter
```

Add method:

```go
func (p *Proxy) SetDBBypassEmitter(e *dbevents.BypassEmitter) {
	p.dbBypass = e
}
```

In `internal/netmonitor/transparent_tcp.go`, add the same field and setter to `TransparentTCP`.

- [ ] **Step 2: Wire App startup**

In `internal/api/app.go`, after `StartProxy` succeeds in `startExplicitProxy`:

```go
	pr.SetDBBypassEmitter(a.dbBypass)
```

After `StartTransparentTCP` succeeds in `tryStartTransparentNetwork`:

```go
	tcp.SetDBBypassEmitter(a.dbBypass)
```

- [ ] **Step 3: Emit on deny**

In `Proxy.handleConnect`, in the deny block after publishing `connectEv`:

```go
	p.emitDBBypassAttempt(context.Background(), commandID, 0, dec.Rule, dec.Message)
```

In `Proxy.handleHTTP`, in the deny block after publishing `connectEv`:

```go
	p.emitDBBypassAttempt(context.Background(), commandID, 0, dec.Rule, dec.Message)
```

Add helper:

```go
func (p *Proxy) emitDBBypassAttempt(ctx context.Context, commandID string, pid int, ruleName string, reason string) {
	if p == nil || p.dbBypass == nil {
		return
	}
	processIdentity := "session:" + p.sessionID
	if commandID != "" {
		processIdentity = "command:" + commandID
	}
	p.dbBypass.EmitIfDBUnavoidabilityDeny(ctx, dbevents.BypassAttempt{
		Engine:          p.policy,
		SessionID:       p.sessionID,
		CommandID:       commandID,
		ProcessID:       pid,
		ProcessIdentity: processIdentity,
		RuleName:        ruleName,
		Reason:          reason,
	})
}
```

In `TransparentTCP.handle`, after publishing a deny event:

```go
	t.emitDBBypassAttempt(context.Background(), commandID, 0, dec.Rule, dec.Message)
```

Add the equivalent helper on `TransparentTCP`.

- [ ] **Step 4: Write proxy test**

Append a unit-level test to `internal/netmonitor/proxy_test.go` that constructs a `Proxy` with a policy containing one DB metadata deny rule, sets a capture `BypassEmitter`, calls `p.emitDBBypassAttempt`, and asserts one `db_bypass_attempt` event. Use the same policy metadata shape from Task 7.

- [ ] **Step 5: Run and commit**

Run:

```bash
go test ./internal/netmonitor -run 'Test.*DBBypass|TestConnectDialTarget' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/netmonitor/proxy.go internal/netmonitor/transparent_tcp.go internal/netmonitor/proxy_test.go internal/api/app.go
git commit -m "feat: emit db bypass events from network proxies"
```

---

### Task 9: Full Verification

**Files:**
- No source edits unless verification reveals a defect.

- [ ] **Step 1: Run focused test suites**

Run:

```bash
go test ./internal/db/service ./internal/db/events ./internal/db/proxy/postgres ./internal/api ./internal/netmonitor ./internal/ptrace ./internal/session -count=1
```

Expected: PASS.

- [ ] **Step 2: Run Windows compile**

Run:

```bash
GOOS=windows go build ./...
```

Expected: PASS.

- [ ] **Step 3: Run diff hygiene**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 4: Commit any verification fixes**

If a verification fix is needed, make the smallest code change that addresses the failing command, rerun the exact failing command, and commit:

```bash
git add <changed-files>
git commit -m "fix: complete db plan 07b verification"
```

If no fixes are needed, do not create an empty commit.

---

## Self-Review Notes

- Runtime bundle wiring is covered by Tasks 2 and 6.
- Listener SessionID auth is covered by Tasks 3 and 4.
- Ptrace PID-to-session resolver is covered by Task 4.
- DB bypass event mapping and dedupe are covered by Tasks 5, 7, and 8.
- Per-session proxy ownership is explicit because the old global proxy cannot enforce a single owning session ID.
- Real Postgres E2E remains outside this plan and starts 07c.
