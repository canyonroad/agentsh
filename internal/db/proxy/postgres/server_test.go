//go:build linux

package postgres

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

func TestServer_New_ZeroConfigRejected(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("New(Config{}): want error, got nil")
	}
}

func TestServer_OffMode_StartIsNoop(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityOff,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil server")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = s.Start(ctx)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start (off mode): %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown (off mode): %v", err)
	}
}

func TestServer_ObserveMode_RequiresAtLeastOneService(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	}
	cfg = withRequiredSessionAuth(cfg)
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New (observe, no services): want error, got nil")
	}
}

func TestServer_New_ObserveRequiresAgentSessionID(t *testing.T) {
	cfg := withRequiredSessionAuth(validServerConfig(t))
	cfg.AgentSessionID = ""
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "AgentSessionID") {
		t.Fatalf("New (observe, no AgentSessionID): err = %v, want AgentSessionID error", err)
	}
}

func TestServer_New_ObserveRequiresSessionResolver(t *testing.T) {
	cfg := withRequiredSessionAuth(validServerConfig(t))
	cfg.SessionResolver = nil
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "SessionResolver") {
		t.Fatalf("New (observe, no SessionResolver): err = %v, want SessionResolver error", err)
	}
}

func TestServer_New_EnforceRequiresSessionAuth(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.Unavoidability = service.UnavoidabilityEnforce
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "AgentSessionID") {
		t.Fatalf("New (enforce, missing auth): err = %v, want AgentSessionID error", err)
	}

	cfg.AgentSessionID = testAgentSessionID
	_, err = New(cfg)
	if err == nil || !strings.Contains(err.Error(), "SessionResolver") {
		t.Fatalf("New (enforce, missing resolver): err = %v, want SessionResolver error", err)
	}
}

func TestServer_New_OffModeDoesNotRequireSessionAuth(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityOff,
		StateDir:       t.TempDir(),
	}
	if _, err := New(cfg); err != nil {
		t.Fatalf("New (off, no session auth): %v", err)
	}
}

func TestServer_New_MissingSink(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "test-appdb.sock")},
			Service:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "db.internal:5432", TLSMode: "terminate_reissue"},
		}},
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New (no sink): want error, got nil")
	}
}

// testWriter wires slog output into t.Log so tests preserve context on failure.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

func TestServer_StartShutdown_BindsAndUnlinksUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "appdb.sock")
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: sockPath},
			Service:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
		}},
	}
	cfg = withRequiredSessionAuth(cfg)
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startErr := make(chan error, 1)
	go func() { startErr <- s.Start(ctx) }()

	// Wait until the socket exists.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(sockPath); err == nil && fi.Mode()&os.ModeSocket != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fi, err := os.Stat(sockPath); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket %q not bound: stat=%v, err=%v", sockPath, fi, err)
	}
	if fi, _ := os.Stat(sockPath); fi.Mode()&0777 != 0700 {
		t.Errorf("socket %q perms = %#o, want 0700", sockPath, fi.Mode()&0777)
	}

	// A Unix-socket dial should succeed and immediately see EOF (handler is no-op).
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Read(buf); err == nil || (err.Error() != "EOF" && !errors.Is(err, io.EOF) && !os.IsTimeout(err)) {
		t.Fatalf("Read after dial: err=%v, want EOF or close", err)
	}
	conn.Close()

	// Cancel context and assert Shutdown completes and unlinks the socket.
	cancel()
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-startErr; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start returned: %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket %q still present after Shutdown: stat err=%v", sockPath, err)
	}
}

func TestServer_StartTwice_ReturnsError(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Services: []Service{{
			Name:    "appdb",
			Dialect: "postgres",
			Listen:  ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "appdb.sock")},
			Service: policy.DBService{Name: "appdb"},
			TLSMode: "terminate_reissue",
		}},
	}
	cfg = withRequiredSessionAuth(cfg)
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	if err := s.Start(ctx); err == nil {
		t.Fatal("second Start: want error, got nil")
	}
}

func TestServer_New_AllowsPassthroughService(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "passthrough",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "x.sock")},
			Service:  policy.DBService{Name: "appdb", TLSMode: "passthrough"},
		}},
	}
	cfg = withRequiredSessionAuth(cfg)
	if _, err := New(cfg); err != nil {
		t.Fatalf("New (passthrough): want nil error, got %v", err)
	}
}

func TestServer_LazyCALoad(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       dir,
		Sink:           &events.SyncSink{},
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "appdb.sock")},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
	}
	cfg = withRequiredSessionAuth(cfg)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ca, err := srv.ca()
	if err != nil {
		t.Fatalf("ca() first call: %v", err)
	}
	if ca == nil {
		t.Fatal("ca() returned nil")
	}
	if _, err := os.Stat(filepath.Join(dir, "db-ca.crt")); err != nil {
		t.Errorf("db-ca.crt missing after lazy load: %v", err)
	}
	again, err := srv.ca()
	if err != nil {
		t.Fatalf("ca() second call: %v", err)
	}
	if again != ca {
		t.Error("ca() did not return cached pointer on second call")
	}
}

func TestServer_New_AppliesMaxQueryBytesDefault(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "appdb.sock")},
			Service:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
		}},
	}
	cfg = withRequiredSessionAuth(cfg)
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.cfg.MaxQueryBytes; got != 1<<20 {
		t.Fatalf("MaxQueryBytes default = %d want %d", got, 1<<20)
	}
}

func TestServer_New_HonorsMaxQueryBytesOverride(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		MaxQueryBytes:  4096,
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "appdb.sock")},
			Service:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
		}},
	}
	cfg = withRequiredSessionAuth(cfg)
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.cfg.MaxQueryBytes; got != 4096 {
		t.Fatalf("MaxQueryBytes = %d want 4096", got)
	}
}

func TestNew_DefaultsCancelMapConfig(t *testing.T) {
	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		AgentSessionID: testAgentSessionID,
		SessionResolver: staticResolver{
			sessionID: testAgentSessionID,
			ok:        true,
		},
		Policy: loadRuleSet(t, `version: 1
name: test
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_plaintext_upstream, trusted_network: true}
database_connection_rules:
  - {name: allow, db_service: appdb, decision: allow}
`),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "db.sock")},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.cancelMap == nil {
		t.Fatal("cancelMap is nil")
	}
	if srv.cfg.CancelMappingMax != defaultCancelMappingMax {
		t.Fatalf("CancelMappingMax = %d, want %d", srv.cfg.CancelMappingMax, defaultCancelMappingMax)
	}
	if srv.cfg.CancelGraceWindow != defaultCancelGraceWindow {
		t.Fatalf("CancelGraceWindow = %s, want %s", srv.cfg.CancelGraceWindow, defaultCancelGraceWindow)
	}
}

func TestServer_SetPolicy_AtomicSwap(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "appdb.sock")},
			Service:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
		}},
	}
	cfg = withRequiredSessionAuth(cfg)
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.policy(); got != nil {
		t.Fatalf("initial policy = %p want nil", got)
	}
	rs := &policy.RuleSet{}
	s.SetPolicy(rs)
	if got := s.policy(); got != rs {
		t.Fatalf("policy() after SetPolicy = %p want %p", got, rs)
	}
}

func TestServer_New_RejectsUnknownDialect(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "rabbitql", // unknown
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "appdb.sock")},
			Service:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "rabbitql", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
		}},
	}
	cfg = withRequiredSessionAuth(cfg)
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "rabbitql") {
		t.Fatalf("New on unknown dialect: err = %v", err)
	}
}

const testAgentSessionID = "agent-session"

type staticResolver struct {
	sessionID string
	ok        bool
}

func (r staticResolver) ResolveSessionID(int32) (string, bool) {
	return r.sessionID, r.ok
}

func withRequiredSessionAuth(cfg Config) Config {
	cfg.AgentSessionID = testAgentSessionID
	cfg.SessionResolver = staticResolver{sessionID: testAgentSessionID, ok: true}
	return cfg
}

func validServerConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "appdb.sock")},
			Service:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
		}},
	}
}
