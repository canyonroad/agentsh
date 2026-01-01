package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
)

func newTestApp(t *testing.T, sessions *session.Manager, store *composite.Store) *App {
	t.Helper()
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.Network.Transparent.Enabled = false
	cfg.Policies.Default = "default"

	// Create an allow-all policy for tests
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
		},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	return NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, metrics.New(), nil)
}

func newSQLiteStore(t *testing.T) *sqlite.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := sqlite.Open(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestPatchSession_UpdatesCwdAndEnv(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	h := app.Router()

	reqBody := `{"cwd":"/workspace/sub","env":{"FOO":"bar"},"unset":["BAZ"]}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/sessions/"+s.ID, strings.NewReader(reqBody))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var out types.Session
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Cwd != "/workspace/sub" {
		t.Fatalf("expected cwd /workspace/sub, got %q", out.Cwd)
	}
	_, env, _ := s.GetCwdEnvHistory()
	if env["FOO"] != "bar" {
		t.Fatalf("expected env FOO=bar, got %q", env["FOO"])
	}
}

func TestKillCommand_KillsRunningExec(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	h := app.Router()

	execDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		body := `{"command":"sleep","args":["30"]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+s.ID+"/exec", strings.NewReader(body))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		execDone <- rr
	}()

	deadline := time.Now().Add(3 * time.Second)
	var cmdID string
	for time.Now().Before(deadline) {
		cmdID = s.CurrentCommandID()
		if cmdID != "" && s.CurrentProcessPID() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cmdID == "" {
		t.Fatalf("expected running command id, got empty")
	}

	killReq := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+s.ID+"/kill/"+cmdID, strings.NewReader(`{}`))
	killRR := httptest.NewRecorder()
	h.ServeHTTP(killRR, killReq)
	if killRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from kill, got %d: %s", killRR.Code, killRR.Body.String())
	}

	select {
	case rr := <-execDone:
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 from exec, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp types.ExecResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if resp.Result.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code after kill")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("exec did not return after kill")
	}
}
