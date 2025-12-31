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

func TestExec_IncludeEventsNone_ReturnsCountsOnly(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	h := app.Router()

	body := `{"command":"echo","args":["hi"],"include_events":"none"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp types.ExecResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Result.ExitCode != 0 {
		t.Fatalf("expected exit_code 0, got %d", resp.Result.ExitCode)
	}
	if resp.Events.Truncated != true {
		t.Fatalf("expected events.truncated true")
	}
	if len(resp.Events.FileOperations) != 0 || len(resp.Events.NetworkOperations) != 0 || len(resp.Events.BlockedOperations) != 0 || len(resp.Events.Other) != 0 {
		t.Fatalf("expected no events returned in arrays")
	}
	if resp.Events.OtherCount == 0 {
		t.Fatalf("expected other_count > 0")
	}
	if resp.Guidance == nil || resp.Guidance.Status != "ok" {
		t.Fatalf("expected guidance.status ok, got %+v", resp.Guidance)
	}
}

func TestExec_IncludeEventsSummary_CapsBlockedOps(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.Network.Transparent.Enabled = false
	cfg.Policies.Default = "default"

	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, metrics.New(), nil)
	h := app.Router()

	// Trigger a command policy deny (rm -rf) which returns blocked_operations in response.
	body := `{"command":"rm","args":["-rf","/tmp/agentsh-test"],"include_events":"summary"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp types.ExecResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Guidance == nil || resp.Guidance.Status != "blocked" || !resp.Guidance.Blocked {
		t.Fatalf("expected blocked guidance, got %+v", resp.Guidance)
	}
	if len(resp.Events.BlockedOperations) == 0 {
		t.Fatalf("expected blocked_operations in summary mode")
	}
	if resp.Events.BlockedOperationsCount < len(resp.Events.BlockedOperations) {
		t.Fatalf("expected blocked_operations_count >= returned blocked_operations length")
	}
	if len(resp.Events.FileOperations) != 0 || len(resp.Events.NetworkOperations) != 0 {
		t.Fatalf("expected file/network ops omitted in summary mode")
	}
}
