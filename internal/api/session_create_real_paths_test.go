package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestCreateSession_RealPaths_RequestOverride(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	h := app.Router()

	body := fmt.Sprintf(`{"id":"real-paths-test","workspace":%q,"policy":"default","real_paths":true}`, ws)
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

	// When real_paths is true, Cwd should be the real workspace path, not /workspace
	absWs, _ := filepath.Abs(ws)
	wantCwd := filepath.ToSlash(filepath.Clean(absWs))
	if out.Cwd != wantCwd {
		t.Errorf("Cwd = %q, want %q (real workspace path)", out.Cwd, wantCwd)
	}
}

func TestCreateSession_RealPaths_ConfigDefault(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create app with RealPaths config default enabled
	app := newTestApp(t, sessions, store)
	app.cfg.Sessions.RealPaths = true

	h := app.Router()

	// Request WITHOUT real_paths field — should use config default (true)
	body := fmt.Sprintf(`{"id":"config-default-test","workspace":%q,"policy":"default"}`, ws)
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

	absWs, _ := filepath.Abs(ws)
	wantCwd := filepath.ToSlash(filepath.Clean(absWs))
	if out.Cwd != wantCwd {
		t.Errorf("Cwd = %q, want %q (config default real_paths=true)", out.Cwd, wantCwd)
	}
}

func TestCreateSession_RealPaths_RequestOverrideFalse(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}

	// Config default is true, but request says false
	app := newTestApp(t, sessions, store)
	app.cfg.Sessions.RealPaths = true

	h := app.Router()

	body := fmt.Sprintf(`{"id":"override-false-test","workspace":%q,"policy":"default","real_paths":false}`, ws)
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

	// Request override false should keep /workspace
	if out.Cwd != "/workspace" {
		t.Errorf("Cwd = %q, want /workspace (request override false)", out.Cwd)
	}
}
