package api

import (
	"encoding/json"
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

func TestCreateSession_HomeFieldPropagated(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	h := app.Router()

	reqBody := map[string]any{
		"id":        "sess_home",
		"workspace": ws,
		"policy":    "default",
		"home":      "/home/testuser",
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(string(bodyBytes)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var out types.Session
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.ID != "sess_home" {
		t.Fatalf("expected id sess_home, got %q", out.ID)
	}
	// HOME expansion correctness is verified by policy engine tests in
	// internal/policy/engine_vars_test.go (TestDenyPrecedenceWhenHomeEqualsProjectRoot).
	// This test verifies the HTTP plumbing accepts and propagates the field.
}

func TestCreateSessionRequestCompat_HomePropagated(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		wantHome string
	}{
		{
			name:     "absent",
			json:     `{"id":"s1","workspace":"/tmp","policy":"default"}`,
			wantHome: "",
		},
		{
			name:     "explicit value",
			json:     `{"id":"s1","workspace":"/tmp","policy":"default","home":"/home/testuser"}`,
			wantHome: "/home/testuser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var compat CreateSessionRequestCompat
			if err := json.Unmarshal([]byte(tt.json), &compat); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if compat.Home != tt.wantHome {
				t.Errorf("compat.Home = %q, want %q", compat.Home, tt.wantHome)
			}

			req := compat.ToTypes()
			if req.Home != tt.wantHome {
				t.Errorf("req.Home = %q after ToTypes(), want %q", req.Home, tt.wantHome)
			}
		})
	}
}

func TestCreateSessionRequestCompat_AllFieldsPropagated(t *testing.T) {
	input := `{
		"id": "s1",
		"workspace": "/tmp",
		"policy": "default",
		"profile": "restricted",
		"home": "/home/testuser",
		"detect_project_root": false,
		"project_root": "/opt/project",
		"real_paths": true
	}`

	var compat CreateSessionRequestCompat
	if err := json.Unmarshal([]byte(input), &compat); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	req := compat.ToTypes()
	if req.ID != "s1" {
		t.Errorf("ID = %q, want s1", req.ID)
	}
	if req.Profile != "restricted" {
		t.Errorf("Profile = %q, want restricted", req.Profile)
	}
	if req.Home != "/home/testuser" {
		t.Errorf("Home = %q, want /home/testuser", req.Home)
	}
	if req.DetectProjectRoot == nil || *req.DetectProjectRoot != false {
		t.Errorf("DetectProjectRoot = %v, want false", req.DetectProjectRoot)
	}
	if req.ProjectRoot != "/opt/project" {
		t.Errorf("ProjectRoot = %q, want /opt/project", req.ProjectRoot)
	}
	if req.RealPaths == nil || *req.RealPaths != true {
		t.Errorf("RealPaths = %v, want true", req.RealPaths)
	}
}
