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

	// Create session with explicit home value
	body := `{"id":"sess_home","workspace":"` + ws + `","policy":"default","home":"/home/testuser"}`
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
	if out.ID != "sess_home" {
		t.Fatalf("expected id sess_home, got %q", out.ID)
	}
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
