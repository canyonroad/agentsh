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
)

func TestCreateSession_RequestTooLargeReturns413(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Tiny limit to force the MaxBytesError path.
		r.Body = http.MaxBytesReader(w, r.Body, 32)
		app.Router().ServeHTTP(w, r)
	})

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	// Use json.Marshal to properly escape paths (especially Windows backslashes)
	reqBody := map[string]string{
		"workspace": ws,
		"policy":    "default",
		"pad":       strings.Repeat("x", 200),
	}
	bodyBytes, _ := json.Marshal(reqBody)
	body := string(bodyBytes)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rr.Code, rr.Body.String())
	}
}
