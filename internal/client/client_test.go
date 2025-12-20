package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestDoJSONSuccessAndAuthHeader(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sessions" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req types.CreateSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(types.Session{ID: "abc", Policy: req.Policy, Workspace: req.Workspace})
	}))
	defer srv.Close()

	c := New(srv.URL, "secret")
	sess, err := c.CreateSession(context.Background(), "ws", "pol")
	if err != nil {
		t.Fatalf("CreateSession error: %v", err)
	}
	if gotKey != "secret" {
		t.Fatalf("expected X-API-Key header, got %q", gotKey)
	}
	if sess.ID != "abc" || sess.Workspace != "ws" || sess.Policy != "pol" {
		t.Fatalf("unexpected session response: %+v", sess)
	}
}

func TestDoJSONHandlesErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	err := c.doJSON(context.Background(), http.MethodGet, "/bad", nil, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("expected HTTPError, got %T", err)
	}
	if httpErr.StatusCode != 500 || httpErr.Body == "" {
		t.Fatalf("unexpected HTTPError: %+v", httpErr)
	}
}

func TestDoJSONNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if err := c.doJSON(context.Background(), http.MethodPost, "/empty", nil, map[string]any{}, nil); err != nil {
		t.Fatalf("doJSON returned error: %v", err)
	}
}

func TestUnixSchemeUsesUnixDialer(t *testing.T) {
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "srv.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer l.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]types.Session{{ID: "unix"}})
		}),
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Shutdown(context.Background()) })

	c := New("unix://"+sock, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sessions, err := c.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions via unix socket: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != "unix" {
		t.Fatalf("unexpected sessions: %+v", sessions)
	}
}

func TestStreamSessionEventsNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	rc, err := c.StreamSessionEvents(context.Background(), "sess")
	if err == nil {
		rc.Close()
		t.Fatal("expected error for non-2xx")
	}
}

func TestStreamSessionEventsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: hello\n\n"))
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	rc, err := c.StreamSessionEvents(context.Background(), "sess")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	defer rc.Close()
	buf := make([]byte, 5)
	n, err := rc.Read(buf)
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("unexpected read err: %v", err)
	}
	if n == 0 {
		t.Fatalf("expected to read some data from stream")
	}
}
