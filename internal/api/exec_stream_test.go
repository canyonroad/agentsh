package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

func TestExecStream_EmitsStdoutAndDone(t *testing.T) {
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
	srv := httptest.NewServer(app.Router())
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"command": "sh", "args": []string{"-c", "echo hello"}})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/sessions/"+sess.ID+"/exec/stream", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.Contains(out, "event: stdout") {
		t.Fatalf("expected stdout event, got: %s", out)
	}
	if !strings.Contains(out, "event: done") {
		t.Fatalf("expected done event, got: %s", out)
	}
}
