package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/gorilla/websocket"
)

func TestPTYWebSocket_RequiresUpgrade(t *testing.T) {
	db := newSQLiteStore(t)
	store := composite.New(db, db)
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sess.ID+"/pty", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestPTYWebSocket_StartAndExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY tests require Unix shell")
	}
	db := newSQLiteStore(t)
	store := composite.New(db, db)
	sessions := session.NewManager(10)

	wsDir := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(wsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(wsDir, "default")
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	srv := newHTTPTestServerOrSkip(t, app.Router())

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/sessions/" + sess.ID + "/pty"
	d := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	c, _, err := d.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	start := map[string]any{
		"type": "start",
		// Non-interactive command executed under a PTY.
		"command": "sh",
		"args":    []string{"-lc", "printf hi"},
		"rows":    24,
		"cols":    80,
	}
	b, _ := json.Marshal(start)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var out strings.Builder
	var exitCode *int
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		mt, msg, err := c.ReadMessage()
		if err != nil {
			break
		}
		switch mt {
		case websocket.BinaryMessage:
			out.Write(msg)
		case websocket.TextMessage:
			var m map[string]any
			if err := json.Unmarshal(msg, &m); err != nil {
				continue
			}
			if m["type"] == "exit" {
				if v, ok := m["exit_code"].(float64); ok {
					ic := int(v)
					exitCode = &ic
				}
				goto done
			}
		}
	}
done:
	if exitCode == nil {
		t.Fatalf("expected exit message, got output=%q", out.String())
	}
	if *exitCode != 0 {
		t.Fatalf("expected exit_code 0, got %d (output=%q)", *exitCode, out.String())
	}
	if out.String() != "hi" {
		t.Fatalf("expected output hi, got %q", out.String())
	}
}
