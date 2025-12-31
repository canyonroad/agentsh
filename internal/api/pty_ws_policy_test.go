package api

import (
	"encoding/json"
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
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/gorilla/websocket"
)

func TestPTYWebSocket_RespectsCommandPolicyDeny(t *testing.T) {
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
			{Name: "deny-sh", Commands: []string{"sh"}, Decision: string(types.DecisionDeny)},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, metrics.New(), nil)

	srv := newHTTPTestServerOrSkip(t, app.Router())

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/sessions/" + sess.ID + "/pty"
	d := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	c, _, err := d.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	start := map[string]any{
		"type":    "start",
		"command": "sh",
		"args":    []string{"-lc", "printf hi"},
		"rows":    24,
		"cols":    80,
	}
	b, _ := json.Marshal(start)
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatal(err)
	}

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	mt, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("expected text message error, got mt=%d msg=%q", mt, string(msg))
	}
	var m map[string]any
	if err := json.Unmarshal(msg, &m); err != nil {
		t.Fatalf("invalid json: %v (%q)", err, string(msg))
	}
	if m["type"] != "error" {
		t.Fatalf("expected type=error, got %v (%q)", m["type"], string(msg))
	}
}
