package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestServer_GRPC_ExecStream(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create allow-all policy for tests
	policyContent := `version: 1
name: default
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: ["*"]
    decision: allow
`
	if err := os.WriteFile(filepath.Join(policyDir, "default.yaml"), []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(dir, "ws")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Server.GRPC.Enabled = true
	cfg.Server.GRPC.Addr = "127.0.0.1:0"
	cfg.Sessions.BaseDir = filepath.Join(dir, "sessions")
	cfg.Audit.Storage.SQLitePath = filepath.Join(dir, "events.db")
	cfg.Policies.Dir = policyDir
	cfg.Policies.Default = "default"
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false

	s, err := New(cfg)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("listening not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	conn, err := grpc.Dial(s.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Create session.
	createReq, _ := structpb.NewStruct(map[string]any{"workspace": workspace, "policy": "default"})
	createResp := &structpb.Struct{}
	if err := conn.Invoke(ctx, "/agentsh.v1.Agentsh/CreateSession", createReq, createResp); err != nil {
		t.Fatal(err)
	}
	cb, _ := protojson.Marshal(createResp)
	var snap struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(cb, &snap)
	if snap.ID == "" {
		t.Fatalf("missing session id: %s", string(cb))
	}

	// ExecStream.
	req, _ := structpb.NewStruct(map[string]any{
		"session_id": snap.ID,
		"command":    "sh",
		"args":       []any{"-c", "echo hi"},
	})
	desc := &grpc.StreamDesc{ServerStreams: true}
	st, err := conn.NewStream(ctx, desc, "/agentsh.v1.Agentsh/ExecStream")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SendMsg(req); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseSend(); err != nil {
		t.Fatal(err)
	}

	var sawStdout bool
	var sawDone bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		msg := &structpb.Struct{}
		if err := st.RecvMsg(msg); err != nil {
			break
		}
		b, _ := protojson.Marshal(msg)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		ev, _ := m["event"].(string)
		switch ev {
		case "stdout":
			if strings.Contains(string(b), "hi") {
				sawStdout = true
			}
		case "done":
			if strings.Contains(string(b), "\"exit_code\":0") {
				sawDone = true
			}
		}
		if sawStdout && sawDone {
			break
		}
	}
	if !sawStdout {
		t.Fatalf("did not see stdout")
	}
	if !sawDone {
		t.Fatalf("did not see done")
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not exit after cancel")
	}
}

func TestServer_GRPC_EventsTail(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create allow-all policy for tests
	policyContent := `version: 1
name: default
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: ["*"]
    decision: allow
`
	if err := os.WriteFile(filepath.Join(policyDir, "default.yaml"), []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(dir, "ws")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Server.GRPC.Enabled = true
	cfg.Server.GRPC.Addr = "127.0.0.1:0"
	cfg.Sessions.BaseDir = filepath.Join(dir, "sessions")
	cfg.Audit.Storage.SQLitePath = filepath.Join(dir, "events.db")
	cfg.Policies.Dir = policyDir
	cfg.Policies.Default = "default"
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false

	s, err := New(cfg)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("listening not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	conn, err := grpc.Dial(s.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Create session.
	createReq, _ := structpb.NewStruct(map[string]any{"workspace": workspace, "policy": "default"})
	createResp := &structpb.Struct{}
	if err := conn.Invoke(ctx, "/agentsh.v1.Agentsh/CreateSession", createReq, createResp); err != nil {
		t.Fatal(err)
	}
	cb, _ := protojson.Marshal(createResp)
	var snap struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(cb, &snap)
	if snap.ID == "" {
		t.Fatalf("missing session id: %s", string(cb))
	}

	// Start tail.
	tailReq, _ := structpb.NewStruct(map[string]any{"session_id": snap.ID})
	desc := &grpc.StreamDesc{ServerStreams: true}
	st, err := conn.NewStream(ctx, desc, "/agentsh.v1.Agentsh/EventsTail")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SendMsg(tailReq); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseSend(); err != nil {
		t.Fatal(err)
	}

	// Kick an exec to generate events.
	go func() {
		execReq, _ := structpb.NewStruct(map[string]any{
			"session_id":     snap.ID,
			"command":        "sh",
			"args":           []any{"-c", "true"},
			"include_events": "none",
		})
		execResp := &structpb.Struct{}
		_ = conn.Invoke(ctx, "/agentsh.v1.Agentsh/Exec", execReq, execResp)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		msg := &structpb.Struct{}
		if err := st.RecvMsg(msg); err != nil {
			break
		}
		b, _ := protojson.Marshal(msg)
		if strings.Contains(string(b), "\"type\":\"command_finished\"") || strings.Contains(string(b), "\"type\":\"command_started\"") {
			cancel()
			select {
			case <-errCh:
			case <-time.After(2 * time.Second):
				t.Fatalf("server did not exit after cancel")
			}
			return
		}
	}
	t.Fatalf("did not see command_* event on stream")
}
