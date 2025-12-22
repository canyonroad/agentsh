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

func TestServer_GRPC_CreateSessionAndExec(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "default.yaml"), []byte("version: 1\nname: default\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	workspace := filepath.Join(dir, "ws")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Server.HTTP.ReadTimeout = "1s"
	cfg.Server.HTTP.WriteTimeout = "2s"
	cfg.Server.HTTP.MaxRequestSize = "1MB"
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

	addr := s.GRPCAddr()
	if addr == "" {
		t.Fatalf("grpc addr empty")
	}

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	createReq, err := structpb.NewStruct(map[string]any{
		"workspace": workspace,
		"policy":    "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	createResp := &structpb.Struct{}
	cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
	defer ccancel()
	if err := conn.Invoke(cctx, "/agentsh.v1.Agentsh/CreateSession", createReq, createResp); err != nil {
		t.Fatal(err)
	}
	b, _ := protojson.Marshal(createResp)
	var snap struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &snap); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if snap.ID == "" {
		t.Fatalf("expected session id in response, got: %s", string(b))
	}

	execReq, err := structpb.NewStruct(map[string]any{
		"session_id":     snap.ID,
		"command":        "sh",
		"args":           []any{"-c", "echo hi"},
		"include_events": "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	execResp := &structpb.Struct{}
	ectx, ecancel := context.WithTimeout(ctx, 5*time.Second)
	defer ecancel()
	if err := conn.Invoke(ectx, "/agentsh.v1.Agentsh/Exec", execReq, execResp); err != nil {
		t.Fatal(err)
	}
	eb, _ := protojson.Marshal(execResp)
	if !strings.Contains(string(eb), "\"exit_code\":0") {
		t.Fatalf("expected exit_code 0, got: %s", string(eb))
	}
	if !strings.Contains(string(eb), "hi") {
		t.Fatalf("expected stdout to contain hi, got: %s", string(eb))
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not exit after cancel")
	}
}
