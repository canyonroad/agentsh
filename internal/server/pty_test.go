package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/ptygrpc"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestServer_HTTP_PTYWebSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY tests require Unix shell")
	}
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
	cfg.Server.HTTP.ReadTimeout = "2s"
	cfg.Server.HTTP.WriteTimeout = "10s"
	cfg.Server.HTTP.MaxRequestSize = "1MB"
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

	baseURL := "http://" + s.httpLn.Addr().String()
	cl := client.New(baseURL, "")
	snap, err := cl.CreateSession(ctx, workspace, "default")
	if err != nil {
		t.Fatal(err)
	}

	wsURL := "ws://" + s.httpLn.Addr().String() + "/api/v1/sessions/" + snap.ID + "/pty"
	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	defer dialCancel()
	conn, _, err := websocket.DefaultDialer.DialContext(dialCtx, wsURL, http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	start := map[string]any{
		"type":    "start",
		"command": "sh",
		"args":    []any{"-c", `read x; echo "X:$x"`},
		"rows":    24,
		"cols":    80,
	}
	sb, _ := json.Marshal(start)
	if err := conn.WriteMessage(websocket.TextMessage, sb); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("hello\n")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var out bytes.Buffer
	for time.Now().Before(deadline) {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		switch mt {
		case websocket.BinaryMessage:
			_, _ = out.Write(msg)
		case websocket.TextMessage:
			var base struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(msg, &base) != nil {
				continue
			}
			switch base.Type {
			case "exit":
				var ex struct {
					ExitCode int `json:"exit_code"`
				}
				_ = json.Unmarshal(msg, &ex)
				if ex.ExitCode != 0 {
					t.Fatalf("non-zero exit_code=%d, output=%q", ex.ExitCode, out.String())
				}
				if !strings.Contains(out.String(), "X:hello") {
					t.Fatalf("expected output to contain %q, got %q", "X:hello", out.String())
				}
				cancel()
				<-errCh
				return
			case "error":
				t.Fatalf("server error: %s", strings.TrimSpace(string(msg)))
			}
		}
	}
	t.Fatalf("timeout waiting for PTY exit, output=%q", out.String())
}

func TestServer_GRPC_PTYExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY tests require Unix shell")
	}
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

	// Create session via generic gRPC endpoint.
	createReq, _ := structpb.NewStruct(map[string]any{"workspace": workspace, "policy": "default"})
	createResp := &structpb.Struct{}
	if err := conn.Invoke(ctx, "/agentsh.v1.Agentsh/CreateSession", createReq, createResp); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(createResp.AsMap())
	var snap struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &snap)
	if snap.ID == "" {
		t.Fatalf("missing session id: %s", string(b))
	}

	ptyc := ptygrpc.NewAgentshPTYClient(conn)
	pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
	defer pcancel()
	stream, err := ptyc.ExecPTY(pctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&ptygrpc.ExecPTYClientMsg{Msg: &ptygrpc.ExecPTYClientMsg_Start{Start: &ptygrpc.ExecPTYStart{
		SessionId: snap.ID,
		Command:   "sh",
		Args:      []string{"-c", `read x; echo "X:$x"`},
		Rows:      24,
		Cols:      80,
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&ptygrpc.ExecPTYClientMsg{Msg: &ptygrpc.ExecPTYClientMsg_Stdin{Stdin: &ptygrpc.ExecPTYStdin{Data: []byte("hello\n")}}}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch m := msg.Msg.(type) {
		case *ptygrpc.ExecPTYServerMsg_Output:
			_, _ = out.Write(m.Output.Data)
		case *ptygrpc.ExecPTYServerMsg_Exit:
			if m.Exit.ExitCode != 0 {
				t.Fatalf("non-zero exit_code=%d output=%q", m.Exit.ExitCode, out.String())
			}
			if !strings.Contains(out.String(), "X:hello") {
				t.Fatalf("expected output to contain %q, got %q", "X:hello", out.String())
			}
			cancel()
			<-errCh
			return
		case *ptygrpc.ExecPTYServerMsg_Error:
			t.Fatalf("server error: %s (%s)", strings.TrimSpace(m.Error.Message), strings.TrimSpace(m.Error.Code))
		}
	}
}
