package api

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/ptygrpc"
	"github.com/agentsh/agentsh/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPC_PTY_RespectsCommandPolicyDeny(t *testing.T) {
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

	lis := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { _ = lis.Close() })
	gs := grpc.NewServer()
	RegisterGRPC(gs, app)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	conn, err := grpc.DialContext(context.Background(), "passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cl := ptygrpc.NewAgentshPTYClient(conn)
	stream, err := cl.ExecPTY(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&ptygrpc.ExecPTYClientMsg{
		Msg: &ptygrpc.ExecPTYClientMsg_Start{
			Start: &ptygrpc.ExecPTYStart{
				SessionId: sess.ID,
				Command:   "sh",
				Args:      []string{"-lc", "printf hi"},
				Rows:      24,
				Cols:      80,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	_, err = stream.Recv()
	if err == nil {
		t.Fatalf("expected error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected status error, got %T: %v", err, err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v: %v", st.Code(), st.Message())
	}
}
