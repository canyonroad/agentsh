package api

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/ptygrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPC_PTYRegistered(t *testing.T) {
	db := newSQLiteStore(t)
	store := composite.New(db, db)
	sessions := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Create(ws, "default"); err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t, sessions, store)

	lis := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { _ = lis.Close() })

	s := grpc.NewServer()
	RegisterGRPC(s, app)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	conn, err := grpc.DialContext(context.Background(), "passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	cl := ptygrpc.NewAgentshPTYClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	stream, err := cl.ExecPTY(ctx)
	if err != nil {
		t.Fatalf("expected stream, got error: %v", err)
	}
	// Without a start message (first frame must be start), the server should reject with InvalidArgument.
	_ = stream.Send(&ptygrpc.ExecPTYClientMsg{})
	_, err = stream.Recv()
	if err == nil {
		t.Fatalf("expected recv error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %T: %v", err, err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v: %v", st.Code(), st.Message())
	}
	if !strings.Contains(strings.ToLower(st.Message()), "start") {
		t.Fatalf("expected message to mention start, got %q", st.Message())
	}
}
