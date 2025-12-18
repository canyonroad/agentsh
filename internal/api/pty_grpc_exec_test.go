package api

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/ptygrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPC_PTY_ExecBasic(t *testing.T) {
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
	_ = stream.CloseSend()

	var out bytes.Buffer
	var exit *ptygrpc.ExecPTYExit
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch m := msg.Msg.(type) {
		case *ptygrpc.ExecPTYServerMsg_Output:
			out.Write(m.Output.Data)
		case *ptygrpc.ExecPTYServerMsg_Exit:
			exit = m.Exit
			goto done
		}
	}
done:
	if exit == nil {
		t.Fatalf("expected exit message")
	}
	if exit.ExitCode != 0 {
		t.Fatalf("expected exit_code 0, got %d", exit.ExitCode)
	}
	if out.String() != "hi" {
		t.Fatalf("expected output hi, got %q", out.String())
	}
}

