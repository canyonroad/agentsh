package api

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/ptygrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPC_PTYRegistered(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { _ = lis.Close() })

	s := grpc.NewServer()
	RegisterGRPC(s, nil)
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
	_, err = stream.Recv()
	if err == nil {
		t.Fatalf("expected recv error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got %v: %v", st.Code(), st.Message())
	}
	if !strings.Contains(strings.ToLower(st.Message()), "pty not implemented") {
		t.Fatalf("expected message to mention pty not implemented, got %q", st.Message())
	}
}
