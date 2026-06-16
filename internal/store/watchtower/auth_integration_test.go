package watchtower_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

func TestServer_CapturesAuthorizationMetadata(t *testing.T) {
	t.Parallel()
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	base := srv.DialerFor()
	authed := transport.DialerFunc(func(ctx context.Context) (transport.Conn, error) {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer inst-7.SECRET")
		return base.Dial(ctx)
	})

	tr, err := transport.New(transport.Options{
		Dialer:    authed,
		AgentID:   "agent-1",
		SessionID: "sess-1",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := tr.RunOnce(ctx, transport.StateConnecting); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if _, err := srv.WaitForFirstSessionInit(time.Second); err != nil {
		t.Fatalf("WaitForFirstSessionInit: %v", err)
	}
	if got := srv.FirstAuthorizationMetadata(); got != "Bearer inst-7.SECRET" {
		t.Fatalf("captured authorization = %q, want %q", got, "Bearer inst-7.SECRET")
	}
}
