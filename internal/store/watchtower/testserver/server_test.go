package testserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestServer_AcksSessionInit verifies the default scenario: server
// replies to SessionInit with SessionAck at watermark (0, 0, accepted).
func TestServer_AcksSessionInit(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	conn, err := srv.Dial(dialCtx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{
				AgentId:   "test",
				SessionId: "s1",
				Algorithm: wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256,
			},
		},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	recvDone := make(chan struct{})
	var (
		got     *wtpv1.ServerMessage
		recvErr error
	)
	go func() {
		got, recvErr = conn.Recv()
		close(recvDone)
	}()

	select {
	case <-recvDone:
	case <-time.After(2 * time.Second):
		t.Fatal("recv timed out")
	}
	if recvErr != nil {
		t.Fatalf("recv: %v", recvErr)
	}
	if got.GetSessionAck() == nil {
		t.Fatalf("got %T, want SessionAck", got.Msg)
	}
	if !got.GetSessionAck().GetAccepted() {
		t.Fatalf("SessionAck.Accepted=false")
	}
}
