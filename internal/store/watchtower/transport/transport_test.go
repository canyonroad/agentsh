package transport_test

import (
	"context"
	"errors"
	"testing"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// fakeConn implements transport.Conn for tests.
type fakeConn struct {
	sendCh chan *wtpv1.ClientMessage
	recvCh chan *wtpv1.ServerMessage
	closed chan struct{}
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		sendCh: make(chan *wtpv1.ClientMessage, 64),
		recvCh: make(chan *wtpv1.ServerMessage, 64),
		closed: make(chan struct{}),
	}
}

func (f *fakeConn) Send(msg *wtpv1.ClientMessage) error {
	select {
	case f.sendCh <- msg:
		return nil
	case <-f.closed:
		return errors.New("closed")
	}
}

func (f *fakeConn) Recv() (*wtpv1.ServerMessage, error) {
	select {
	case msg := <-f.recvCh:
		return msg, nil
	case <-f.closed:
		return nil, errors.New("closed")
	}
}

func (f *fakeConn) CloseSend() error {
	close(f.closed)
	return nil
}

// TestConnectingState_SendsSessionInitAndAdvancesOnAck verifies that the
// Connecting state sends a SessionInit on entry and advances to Replaying
// once it observes a SessionAck.
func TestConnectingState_SendsSessionInitAndAdvancesOnAck(t *testing.T) {
	conn := newFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return conn, nil
	})

	tr := transport.New(transport.Options{
		Dialer:    dialer,
		AgentID:   "test-agent",
		SessionID: "sess-1",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	doneCh := make(chan transport.State, 1)
	go func() {
		doneCh <- tr.RunOnce(ctx, transport.StateConnecting)
	}()

	// Expect SessionInit on the wire.
	select {
	case msg := <-conn.sendCh:
		if msg.GetSessionInit() == nil {
			t.Fatalf("expected SessionInit, got %T", msg.Msg)
		}
		if got, want := msg.GetSessionInit().AgentId, "test-agent"; got != want {
			t.Fatalf("agent_id: got %q, want %q", got, want)
		}
	case <-ctx.Done():
		t.Fatal("did not receive SessionInit")
	}

	// Send SessionAck back.
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{
				AckHighWatermarkSeq: 0,
				Generation: 0,
			},
		},
	}

	select {
	case st := <-doneCh:
		if st != transport.StateReplaying {
			t.Fatalf("next state: got %s, want StateReplaying", st)
		}
	case <-ctx.Done():
		t.Fatal("Connecting state did not return")
	}
}
