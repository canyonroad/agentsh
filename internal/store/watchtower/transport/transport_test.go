package transport_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// fakeConn implements transport.Conn for tests. The send/recv channels
// model a single sender + single receiver per the Conn concurrency
// contract; sendErr/recvErr let tests force a Send/Recv failure.
type fakeConn struct {
	sendCh  chan *wtpv1.ClientMessage
	recvCh  chan *wtpv1.ServerMessage
	closed  chan struct{}
	sendErr error
	recvErr error
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		sendCh: make(chan *wtpv1.ClientMessage, 64),
		recvCh: make(chan *wtpv1.ServerMessage, 64),
		closed: make(chan struct{}),
	}
}

func (f *fakeConn) Send(msg *wtpv1.ClientMessage) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	select {
	case f.sendCh <- msg:
		return nil
	case <-f.closed:
		return errors.New("closed")
	}
}

func (f *fakeConn) Recv() (*wtpv1.ServerMessage, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	select {
	case msg := <-f.recvCh:
		return msg, nil
	case <-f.closed:
		return nil, errors.New("closed")
	}
}

func (f *fakeConn) CloseSend() error {
	select {
	case <-f.closed:
		// already closed
	default:
		close(f.closed)
	}
	return nil
}

// TestConnectingState_SendsSessionInitAndAdvancesOnAck verifies that the
// Connecting state sends a SessionInit on entry and advances to Replaying
// once it observes a SessionAck with accepted=true.
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

	type result struct {
		st  transport.State
		err error
	}
	doneCh := make(chan result, 1)
	go func() {
		st, err := tr.RunOnce(ctx, transport.StateConnecting)
		doneCh <- result{st, err}
	}()

	// Expect SessionInit on the wire. The default Algorithm must be
	// HMAC_SHA256 so the proto validator accepts the frame.
	select {
	case msg := <-conn.sendCh:
		init := msg.GetSessionInit()
		if init == nil {
			t.Fatalf("expected SessionInit, got %T", msg.Msg)
		}
		if got, want := init.AgentId, "test-agent"; got != want {
			t.Fatalf("agent_id: got %q, want %q", got, want)
		}
		if got, want := init.Algorithm, wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256; got != want {
			t.Fatalf("algorithm default: got %s, want %s", got, want)
		}
	case <-ctx.Done():
		t.Fatal("did not receive SessionInit")
	}

	// Send SessionAck back.
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{
				AckHighWatermarkSeq: 0,
				Generation:          0,
				Accepted:            true,
			},
		},
	}

	select {
	case res := <-doneCh:
		if res.err != nil {
			t.Fatalf("happy-path RunOnce: unexpected error: %v", res.err)
		}
		if res.st != transport.StateReplaying {
			t.Fatalf("next state: got %s, want StateReplaying", res.st)
		}
	case <-ctx.Done():
		t.Fatal("Connecting state did not return")
	}
}

// TestConnectingState_FailureBranches covers each error path the
// Connecting state can take. Transient errors (dial/send/recv/wrong-frame)
// stay in StateConnecting so the run loop can back off and retry; a
// SessionAck rejection is terminal and bubbles up via StateShutdown +
// Transport.RejectReason().
func TestConnectingState_FailureBranches(t *testing.T) {
	t.Parallel()

	type setup struct {
		// dialErr forces the Dialer to fail before the transport even
		// gets a Conn.
		dialErr error
		// conn, when non-nil, is what the Dialer returns. Mutually
		// exclusive with dialErr.
		conn *fakeConn
		// preload, if non-nil, is enqueued onto conn.recvCh before
		// RunOnce runs so Recv returns it deterministically.
		preload *wtpv1.ServerMessage
	}

	cases := []struct {
		name      string
		setup     func() setup
		wantState transport.State
		// wantErrSubstr is a substring the returned error must contain.
		wantErrSubstr string
		// wantReject, when non-empty, is the value RejectReason() must
		// return after RunOnce.
		wantReject string
	}{
		{
			name: "dial failure",
			setup: func() setup {
				return setup{dialErr: errors.New("boom")}
			},
			wantState:     transport.StateConnecting,
			wantErrSubstr: "dial",
		},
		{
			name: "send failure",
			setup: func() setup {
				c := newFakeConn()
				c.sendErr = errors.New("write: broken pipe")
				return setup{conn: c}
			},
			wantState:     transport.StateConnecting,
			wantErrSubstr: "send SessionInit",
		},
		{
			name: "recv failure",
			setup: func() setup {
				c := newFakeConn()
				c.recvErr = errors.New("read: connection reset")
				return setup{conn: c}
			},
			wantState:     transport.StateConnecting,
			wantErrSubstr: "recv SessionAck",
		},
		{
			name: "wrong first frame",
			setup: func() setup {
				c := newFakeConn()
				return setup{
					conn: c,
					preload: &wtpv1.ServerMessage{
						Msg: &wtpv1.ServerMessage_BatchAck{
							BatchAck: &wtpv1.BatchAck{
								AckHighWatermarkSeq: 7,
								Generation:          1,
							},
						},
					},
				}
			},
			wantState:     transport.StateConnecting,
			wantErrSubstr: "expected SessionAck",
		},
		{
			name: "rejected SessionAck",
			setup: func() setup {
				c := newFakeConn()
				return setup{
					conn: c,
					preload: &wtpv1.ServerMessage{
						Msg: &wtpv1.ServerMessage_SessionAck{
							SessionAck: &wtpv1.SessionAck{
								Accepted:     false,
								RejectReason: "bad agent",
							},
						},
					},
				}
			},
			wantState:     transport.StateShutdown,
			wantErrSubstr: "session rejected",
			wantReject:    "bad agent",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := tc.setup()
			dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
				if s.dialErr != nil {
					return nil, s.dialErr
				}
				return s.conn, nil
			})

			tr := transport.New(transport.Options{
				Dialer:    dialer,
				AgentID:   "test-agent",
				SessionID: "sess-1",
			})

			if s.conn != nil && s.preload != nil {
				s.conn.recvCh <- s.preload
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			st, err := tr.RunOnce(ctx, transport.StateConnecting)
			if st != tc.wantState {
				t.Fatalf("state: got %s, want %s (err=%v)", st, tc.wantState, err)
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("error: got %v, want substring %q", err, tc.wantErrSubstr)
			}
			if got := tr.RejectReason(); got != tc.wantReject {
				t.Fatalf("RejectReason: got %q, want %q", got, tc.wantReject)
			}
		})
	}
}
