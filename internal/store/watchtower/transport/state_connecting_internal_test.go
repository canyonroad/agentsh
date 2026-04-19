package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// internalFakeConn is a minimal Conn used only to drive the internal
// teardown invariant tests. Tracks Close/CloseSend invocations so the
// test can assert teardown happened. recvMsg, when non-nil, is returned
// from Recv before recvErr is consulted; this lets a row drive the
// wrong-first-frame and rejected-SessionAck branches that hold a Conn.
type internalFakeConn struct {
	sendErr        error
	recvMsg        *wtpv1.ServerMessage
	recvErr        error
	closeCalls     int
	closeSendCalls int
}

func (f *internalFakeConn) Send(_ *wtpv1.ClientMessage) error { return f.sendErr }
func (f *internalFakeConn) Recv() (*wtpv1.ServerMessage, error) {
	if f.recvMsg != nil {
		return f.recvMsg, nil
	}
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	// Block effectively never; test rows always set either recvMsg or
	// recvErr (or fail earlier on Send).
	return nil, errors.New("internal test should set recvMsg or recvErr")
}
func (f *internalFakeConn) CloseSend() error { f.closeSendCalls++; return nil }
func (f *internalFakeConn) Close() error     { f.closeCalls++; return nil }

// TestRunConnecting_DiscardsConnOnError pins the unexported invariant
// that, on any held-Conn error path, runConnecting clears t.conn (so
// the next iteration can dial fresh) and calls Close() exactly once
// (the full-teardown primitive, never CloseSend()). This complements
// TestConnectingState_FailureBranches (external) which asserts
// Close()-was-called from outside the package; this internal test
// asserts the Transport no longer retains the stale Conn afterwards.
//
// Lives in the internal package so it can read t.conn directly without
// growing the public API surface.
func TestRunConnecting_DiscardsConnOnError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		conn           *internalFakeConn
		wantState      State
		wantRejectStr  string // expected RejectReason() after RunOnce
		wantCloseCalls int
	}{
		{
			name:           "send failure clears conn",
			conn:           &internalFakeConn{sendErr: errors.New("write: broken pipe")},
			wantState:      StateConnecting,
			wantCloseCalls: 1,
		},
		{
			name:           "recv failure clears conn",
			conn:           &internalFakeConn{recvErr: errors.New("read: connection reset")},
			wantState:      StateConnecting,
			wantCloseCalls: 1,
		},
		{
			name: "wrong first frame clears conn",
			conn: &internalFakeConn{
				recvMsg: &wtpv1.ServerMessage{
					Msg: &wtpv1.ServerMessage_BatchAck{
						BatchAck: &wtpv1.BatchAck{
							AckHighWatermarkSeq: 7,
							Generation:          1,
						},
					},
				},
			},
			wantState:      StateConnecting,
			wantCloseCalls: 1,
		},
		{
			name: "rejected SessionAck clears conn",
			conn: &internalFakeConn{
				recvMsg: &wtpv1.ServerMessage{
					Msg: &wtpv1.ServerMessage_SessionAck{
						SessionAck: &wtpv1.SessionAck{
							Accepted:     false,
							RejectReason: "bad agent",
						},
					},
				},
			},
			wantState:      StateShutdown,
			wantRejectStr:  "bad agent",
			wantCloseCalls: 1,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fc := tc.conn
			tr, err := New(Options{
				Dialer: DialerFunc(func(_ context.Context) (Conn, error) {
					return fc, nil
				}),
				AgentID:   "test-agent",
				SessionID: "sess-1",
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			st, err := tr.RunOnce(ctx, StateConnecting)
			if err == nil {
				t.Fatalf("RunOnce: expected error, got nil")
			}
			if st != tc.wantState {
				t.Fatalf("state: got %s, want %s (err=%v)", st, tc.wantState, err)
			}
			if tr.conn != nil {
				t.Fatalf("Transport.conn: got %v, want nil after error path", tr.conn)
			}
			if got, want := fc.closeCalls, tc.wantCloseCalls; got != want {
				t.Fatalf("Close calls: got %d, want %d", got, want)
			}
			if got, want := fc.closeSendCalls, 0; got != want {
				t.Fatalf("CloseSend calls: got %d, want %d", got, want)
			}
			if got, want := tr.RejectReason(), tc.wantRejectStr; got != want {
				t.Fatalf("RejectReason: got %q, want %q", got, want)
			}
		})
	}
}
