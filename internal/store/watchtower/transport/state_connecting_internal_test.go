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
// test can assert teardown happened.
type internalFakeConn struct {
	sendErr        error
	recvErr        error
	closeCalls     int
	closeSendCalls int
}

func (f *internalFakeConn) Send(_ *wtpv1.ClientMessage) error { return f.sendErr }
func (f *internalFakeConn) Recv() (*wtpv1.ServerMessage, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	// Block effectively never; test rows always set an error first.
	return nil, errors.New("internal test should set recvErr")
}
func (f *internalFakeConn) CloseSend() error { f.closeSendCalls++; return nil }
func (f *internalFakeConn) Close() error     { f.closeCalls++; return nil }

// TestRunConnecting_DiscardsConnOnError pins the unexported invariant
// that, on any transient error path, runConnecting clears t.conn so the
// next iteration can dial fresh. This complements
// TestConnectingState_FailureBranches (external) which asserts
// Close()-was-called; this internal test asserts the Transport no longer
// retains the stale Conn.
//
// Lives in the internal package so it can read t.conn directly without
// growing the public API surface.
func TestRunConnecting_DiscardsConnOnError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		conn *internalFakeConn
	}{
		{
			name: "send failure clears conn",
			conn: &internalFakeConn{sendErr: errors.New("write: broken pipe")},
		},
		{
			name: "recv failure clears conn",
			conn: &internalFakeConn{recvErr: errors.New("read: connection reset")},
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

			if _, err := tr.RunOnce(ctx, StateConnecting); err == nil {
				t.Fatalf("RunOnce: expected error, got nil")
			}
			if tr.conn != nil {
				t.Fatalf("Transport.conn: got %v, want nil after error path", tr.conn)
			}
			if got, want := fc.closeCalls, 1; got != want {
				t.Fatalf("Close calls: got %d, want %d", got, want)
			}
			if got, want := fc.closeSendCalls, 0; got != want {
				t.Fatalf("CloseSend calls: got %d, want %d", got, want)
			}
		})
	}
}
