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
//
// closeSendCalled is set when CloseSend (half-close) runs; closed is set
// when Close (full teardown) runs. Both are idempotent. Tests inspect
// closeSendCalls/closeCalls to assert which lifecycle hook was invoked
// and how many times.
type fakeConn struct {
	sendCh          chan *wtpv1.ClientMessage
	recvCh          chan *wtpv1.ServerMessage
	closeSendCalled chan struct{}
	closed          chan struct{}
	closeSendCalls  int
	closeCalls      int
	sendErr         error
	recvErr         error
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		sendCh:          make(chan *wtpv1.ClientMessage, 64),
		recvCh:          make(chan *wtpv1.ServerMessage, 64),
		closeSendCalled: make(chan struct{}),
		closed:          make(chan struct{}),
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
	f.closeSendCalls++
	select {
	case <-f.closeSendCalled:
		// already half-closed; remain idempotent
	default:
		close(f.closeSendCalled)
	}
	return nil
}

func (f *fakeConn) Close() error {
	f.closeCalls++
	select {
	case <-f.closed:
		// already closed; remain idempotent
	default:
		close(f.closed)
	}
	return nil
}

// TestConnectingState_SendsSessionInitAndAdvancesOnAck verifies that the
// Connecting state sends a SessionInit on entry and advances to Replaying
// once it observes a SessionAck with accepted=true.
//
// The SessionInit assertions cover every field on the wire so that any
// future change to provenance (or default population) trips a test
// rather than silently shipping a wrong field.
func TestConnectingState_SendsSessionInitAndAdvancesOnAck(t *testing.T) {
	conn := newFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return conn, nil
	})

	const (
		wantAgentID        = "test-agent"
		wantSessionID      = "sess-1"
		wantAgentVersion   = "v1.2.3"
		wantOcsfVersion    = "1.4.0"
		wantKeyFingerprint = "deadbeef"
		wantContextDigest  = "cafef00d"
		wantTotalChained   = uint64(42)
		wantFormatVersion  = uint32(2)
	)

	tr, err := transport.New(transport.Options{
		Dialer:         dialer,
		AgentID:        wantAgentID,
		SessionID:      wantSessionID,
		AgentVersion:   wantAgentVersion,
		OcsfVersion:    wantOcsfVersion,
		KeyFingerprint: wantKeyFingerprint,
		ContextDigest:  wantContextDigest,
		TotalChained:   wantTotalChained,
		// FormatVersion + Algorithm omitted so we exercise defaults.
	})
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

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

	// Expect SessionInit on the wire. Assert every field — the defaulted
	// Algorithm and FormatVersion as well as everything supplied via
	// Options. ackedSequence/ackedGeneration are zero on first connect.
	select {
	case msg := <-conn.sendCh:
		init := msg.GetSessionInit()
		if init == nil {
			t.Fatalf("expected SessionInit, got %T", msg.Msg)
		}
		if got, want := init.AgentId, wantAgentID; got != want {
			t.Fatalf("agent_id: got %q, want %q", got, want)
		}
		if got, want := init.SessionId, wantSessionID; got != want {
			t.Fatalf("session_id: got %q, want %q", got, want)
		}
		if got, want := init.AgentVersion, wantAgentVersion; got != want {
			t.Fatalf("agent_version: got %q, want %q", got, want)
		}
		if got, want := init.OcsfVersion, wantOcsfVersion; got != want {
			t.Fatalf("ocsf_version: got %q, want %q", got, want)
		}
		if got, want := init.KeyFingerprint, wantKeyFingerprint; got != want {
			t.Fatalf("key_fingerprint: got %q, want %q", got, want)
		}
		if got, want := init.ContextDigest, wantContextDigest; got != want {
			t.Fatalf("context_digest: got %q, want %q", got, want)
		}
		if got, want := init.TotalChained, wantTotalChained; got != want {
			t.Fatalf("total_chained: got %d, want %d", got, want)
		}
		if got, want := init.FormatVersion, wantFormatVersion; got != want {
			t.Fatalf("format_version default: got %d, want %d", got, want)
		}
		if got, want := init.Algorithm, wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256; got != want {
			t.Fatalf("algorithm default: got %s, want %s", got, want)
		}
		if got, want := init.WalHighWatermarkSeq, uint64(0); got != want {
			t.Fatalf("wal_high_watermark_seq: got %d, want %d", got, want)
		}
		if got, want := init.Generation, uint32(0); got != want {
			t.Fatalf("generation: got %d, want %d", got, want)
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
//
// Each row that obtains a Conn also asserts that the Conn was Close()'d
// exactly once (the full-teardown primitive, not the half-close
// CloseSend) so the underlying stream is released before retry.
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
		// gotConn says whether the test row expects a Conn was obtained
		// (so close-call assertions apply). Dial-failure rows set this
		// false because the Dialer returned an error before a Conn.
		gotConn bool
	}{
		{
			name: "dial failure",
			setup: func() setup {
				return setup{dialErr: errors.New("boom")}
			},
			wantState:     transport.StateConnecting,
			wantErrSubstr: "dial",
			gotConn:       false,
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
			gotConn:       true,
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
			gotConn:       true,
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
			gotConn:       true,
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
			gotConn:       true,
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

			tr, err := transport.New(transport.Options{
				Dialer:    dialer,
				AgentID:   "test-agent",
				SessionID: "sess-1",
			})
			if err != nil {
				t.Fatalf("New: unexpected error: %v", err)
			}

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

			if !tc.gotConn {
				// Dial failed before a Conn was ever obtained; nothing
				// downstream to inspect. The state assertion above
				// proves the dial path was exercised.
				return
			}
			// Every error path on a held Conn must call Close() exactly
			// once (full teardown), and must NOT use CloseSend()
			// (half-close); the latter would leave the stream open.
			if got, want := s.conn.closeCalls, 1; got != want {
				t.Fatalf("Close calls: got %d, want %d", got, want)
			}
			if got, want := s.conn.closeSendCalls, 0; got != want {
				t.Fatalf("CloseSend calls: got %d, want %d (CloseSend is half-close, not teardown)", got, want)
			}
		})
	}
}

// TestNew_RejectsInvalidOptions verifies that New rejects misconfigured
// Options at construction so misuse fails immediately rather than inside
// the run loop. Each row asserts that the error mentions the bad field.
func TestNew_RejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return newFakeConn(), nil
	})

	cases := []struct {
		name          string
		opts          transport.Options
		wantErrSubstr string
	}{
		{
			name: "nil dialer",
			opts: transport.Options{
				AgentID:   "agent",
				SessionID: "sess",
			},
			wantErrSubstr: "Dialer",
		},
		{
			name: "empty AgentID",
			opts: transport.Options{
				Dialer:    dialer,
				SessionID: "sess",
			},
			wantErrSubstr: "AgentID",
		},
		{
			name: "empty SessionID",
			opts: transport.Options{
				Dialer:  dialer,
				AgentID: "agent",
			},
			wantErrSubstr: "SessionID",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tr, err := transport.New(tc.opts)
			if tr != nil {
				t.Fatalf("Transport: got %v, want nil", tr)
			}
			if err == nil {
				t.Fatalf("err: got nil, want non-nil mentioning %q", tc.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("err: got %v, want substring %q", err, tc.wantErrSubstr)
			}
		})
	}
}
