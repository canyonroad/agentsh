package transport_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestRun_ExitsOnContextCancellationDuringConnecting verifies that the
// Run loop returns ctx.Err() promptly when the parent context is
// cancelled while the state machine is backing off between failed dial
// attempts. The dialer returns an error on every attempt, forcing the
// loop into the backoff branch; the ctx cancel MUST unblock the sleep
// and surface context.Canceled within a short grace window.
//
// This is the smoke test for the Run loop's ctx-honour contract. It
// does not assert anything about which state the loop was in when it
// returned — only that it returned context.Canceled in bounded time
// and that rdrFactory was never invoked (i.e. replay/live were not
// reached under a dial-refused path).
func TestRun_ExitsOnContextCancellationDuringConnecting(t *testing.T) {
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return nil, errors.New("dial refused")
	})

	tr, err := transport.New(transport.Options{
		Dialer:    dialer,
		AgentID:   "a",
		SessionID: "s",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		t.Fatal("rdrFactory called; Run should not reach Replaying/Live")
		return nil, nil
	}
	go func() {
		done <- tr.Run(ctx, rdrFactory, transport.LiveOptions{
			Batcher: transport.BatcherOptions{
				MaxRecords: 100,
				MaxBytes:   1 << 16,
				MaxAge:     50 * time.Millisecond,
			},
			MaxInflight:    8,
			HeartbeatEvery: time.Second,
		})
	}()

	// Let the first dial attempt fail and enter the backoff sleep.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel")
	}
}

// TestRun_ReturnsTerminalErrorOnSessionRejection verifies the
// terminal-vs-retriable error contract: when runConnecting reports
// (StateShutdown, err) — e.g. server SessionAck rejection — Run MUST
// surface the error immediately rather than backing off and retrying.
// The opposite behavior would make a misconfiguration or server-side
// reject loop forever.
func TestRun_ReturnsTerminalErrorOnSessionRejection(t *testing.T) {
	conn := newFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return conn, nil
	})

	tr, err := transport.New(transport.Options{
		Dialer:    dialer,
		AgentID:   "a",
		SessionID: "s",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		t.Fatal("rdrFactory called; rejection should fire before Replaying/Live")
		return nil, nil
	}
	go func() {
		done <- tr.Run(ctx, rdrFactory, transport.LiveOptions{
			Batcher: transport.BatcherOptions{
				MaxRecords: 100,
				MaxBytes:   1 << 16,
				MaxAge:     50 * time.Millisecond,
			},
			MaxInflight:    8,
			HeartbeatEvery: time.Second,
		})
	}()

	// Drain the SessionInit; respond with a rejection.
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit sent")
	}
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{
				Accepted:     false,
				RejectReason: "go away",
			},
		},
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run returned nil, want non-nil terminal error")
		}
		if !strings.Contains(err.Error(), "go away") {
			t.Fatalf("Run error %q does not mention reject reason", err.Error())
		}
		// Verify we did not retry: only one SessionInit was sent (the
		// initial one we already drained). A subsequent dial+Init
		// would deposit another frame on conn.sendCh.
		select {
		case extra := <-conn.sendCh:
			t.Fatalf("Run retried after rejection; saw extra %T", extra.Msg)
		default:
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of rejection")
	}
}

// TestRun_RetriesTransientDialFailureUntilSuccess verifies that
// transient dial failures back off (do NOT terminate) and that a
// subsequent successful dial advances the loop into Replaying. This
// exercises the bo.Reset()/rep=nil branch and the StateConnecting →
// next-state handoff that the cancellation test cannot.
//
// The test stops short of actually running runReplaying — rdrFactory
// returns an error to abort replay, which surfaces back through the
// Run loop as a regress to StateConnecting. The dialer is then made
// to return ctx.Err()-like errors so the loop exits via cancel within
// the deadline.
func TestRun_RetriesTransientDialFailureUntilSuccess(t *testing.T) {
	var attempts atomic.Int32
	conn := newFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		n := attempts.Add(1)
		if n == 1 {
			return nil, errors.New("transient dial fail")
		}
		// Reset conn state for the second attempt: tests reuse the same
		// fakeConn, so we hand back the same conn (its closed channel
		// is not yet shut on the first error path).
		return conn, nil
	})

	tr, err := transport.New(transport.Options{
		Dialer:    dialer,
		AgentID:   "a",
		SessionID: "s",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rdrAttempts := make(chan struct{}, 4)
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		select {
		case rdrAttempts <- struct{}{}:
		default:
		}
		return nil, errors.New("rdrFactory deliberately failing to abort replay")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- tr.Run(ctx, rdrFactory, transport.LiveOptions{
			Batcher: transport.BatcherOptions{
				MaxRecords: 100,
				MaxBytes:   1 << 16,
				MaxAge:     50 * time.Millisecond,
			},
			MaxInflight:    8,
			HeartbeatEvery: time.Second,
		})
	}()

	// Wait for the second (successful) attempt's SessionInit, then
	// reply with an accepted SessionAck so runConnecting returns
	// StateReplaying.
	select {
	case <-conn.sendCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no SessionInit on second attempt within 2s")
	}
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{
				Accepted:            true,
				AckHighWatermarkSeq: 0,
				Generation:          0,
			},
		},
	}

	// Replaying enters and calls rdrFactory; we error it. Confirm we
	// reached Replaying, then cancel to exit cleanly.
	select {
	case <-rdrAttempts:
	case <-time.After(2 * time.Second):
		t.Fatal("rdrFactory was not invoked; Run did not reach Replaying")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}

	if got := attempts.Load(); got < 2 {
		t.Fatalf("dial attempts: got %d, want >= 2 (first transient, second success)", got)
	}
}
