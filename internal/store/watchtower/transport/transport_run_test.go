package transport_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
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
