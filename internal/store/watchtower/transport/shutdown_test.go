package transport_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestShutdown_StopDrainsThenCloseSends verifies the Task 19 contract:
// when Stop is invoked while the transport is in StateLive, the run
// loop drains pending records (up to drainDeadline), CloseSend's the
// stream, and Run returns nil.
//
// The test does not assert payload contents on the wire (encoding is
// stubbed pre-Task-22) — only the Stop-observable side effects:
// CloseSend was called on the conn, and Run exited cleanly within the
// drainDeadline + grace.
func TestShutdown_StopDrainsThenCloseSends(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	conn := newFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return conn, nil
	})

	tr, err := transport.New(transport.Options{
		Dialer:    dialer,
		AgentID:   "a",
		SessionID: "s",
		WAL:       w,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rdrFactory := func(gen uint32, start uint64) (*wal.Reader, error) {
		return w.NewReader(wal.ReaderOptions{Generation: gen, Start: start})
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

	// Drain SessionInit; reply with accepted SessionAck so the loop
	// advances Connecting → Replaying → Live. With an empty WAL the
	// Replaying stage drains immediately (NextBatch returns done=true
	// on the empty reader) and Live is reached.
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit within 1s")
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

	// Heuristic settle window — by 100ms the run loop has gone through
	// Replaying (no records) and entered Live's select. Any earlier and
	// Stop may queue ahead of Live entry; that path is exercised by
	// TestShutdown_StopBeforeLiveExits below.
	time.Sleep(100 * time.Millisecond)

	tr.Stop(200 * time.Millisecond)

	select {
	case <-conn.closeSendCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("CloseSend not invoked within 2s of Stop")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of Stop")
	}
}

// TestShutdown_StopBeforeLiveExits verifies that Stop arriving while
// the loop is still in Connecting (e.g. dial back-off) is observed and
// causes a clean exit. The conn dialer never returns a conn (returns
// error every attempt), so the loop bounces in the
// dial-fail → backoff loop. Stop should unblock the backoff and exit.
func TestShutdown_StopBeforeLiveExits(t *testing.T) {
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

	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		t.Fatal("rdrFactory called; Run should not reach Replaying/Live")
		return nil, nil
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

	// Let one dial fail and enter backoff sleep.
	time.Sleep(50 * time.Millisecond)
	tr.Stop(200 * time.Millisecond)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of Stop")
	}
}
