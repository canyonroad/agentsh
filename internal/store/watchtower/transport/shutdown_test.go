package transport_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestShutdown_StopDrainsThenCloseSends verifies the Task 19 contract
// in StateLive: after Stop is signaled, runShutdown drains the live
// batcher and CloseSend's the conn before Run returns.
//
// Determinism: MaxAge is set to 10s so the batcher's periodic tick
// cannot flush during the test window; batched records sit until
// either another record fills MaxRecords=100 (not triggered) or
// runShutdown's Drain flushes them. The test appends exactly one
// record after Live is reached, then calls Stop and asserts that a
// subsequent EventBatch lands on conn.sendCh — only runShutdown's
// Drain path can have emitted it under these settings. The
// outer-loop handleOuterStop path does NOT drain any batcher and
// would not produce that send, so the observable cleanly isolates
// the Live-drain path from every other stopCh arm.
func TestShutdown_StopDrainsThenCloseSends(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	// Seed one record so Replaying has something to drain (and thus
	// we know Replaying's EventBatch is a distinct send on sendCh
	// from whatever Live's runShutdown Drain emits later).
	// Seq starts at 1 because computeReplayStart opens the reader at
	// remoteReplayCursor.Sequence + 1 = 1 on a zero-seed transport,
	// so seq=0 would be filtered out by the Reader.
	if _, err := w.Append(1, 0, []byte("replay-payload")); err != nil {
		t.Fatalf("wal.Append: %v", err)
	}

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
				// Large MaxAge so the periodic tick cannot flush
				// the Live batcher during the test window.
				MaxAge: 10 * time.Second,
			},
			MaxInflight:    8,
			HeartbeatEvery: time.Second,
		})
	}()

	// 1) SessionInit out.
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit within 1s")
	}
	// 2) Accept the session.
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{
				Accepted:            true,
				AckHighWatermarkSeq: 0,
				Generation:          0,
			},
		},
	}
	// 3) Replaying's EventBatch for the seeded record.
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no Replaying EventBatch within 1s")
	}

	// By now Replaying has returned StateLive and the Run loop is
	// inside runLive's select. Append a post-live record so the
	// Live reader Notifies; runLive pulls the record and puts it in
	// the batcher without flushing (MaxRecords=100, MaxAge=10s).
	if _, err := w.Append(2, 0, []byte("live-payload")); err != nil {
		t.Fatalf("wal.Append(live): %v", err)
	}

	// Brief settle so runLive's Notify handler adds the record to
	// the batcher before Stop arrives.
	time.Sleep(30 * time.Millisecond)

	// Drain-observable: after Stop, runShutdown's Drain must emit
	// the buffered Live record as an EventBatch BEFORE CloseSend.
	tr.Stop(200 * time.Millisecond)

	select {
	case <-conn.sendCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no Live-drain EventBatch on sendCh within 2s of Stop; runShutdown did not flush the batcher")
	}

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

// TestShutdown_StopDuringReplayAborts verifies that Stop arriving
// while runReplaying is still in flight is serviced promptly (the
// new stopCh arm in state_replaying.go) rather than blocking until
// replay finishes. The test pins Replaying by making buildEventBatchFn's
// Send block until released, which parks runReplaying inside the
// Send call; Stop fires, runReplaying's select observes it, aborts
// the send path, full-tears down, and Run returns nil.
//
// Without the runReplaying stopCh arm this test deadlocks (2s
// timeout on Run return). It is the regression guard for the Stop-
// during-Replaying branch of the documented contract.
func TestShutdown_StopDuringReplayAborts(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	// Seed enough records that replay actually has work to do.
	// Seqs start at 1 (Run opens the reader at remoteReplayCursor+1).
	for i := int64(1); i <= 50; i++ {
		if _, err := w.Append(i, 0, []byte("replay-payload")); err != nil {
			t.Fatalf("wal.Append: %v", err)
		}
	}

	// Block Send calls during replay: the first EventBatch Send
	// blocks until we signal release. This pins runReplaying inside
	// the Send invocation so Stop is the only thing that can
	// unblock the loop.
	release := make(chan struct{})
	var sendCalls atomic.Int32
	conn := newFakeConn()
	blockedSend := func(msg *wtpv1.ClientMessage) error {
		n := sendCalls.Add(1)
		// First send (SessionInit) passes through normally.
		if n == 1 {
			select {
			case conn.sendCh <- msg:
				return nil
			case <-conn.closed:
				return errors.New("closed")
			}
		}
		// Second and later sends block on release OR conn close.
		select {
		case <-release:
		case <-conn.closed:
			return errors.New("closed")
		}
		return nil
	}
	conn.sendFn = blockedSend
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
				MaxAge:     10 * time.Second,
			},
			MaxInflight:    8,
			HeartbeatEvery: time.Second,
		})
	}()

	// Drain SessionInit, accept session.
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

	// Let runReplaying enter and block on the first EventBatch Send.
	// By the 2-send threshold we know we are past SessionInit and
	// inside runReplaying.
	deadline := time.After(2 * time.Second)
	for {
		if sendCalls.Load() >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("runReplaying did not reach its first EventBatch Send; sendCalls=%d", sendCalls.Load())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Stop while runReplaying is pinned in Send.
	stopReturned := make(chan struct{})
	go func() {
		tr.Stop(200 * time.Millisecond)
		close(stopReturned)
	}()

	// Releasing the blocked Send lets runReplaying unwind past the
	// Send call; the select at the top of the loop then picks up
	// stopCh. (If we do NOT release, conn.closed fires via the
	// full-teardown in runReplaying's stopCh arm — also a valid
	// unblocking path. Releasing avoids relying on ordering between
	// close-as-unblock and the stopCh arm's actual execution.)
	close(release)

	select {
	case <-stopReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s of signal; runReplaying did not observe stopCh")
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
// the loop is still in Connecting (e.g. dial back-off) is observed
// and causes a clean exit. The dialer returns an error on every
// attempt so the loop bounces in the dial-fail → backoff loop.
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
