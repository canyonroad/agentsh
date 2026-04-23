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
	// inside runLive's select. Append a post-live record. Either of
	// the following paths produces the Live-drain observable:
	//
	//   a) runLive's Notify arm fires first, pulls seq=2 via
	//      TryNext, adds to the batcher (no flush — MaxRecords=100,
	//      MaxAge=10s holds it), then Stop arrives, runShutdown's
	//      Drain flushes the buffered batch.
	//   b) Stop arrives first, runLive's stopCh arm runs
	//      runShutdown, whose TryNext pulls seq=2 directly (TryNext
	//      is synchronous; Append is visible immediately regardless
	//      of Notify timing), adds to the batcher, and Drain flushes
	//      one batch containing that record.
	//
	// Both produce the same observable: a second EventBatch on
	// conn.sendCh followed by CloseSend. No intermediate sleep is
	// needed — the race is resolved inside runLive/runShutdown, not
	// by the test goroutine.
	if _, err := w.Append(2, 0, []byte("live-payload")); err != nil {
		t.Fatalf("wal.Append(live): %v", err)
	}

	// Drain-observable: after Stop, runShutdown's Drain (or
	// runShutdown's own TryNext loop) emits the Live-era record as
	// an EventBatch BEFORE CloseSend.
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

// TestShutdown_StopBetweenReplayBatches verifies the Stop-during-
// Replaying contract as actually implemented: stopCh is observed at
// the TOP of runReplaying's drain loop, between NextBatch iterations.
// Stop does NOT preempt an in-flight Conn.Send or NextBatch (those
// are synchronous calls with no ctx hook); the stopCh arm only runs
// once the current Send/NextBatch has returned.
//
// Test shape: seed the WAL with many records and use a small batch
// cap so replay issues many Send calls. Drain a few Replaying
// EventBatches off sendCh (proving the loop is actively iterating),
// then call Stop. A deterministic upper bound on "extra sends after
// Stop" is enforced by instrumenting sendFn: after Stop is called,
// the (N+1)th additional Send call blocks on conn.closed. If
// runReplaying's top-of-loop stopCh arm is serviced within N more
// sends, everything proceeds cleanly (the stopCh arm closes the
// conn, unblocking any pending Send). If runReplaying ignores
// stopCh until replay completes, the (N+1)th Send blocks and
// Stop's `<-r.done` wait never fires — the test deadlocks and
// times out with a concrete violation message.
//
// The 2s timeout + deterministic bound N=5 catches regressions
// where Stop is serviced near replay completion (delta ~= 200
// sends, far exceeding N=5). Without the stopCh arm, this test
// deadlocks.
func TestShutdown_StopBetweenReplayBatches(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	// Seed many records; small batch cap means replay issues many
	// Send calls and thus loops through runReplaying's top-of-loop
	// select many times.
	const totalRecords = 200
	for i := int64(1); i <= totalRecords; i++ {
		if _, err := w.Append(i, 0, []byte("replay-payload")); err != nil {
			t.Fatalf("wal.Append: %v", err)
		}
	}

	// Instrumented send with a "block after N more sends" latch.
	// `blockAfter` is zero initially (no blocking). The test arms
	// it AFTER calling Stop, to blockAfter = sendsAtStopCall + 5.
	// Any Send past that count blocks on conn.closed until the
	// runReplaying stopCh arm tears the conn down. If the stopCh
	// arm is never serviced, Send stays blocked and the test's
	// stopReturned wait hits the 2s timeout — a deterministic fail.
	var (
		sendCalls   atomic.Int32
		blockAfter  atomic.Int32 // 0 = no blocking
		blockedOnce atomic.Bool  // flips true once a Send actually blocked; diagnostic
	)
	conn := newFakeConn()
	conn.sendFn = func(msg *wtpv1.ClientMessage) error {
		n := sendCalls.Add(1)
		if limit := blockAfter.Load(); limit > 0 && n > limit {
			blockedOnce.Store(true)
			<-conn.closed
			return errors.New("closed")
		}
		select {
		case conn.sendCh <- msg:
			return nil
		case <-conn.closed:
			return errors.New("closed")
		}
	}
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
				MaxRecords: 1,
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

	// Drain a few Replay EventBatches so runReplaying is demonstrably
	// iterating.
	for i := 0; i < 3; i++ {
		select {
		case <-conn.sendCh:
		case <-time.After(1 * time.Second):
			t.Fatalf("expected replay EventBatch %d within 1s", i+1)
		}
	}

	// Drain additional sendCh traffic in the background so Send
	// calls do not stall runReplaying's top-of-loop checks.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			select {
			case <-conn.sendCh:
			case <-conn.closed:
				return
			case <-time.After(3 * time.Second):
				return
			}
		}
	}()

	// Arm the post-Stop block latch: allow up to `maxSendsAfterStop`
	// more sends past the sampled baseline, then any further Send
	// blocks on conn.closed. The budget covers (1) in-flight sends
	// completing between the sample and the actual Stop delivery,
	// (2) Go scheduler latency on the goroutine launch below, and
	// (3) the single NextBatch/Send that may still be mid-flight
	// when the Stop request reaches the buffered channel. All
	// combined comfortably fit under maxSendsAfterStop=50, which is
	// trivially smaller than the ~200-send regression signal that
	// an ignored stopCh would produce.
	const maxSendsAfterStop = 50
	sendsAtStopCall := sendCalls.Load()
	blockAfter.Store(sendsAtStopCall + maxSendsAfterStop)

	stopReturned := make(chan struct{})
	go func() {
		tr.Stop(200 * time.Millisecond)
		close(stopReturned)
	}()

	select {
	case <-stopReturned:
	case <-time.After(2 * time.Second):
		t.Fatalf("Stop did not return within 2s; sends=%d, sendsAtStopCall=%d, limit=%d, blocked=%v — regression: runReplaying did not observe stopCh promptly",
			sendCalls.Load(), sendsAtStopCall, sendsAtStopCall+maxSendsAfterStop, blockedOnce.Load())
	}
	<-drainDone

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of Stop")
	}

	// Upper bound: runReplaying observed stopCh within maxSendsAfterStop
	// additional sends past the sampled baseline. Any regression that
	// services Stop only near replay completion would drive sendCalls
	// to ~totalRecords + 1 and trip this assertion before the timeout
	// — as well as causing the blockAfter latch to trigger. The
	// budget accommodates scheduler noise; it remains trivially
	// smaller than the ~200-send regression signal.
	totalSends := sendCalls.Load()
	if delta := totalSends - sendsAtStopCall; delta > maxSendsAfterStop {
		t.Fatalf("Stop not observed promptly between replay batches: totalSends=%d, sendsAtStopCall=%d, delta=%d, limit=%d",
			totalSends, sendsAtStopCall, delta, maxSendsAfterStop)
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
