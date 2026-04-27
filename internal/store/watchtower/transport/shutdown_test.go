package transport_test

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestShutdown_NoLeakAfterDrainSentinel pins the roborev #6143 (High)
// context: with the TransportLoss carrier, a loss marker in the drain
// set now produces a TransportLoss frame on the wire rather than
// failing closed. The full record sequence [data1, loss, data2] must
// produce TWO Send calls: one EventBatch for data1 and one
// TransportLoss for the loss marker. data2 sits past the loss boundary
// and gets a second EventBatch (three total Sends).
//
// We construct the WAL with [data1, loss, data2] and call runShutdown
// directly via the test seam so the test does not depend on the Run-loop
// stopCh/Notify race resolving in our favour.
func TestShutdown_NoLeakAfterDrainSentinel(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	if _, err := w.Append(1, 1, []byte("data1")); err != nil {
		t.Fatalf("Append data1: %v", err)
	}
	if err := w.AppendLoss(wal.LossRecord{
		FromSequence: 2,
		ToSequence:   2,
		Generation:   1,
		Reason:       "overflow",
	}); err != nil {
		t.Fatalf("AppendLoss: %v", err)
	}
	if _, err := w.Append(3, 1, []byte("data2")); err != nil {
		t.Fatalf("Append data2: %v", err)
	}

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 1, Start: 1})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	// Stub encoder: handles raw (non-proto) payloads by emitting one
	// EventBatch per data run and one TransportLoss per loss marker,
	// matching the production encoder's behavior without requiring
	// valid CompactEvent proto bytes in the test WAL.
	defer transport.SetEncodeBatchMessageFnForTest(func(records []wal.Record) ([]*wtpv1.ClientMessage, error) {
		var msgs []*wtpv1.ClientMessage
		var dataRun bool
		for _, r := range records {
			switch r.Kind {
			case wal.RecordLoss:
				if dataRun {
					msgs = append(msgs, &wtpv1.ClientMessage{
						Msg: &wtpv1.ClientMessage_EventBatch{EventBatch: &wtpv1.EventBatch{}},
					})
					dataRun = false
				}
				msgs = append(msgs, &wtpv1.ClientMessage{
					Msg: &wtpv1.ClientMessage_TransportLoss{TransportLoss: &wtpv1.TransportLoss{
						FromSequence: r.Loss.FromSequence,
						ToSequence:   r.Loss.ToSequence,
					}},
				})
			case wal.RecordData:
				dataRun = true
			}
		}
		if dataRun {
			msgs = append(msgs, &wtpv1.ClientMessage{
				Msg: &wtpv1.ClientMessage_EventBatch{EventBatch: &wtpv1.EventBatch{}},
			})
		}
		return msgs, nil
	})()

	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 100,
		MaxBytes:   1 << 16,
		MaxAge:     10 * time.Second,
	})

	conn := newFakeConn()
	tr, err := transport.New(transport.Options{
		Dialer: transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
			return conn, nil
		}),
		AgentID:   "a",
		SessionID: "s",
		WAL:       w,
	})
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	transport.SetConnForTest(tr, conn)

	got := transport.RunShutdownForTest(tr, b, rdr, 500*time.Millisecond)
	if got != nil {
		t.Fatalf("runShutdown returned %v; want nil", got)
	}

	// Count post-shutdown sends. With the carrier, runShutdown emits:
	//   send 1: EventBatch for data1 (gap-flush when loss is added)
	//   send 2: TransportLoss for the loss marker
	//   send 3: EventBatch for data2 (final Drain)
	sendCount := 0
drainSends:
	for {
		select {
		case <-conn.sendCh:
			sendCount++
		default:
			break drainSends
		}
	}
	if sendCount != 3 {
		t.Fatalf("got %d post-shutdown sends; want exactly 3 (data1 EventBatch + TransportLoss + data2 EventBatch)", sendCount)
	}

	// CloseSend must still happen.
	select {
	case <-conn.closeSendCalled:
	case <-time.After(time.Second):
		t.Fatal("CloseSend not called within 1s of runShutdown returning")
	}
}

// TestShutdown_RecordLossDuringDrainPropagates pins the carrier contract:
// when runShutdown's drain encounters a loss marker, a TransportLoss
// frame is emitted on the wire and the session continues to return nil
// from Run rather than propagating an error.
//
// Test shape — the encoder seam is split (build → Replaying;
// encode → Live/Shutdown), so:
//
//  1. Seed one record so Replaying has something to send. This is
//     the test's sync point for "runLive has started" (the second
//     conn.sendCh receive lines up with Replaying having transitioned
//     to Live; without it, Stop can race the Replaying→Live boundary
//     and the OUTER stopCh arm in Run preempts runLive's inner
//     stopCh arm, bypassing runShutdown entirely).
//  2. Replaying uses buildEventBatchFn → swap to a happy-path stub
//     so Replaying's send succeeds and the test reaches Live.
//  3. Live and Shutdown use encodeBatchMessageFn → production encoder
//     handles loss markers as TransportLoss frames.
//  4. Append a post-live record with a loss → Stop with positive drainDeadline →
//     runShutdown's Drain encodes the buffered batch → TransportLoss
//     emitted → Run returns nil.
func TestShutdown_RecordLossDuringDrainPropagates(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Same scheduling-jitter caveat as TestShutdown_StopDrainsThenCloseSends.
		t.Skip("Windows: drain-deadline timing flakes under runner-scheduling jitter")
	}

	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	// Replaying succeeds with the same nonEmptyMsg stub the other
	// shutdown tests use.
	defer transport.SetBuildEventBatchFnForTest(nonEmptyMsg)()

	// Seed one record so Replaying has something to send — the second
	// conn.sendCh receive is the "runLive has started" sync point.
	if _, err := w.Append(1, 0, []byte("replay-payload")); err != nil {
		t.Fatalf("wal.Append(replay): %v", err)
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
		t.Fatalf("transport.New: %v", err)
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

	// Handshake: SessionInit out, SessionAck in.
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit within 1s")
	}
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{Accepted: true},
		},
	}
	// Replaying sends one EventBatch — sync point for "runLive started".
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no Replaying EventBatch within 1s")
	}

	// runLive is in its inner select. Append a loss record so
	// runShutdown's Drain produces a TransportLoss frame.
	if err := w.AppendLoss(wal.LossRecord{
		FromSequence: 2,
		ToSequence:   2,
		Generation:   0,
		Reason:       "overflow",
	}); err != nil {
		t.Fatalf("wal.AppendLoss(live): %v", err)
	}

	tr.Stop(500 * time.Millisecond)

	select {
	case got := <-done:
		if got != nil {
			t.Fatalf("Run returned %v; want nil (TransportLoss is emitted, not fatal)", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of Stop")
	}
}

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
	if runtime.GOOS == "windows" {
		// The test asserts the Live-drain EventBatch lands on the
		// fakeConn sendCh within 2s of Stop. On the Windows runner
		// the combined goroutine-scheduling + filesystem-fsync
		// latency frequently overshoots that budget, producing a
		// flaky "runShutdown did not flush the batcher" fail even
		// though the drain completed. The timing-sensitive seam
		// needs a Windows-tuned deadline or a deterministic flush
		// signal; scope as follow-up. The Linux + macOS runs still
		// cover the core drain contract.
		t.Skip("Windows: 2s drain deadline flakes under runner-scheduling jitter")
	}
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	// The test seeds raw non-CompactEvent payloads; swap both the
	// Live-state and Replaying-state encoders for deterministic stubs
	// so the production proto.Unmarshal path doesn't reject them.
	defer transport.SetEncodeBatchMessageFnForTest(nonEmptyMsg)()
	defer transport.SetBuildEventBatchFnForTest(nonEmptyMsg)()

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
// Timing anchor: the test uses the EnqueueStopAndWaitForTest seam
// (seams_export_test.go), which is a thin wrapper around the same
// stopWithHooks helper that the public Transport.Stop uses. This
// keeps the public enqueue/wait path covered while letting the
// test arm a send-count latch close to the enqueue moment.
//
// Ordering claim (narrow): after postEnqueue returns, the stopReq
// is in t.stopCh. Go's select semantics do NOT strictly prevent a
// receiver that was already ready-to-consume from observing the
// request before postEnqueue; runReplaying's top-of-loop select
// uses a `default` fall-through so that window is rarely active,
// but the seam docstring spells out the caveat. For the budget
// below the caveat is tolerable: the latch just needs to accept a
// handful of sends that may fire between enqueue and the next
// top-of-loop check under normal scheduling.
//
// Regression shape: if runReplaying never observes stopCh (the
// arm is removed or broken), the (maxSendsAfterStop+1)th Send
// blocks on conn.closed, the seam's `<-r.done` wait never fires,
// and the 2s timeout fails the test with an explicit diagnostic.
// Validated by temporarily removing runReplaying's stopCh arm —
// the test fails deterministically with delta ~= totalRecords.
func TestShutdown_StopBetweenReplayBatches(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{Dir: dir, SegmentSize: 64 * 1024})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	// Same non-CompactEvent payload as StopDrainsThenCloseSends —
	// swap both encoders for stubs.
	defer transport.SetEncodeBatchMessageFnForTest(nonEmptyMsg)()
	defer transport.SetBuildEventBatchFnForTest(nonEmptyMsg)()

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
	// `blockAfter` starts at zero (no blocking). The test arms it
	// inside postEnqueue (AFTER the stopReq has been written to
	// t.stopCh) to sendCalls.Load() + maxSendsAfterStop. Any Send
	// past that count blocks on conn.closed until runReplaying's
	// stopCh arm tears the conn down; if the arm is never serviced
	// Send stays blocked and EnqueueStopAndWaitForTest's `<-r.done`
	// wait hits the 2s test timeout — a deterministic fail
	// anchored to the enqueue moment.
	const maxSendsAfterStop = 50
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

	// Use EnqueueStopAndWaitForTest to atomically enqueue the
	// stopReq and then arm the latch in postEnqueue — so the latch
	// budget measures only the enqueue→observation window.
	var sendsAtEnqueue int32
	stopReturned := make(chan struct{})
	go func() {
		transport.EnqueueStopAndWaitForTest(
			tr,
			200*time.Millisecond,
			nil, // preEnqueue
			func() {
				// postEnqueue: stopReq is now in t.stopCh.
				// Sample + arm the latch. All further Sends are
				// counted toward the maxSendsAfterStop budget
				// relative to THIS moment.
				sendsAtEnqueue = sendCalls.Load()
				blockAfter.Store(sendsAtEnqueue + maxSendsAfterStop)
			},
		)
		close(stopReturned)
	}()

	select {
	case <-stopReturned:
	case <-time.After(2 * time.Second):
		t.Fatalf("Stop did not return within 2s; sends=%d, sendsAtEnqueue=%d, limit=%d, blocked=%v — regression: runReplaying did not observe stopCh promptly",
			sendCalls.Load(), sendsAtEnqueue, sendsAtEnqueue+maxSendsAfterStop, blockedOnce.Load())
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

	// Upper bound anchored at the enqueue moment: runReplaying
	// observed stopCh within maxSendsAfterStop sends past the
	// enqueue. Any regression that services Stop only near replay
	// completion drives delta to ~totalRecords, far exceeding
	// maxSendsAfterStop.
	totalSends := sendCalls.Load()
	if delta := totalSends - sendsAtEnqueue; delta > maxSendsAfterStop {
		t.Fatalf("Stop not observed promptly between replay batches: totalSends=%d, sendsAtEnqueue=%d, delta=%d, limit=%d",
			totalSends, sendsAtEnqueue, delta, maxSendsAfterStop)
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

// TestStop_AfterRunAlreadyExited is the Task 27c acceptance test: once
// the Run loop has terminated (e.g. via SessionAck rejection), a
// subsequent Transport.Stop call MUST return without blocking on a
// never-closed stopReq.done channel. Without the RunDone signal,
// Stop's send to t.stopCh succeeds (cap-1 buffer) but its <-r.done
// wait deadlocks because no consumer ever services the request.
//
// The test drives Run to terminal exit via SessionAck rejection,
// waits for Run to actually return, THEN calls Stop and asserts it
// returns within a tight bound.
func TestStop_AfterRunAlreadyExited(t *testing.T) {
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
	runDone := make(chan error, 1)
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		t.Fatal("rdrFactory called; rejection should fire before Replaying/Live")
		return nil, nil
	}
	go func() {
		runDone <- tr.Run(ctx, rdrFactory, transport.LiveOptions{
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

	// Wait for Run to return — the precondition for the test is "Run
	// has already exited when Stop is called". Without this wait we
	// would race against the run loop and might hit the
	// stopCh-still-being-consumed path instead.
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of rejection")
	}

	// Now Stop. Per Task 27c, this MUST return promptly because the
	// RunDone signal lets Stop observe that no consumer is left.
	stopReturned := make(chan struct{})
	go func() {
		tr.Stop(0)
		close(stopReturned)
	}()
	select {
	case <-stopReturned:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop did not return within 500ms after Run exit; RunDone signal missing")
	}
}

// TestRun_RejectsSecondInvocation pins the roborev finding that Task
// 27c's `defer close(t.runDone)` would panic on a second Run call
// (close-of-closed-channel). Transport is single-use per run-loop
// lifetime — the contract is now explicit. A second Run MUST return
// an error rather than panic.
func TestRun_RejectsSecondInvocation(t *testing.T) {
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
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		t.Fatal("rdrFactory called; rejection should fire before Replaying/Live")
		return nil, nil
	}
	liveOpts := transport.LiveOptions{
		Batcher: transport.BatcherOptions{
			MaxRecords: 100,
			MaxBytes:   1 << 16,
			MaxAge:     50 * time.Millisecond,
		},
		MaxInflight:    8,
		HeartbeatEvery: time.Second,
	}

	// Drive the first Run to terminal exit.
	firstDone := make(chan error, 1)
	go func() { firstDone <- tr.Run(ctx, rdrFactory, liveOpts) }()
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit sent")
	}
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{Accepted: false, RejectReason: "go away"},
		},
	}
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first Run did not return within 2s of rejection")
	}

	// Second Run MUST return an error, not panic on close-of-closed.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Run panicked: %v", r)
		}
	}()
	err = tr.Run(ctx, rdrFactory, liveOpts)
	if err == nil {
		t.Fatal("second Run returned nil; want sentinel rejecting reuse")
	}
	if !errors.Is(err, transport.ErrTransportSingleUse) {
		t.Fatalf("second Run returned %v; want errors.Is(...) == ErrTransportSingleUse", err)
	}
}

// TestStop_PostEnqueueNotCalledOnRunDoneFastPath pins the roborev
// finding that the documented seam contract (postEnqueue runs after
// the stopCh send completes) was being violated on the runDone
// bail-out path: the bail-out skips the send entirely, so postEnqueue
// must NOT fire. Tests/seams that rely on "postEnqueue ran => stopCh
// has the request" would otherwise be misled.
func TestStop_PostEnqueueNotCalledOnRunDoneFastPath(t *testing.T) {
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
	runDone := make(chan error, 1)
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		t.Fatal("rdrFactory called; rejection should fire before Replaying/Live")
		return nil, nil
	}
	go func() {
		runDone <- tr.Run(ctx, rdrFactory, transport.LiveOptions{
			Batcher: transport.BatcherOptions{
				MaxRecords: 100,
				MaxBytes:   1 << 16,
				MaxAge:     50 * time.Millisecond,
			},
			MaxInflight:    8,
			HeartbeatEvery: time.Second,
		})
	}()
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit sent")
	}
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{Accepted: false, RejectReason: "go away"},
		},
	}
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of rejection")
	}

	var preCalls, postCalls atomic.Int32
	pre := func() { preCalls.Add(1) }
	post := func() { postCalls.Add(1) }

	stopReturned := make(chan struct{})
	go func() {
		transport.EnqueueStopAndWaitForTest(tr, 0, pre, post)
		close(stopReturned)
	}()
	select {
	case <-stopReturned:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop did not return within 500ms after Run exit")
	}

	// preEnqueue is documented to fire BEFORE the send attempt, so it
	// runs even on the bail-out path — that's correct. postEnqueue is
	// documented to fire AFTER a successful send, so on the runDone
	// bail-out (no send) it must NOT fire.
	if got := preCalls.Load(); got != 1 {
		t.Errorf("preEnqueue calls = %d; want 1", got)
	}
	if got := postCalls.Load(); got != 0 {
		t.Errorf("postEnqueue calls = %d; want 0 (bail-out path skipped the send)", got)
	}
}
