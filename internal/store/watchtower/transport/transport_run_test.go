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
// subsequent successful dial advances the loop into Replaying. Then
// it forces Replaying to fail (rdrFactory error) and asserts the loop
// regresses to StateConnecting and re-dials — i.e. the full
// dial-fail → dial-ok → replay-fail → re-dial cycle is exercised, not
// just "any number of dials >= 2".
//
// Sequence:
//   attempt 1: dial returns error    → backoff, retry
//   attempt 2: dial returns conn,    → SessionInit + accepted SessionAck
//                                       → StateReplaying
//                                     → rdrFactory fails               → StateConnecting
//   attempt 3: dial returns conn,    → SessionInit observed; cancel
//
// Without this end-to-end shape, a regression where Replaying-failure
// fails to regress to Connecting (or fails to re-dial) would still
// pass a "dials >= 2" assertion.
func TestRun_RetriesTransientDialFailureUntilSuccess(t *testing.T) {
	var attempts atomic.Int32
	conn2 := newFakeConn()
	conn3 := newFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		n := attempts.Add(1)
		if n == 1 {
			return nil, errors.New("transient dial fail")
		}
		if n == 2 {
			return conn2, nil
		}
		// Run-loop now closes the held conn on rdrFactory failure
		// (regressToConnecting helper) to avoid leaking conn + recv;
		// the third dial therefore needs a fresh conn rather than
		// reusing conn2 (which would have been Close'd).
		return conn3, nil
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

	// === attempt 2: drain SessionInit, ack accepted, drive into Replaying.
	select {
	case <-conn2.sendCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no SessionInit on second attempt within 2s")
	}
	conn2.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{
				Accepted:            true,
				AckHighWatermarkSeq: 0,
				Generation:          0,
			},
		},
	}
	select {
	case <-rdrAttempts:
	case <-time.After(2 * time.Second):
		t.Fatal("rdrFactory was not invoked; Run did not reach Replaying")
	}

	// === attempt 3: replay failure should regress to Connecting and
	// re-dial. Observe a third SessionInit on the FRESH conn — proves
	// the replay-failure → reconnect cycle, not just "loop ran twice."
	select {
	case <-conn3.sendCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("no SessionInit on third attempt; replay-failure did not regress to Connecting (dial attempts=%d)", attempts.Load())
	}
	if got := attempts.Load(); got < 3 {
		t.Fatalf("dial attempts: got %d, want >= 3 (transient + success + post-replay-failure re-dial)", got)
	}

	cancel()
	// fakeConn.Recv does not honor ctx; close the third conn so the
	// runConnecting Recv unblocks and the Run loop sees ctx.Done() on
	// the next iteration.
	_ = conn3.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}
}

// TestRun_StartsRecvGoroutineAfterAcceptedSessionAck closes SCAFFOLDING
// item #1: "Run never calls newRecvSession / runRecv after a successful
// dial, so runLive's recv arms remain dormant via Go nil-channel
// semantics." After the SessionAck-accepted handshake completes, the
// recv goroutine MUST be running so that runReplaying / runLive can
// observe BatchAck, ServerHeartbeat, Goaway, and stream errors.
//
// This is the load-bearing prerequisite for every component test that
// exercises server-initiated stream behaviour (Tasks 25, 26).
func TestRun_StartsRecvGoroutineAfterAcceptedSessionAck(t *testing.T) {
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

	// Pre-condition: no recv goroutine before Run starts.
	if rsh := transport.RecvSessionForTest(tr); rsh != nil {
		t.Fatalf("RecvSessionForTest pre-Run = %v, want nil", rsh)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Block rdrFactory so the recv goroutine state is observable
	// BEFORE the test could regress through StateLive's failure path
	// and tear it down.
	rdrFactoryEntered := make(chan struct{}, 1)
	rdrFactoryRelease := make(chan struct{})
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		select {
		case rdrFactoryEntered <- struct{}{}:
		default:
		}
		<-rdrFactoryRelease
		return nil, errors.New("test: no replay reader")
	}
	runDone := make(chan error, 1)
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

	// Drain SessionInit, accept the session.
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit sent")
	}
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{Accepted: true},
		},
	}

	// Wait for rdrFactory to be entered. At this point the run loop
	// has crossed runConnecting → StateReplaying → StateLive and is
	// blocked inside our gated rdrFactory; the recv goroutine started
	// in runConnecting MUST be alive.
	select {
	case <-rdrFactoryEntered:
	case <-time.After(1 * time.Second):
		t.Fatal("rdrFactory was not entered within 1s of SessionAck")
	}

	if rsh := transport.RecvSessionForTest(tr); rsh == nil {
		t.Fatal("recv goroutine never started after accepted SessionAck (SCAFFOLDING ONLY item #1 still open)")
	}

	close(rdrFactoryRelease)
	cancel()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}
}

// TestRun_NoRecvLeakOnReaderFactoryFailure pins the roborev High
// finding: if a post-SessionAck path regresses to StateConnecting
// without runReplaying / runLive taking ownership, the recv goroutine
// started in runConnecting must be torn down — otherwise the next
// dial's startRecv overwrites t.recv and the orphaned goroutine
// races the new connection through the shared t.conn pointer.
//
// We block rdrFactory until the test has observed the recv goroutine,
// then unblock with an error to drive StateLive → StateConnecting.
// rsh.Done() must close before the next dial, proving teardown ran.
func TestRun_NoRecvLeakOnReaderFactoryFailure(t *testing.T) {
	conn := newFakeConn()
	dialAttempts := 0
	gateSecondDial := make(chan struct{})
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		dialAttempts++
		if dialAttempts == 1 {
			return conn, nil
		}
		// Block the second dial so the first recv-session lifecycle
		// is observable before the next iteration races us.
		<-gateSecondDial
		return nil, errors.New("dial gate released")
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
	rdrFactoryEntered := make(chan struct{}, 1)
	rdrFactoryRelease := make(chan struct{})
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		// Signal entry; test inspects recv state, then releases.
		select {
		case rdrFactoryEntered <- struct{}{}:
		default:
		}
		<-rdrFactoryRelease
		return nil, errors.New("test: rdrFactory always fails")
	}
	runDone := make(chan error, 1)
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

	// SessionInit + accept.
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit sent")
	}
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{Accepted: true},
		},
	}

	// Wait for rdrFactory to be entered — at this point startRecv has
	// run AND we are still inside the StateLive setup before regress.
	select {
	case <-rdrFactoryEntered:
	case <-time.After(1 * time.Second):
		t.Fatal("rdrFactory was not entered within 1s of SessionAck")
	}

	rsh := transport.RecvSessionForTest(tr)
	if rsh == nil {
		t.Fatal("recv goroutine not running at rdrFactory entry; startRecv did not fire")
	}

	// Release rdrFactory (which returns an error → regressToConnecting).
	close(rdrFactoryRelease)

	// rsh.Done() closes when runRecv exits via teardown's
	// cancel + close(rs.done) sequence. Without the fix, teardown
	// is skipped on this leak path and the goroutine is orphaned.
	select {
	case <-rsh.Done():
	case <-time.After(1 * time.Second):
		t.Fatal("recv goroutine still running after rdrFactory failure; teardown leaked the recvSession")
	}

	close(gateSecondDial)
	cancel()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}
}

// TestRun_NoRecvLeakOnOuterCtxCancel pins the roborev Medium round-3
// finding by exercising specifically the outer Run-loop top-of-iteration
// ctx.Done() branch — NOT the rdrFactory regress path.
//
// Determinism trick (round-4 follow-up): cancel ctx BEFORE sending
// SessionAck. fakeConn.Recv does not honor ctx, so the run loop is
// blocked in conn.Recv() inside runConnecting and does not observe
// the cancel. When SessionAck arrives, runConnecting completes,
// startRecv runs, and the StateConnecting case sets st = StateReplaying
// and falls through. The NEXT iteration's top-of-loop select then
// sees ctx.Done() — and ONLY the outer ctx.Done branch teardown can
// fire here (rdrFactory was never called). Removing the outer
// regressToConnecting() call from that branch would leave the recv
// goroutine alive, failing this test.
func TestRun_NoRecvLeakOnOuterCtxCancel(t *testing.T) {
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
	rdrFactoryCalled := make(chan struct{}, 1)
	rdrFactory := func(uint32, uint64) (*wal.Reader, error) {
		select {
		case rdrFactoryCalled <- struct{}{}:
		default:
		}
		return nil, errors.New("rdrFactory should not be reached")
	}
	runDone := make(chan error, 1)
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

	// Drain SessionInit (run loop is now in conn.Recv waiting for ack).
	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit sent")
	}

	// Cancel ctx BEFORE the ack arrives. fakeConn.Recv ignores ctx so
	// the run loop continues to wait on conn.recvCh.
	cancel()

	// Now deliver the ack. Run loop unblocks, ackSessionAck runs,
	// startRecv runs, st = StateReplaying, continue → next iteration's
	// select sees ctx.Done() and the OUTER teardown fires.
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{Accepted: true},
		},
	}

	// Run must return ctx.Canceled with no leaked goroutine. If the
	// outer ctx.Done branch were missing the regressToConnecting call,
	// runRecv would still be alive after Run returns — we detect this
	// by asserting Run returns AND no rdrFactory call ever happened
	// (proving we did not pass through StateLive's regress path).
	select {
	case got := <-runDone:
		if !errors.Is(got, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel")
	}

	select {
	case <-rdrFactoryCalled:
		t.Fatal("rdrFactory was reached; test no longer isolates the outer ctx.Done teardown path")
	default:
	}

	// After Run returns, t.recv MUST be nil. This is the load-bearing
	// assertion: the outer ctx.Done branch is the ONLY teardown path
	// reachable in this test, so a nil t.recv proves the branch fired
	// regressToConnecting (which sets t.recv = nil via teardownRecv).
	if rsh := transport.RecvSessionForTest(tr); rsh != nil {
		t.Fatal("recv goroutine still attached after Run returned; outer ctx.Done branch leaked")
	}
}

// TestRunOnce_DoesNotStartRecvGoroutine pins the roborev Medium
// round-3 finding: RunOnce(StateConnecting) is a single-transition
// seam used by transport-level tests; it MUST NOT leave a live
// recvSession with no owner. Run owns the recv lifecycle (calling
// startRecv after a successful runConnecting), so RunOnce by design
// does NOT start one.
func TestRunOnce_DoesNotStartRecvGoroutine(t *testing.T) {
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

	type res struct {
		st  transport.State
		err error
	}
	done := make(chan res, 1)
	go func() {
		st, e := tr.RunOnce(ctx, transport.StateConnecting)
		done <- res{st, e}
	}()

	select {
	case <-conn.sendCh:
	case <-time.After(1 * time.Second):
		t.Fatal("no SessionInit sent")
	}
	conn.recvCh <- &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{Accepted: true},
		},
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("RunOnce returned err: %v", r.err)
		}
		if r.st != transport.StateReplaying {
			t.Fatalf("RunOnce next state: got %v, want StateReplaying", r.st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunOnce did not return within 2s of SessionAck")
	}

	// CRITICAL: RunOnce must not have started the recv goroutine.
	// Run owns that lifecycle so a single-transition seam does not
	// leak a recvSession with no teardown owner.
	if rsh := transport.RecvSessionForTest(tr); rsh != nil {
		t.Fatal("RunOnce(StateConnecting) leaked a recvSession; Run should own startRecv, not runConnecting")
	}
}
