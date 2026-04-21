package transport_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// recvFakeConn is a per-test Conn that drives the recv goroutine via
// a buffered queue of *wtpv1.ServerMessage frames. Recv() pops the
// next queued frame; once the queue drains it blocks until either
// (a) more frames are pushed (via the test) or (b) Close() is called,
// at which point Recv returns the configured eofErr.
//
// The fake intentionally does NOT implement the wire-protocol Send/CloseSend
// paths used by the Connecting handshake — it is a Recv-only fixture
// for the recv-multiplexer integration tests below. Send/CloseSend are
// no-ops returning nil; tests should NOT exercise the send path through
// this fake.
type recvFakeConn struct {
	mu       sync.Mutex
	queue    []*wtpv1.ServerMessage
	cond     *sync.Cond
	closed   bool
	eofErr   error
	recvErr  error
}

func newRecvFakeConn() *recvFakeConn {
	c := &recvFakeConn{
		eofErr: errors.New("recv: stream closed by peer"),
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// Push enqueues a frame for the next Recv() to pop. Goroutine-safe.
func (c *recvFakeConn) Push(msg *wtpv1.ServerMessage) {
	c.mu.Lock()
	c.queue = append(c.queue, msg)
	c.cond.Broadcast()
	c.mu.Unlock()
}

// SetRecvErr arms a one-shot error to be returned by the NEXT Recv()
// call (instead of pulling from the queue). Use to simulate stream
// errors mid-test.
func (c *recvFakeConn) SetRecvErr(err error) {
	c.mu.Lock()
	c.recvErr = err
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *recvFakeConn) Send(_ *wtpv1.ClientMessage) error { return nil }
func (c *recvFakeConn) CloseSend() error                  { return nil }
func (c *recvFakeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}
func (c *recvFakeConn) Recv() (*wtpv1.ServerMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.recvErr != nil {
			err := c.recvErr
			c.recvErr = nil
			return nil, err
		}
		if len(c.queue) > 0 {
			msg := c.queue[0]
			c.queue = c.queue[1:]
			return msg, nil
		}
		if c.closed {
			return nil, c.eofErr
		}
		c.cond.Wait()
	}
}

// recvBatchAck is a one-line constructor for a BatchAck server message.
func recvBatchAck(gen uint32, seq uint64) *wtpv1.ServerMessage {
	return &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_BatchAck{
			BatchAck: &wtpv1.BatchAck{
				AckHighWatermarkSeq: seq,
				Generation:          gen,
			},
		},
	}
}

// recvHeartbeat is a one-line constructor for a ServerHeartbeat server
// message. The proto carries no generation field; the recv multiplexer
// substitutes t.persistedAck.Generation at apply time.
func recvHeartbeat(seq uint64) *wtpv1.ServerMessage {
	return &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_ServerHeartbeat{
			ServerHeartbeat: &wtpv1.ServerHeartbeat{
				AckHighWatermarkSeq: seq,
			},
		},
	}
}

// newIntegrationTransport constructs a Transport with no WAL and a
// dialer that always returns the supplied fake conn. The fake conn
// is also attached via SetConnForTest so the test can drive the recv
// goroutine without going through runConnecting.
func newIntegrationTransport(t *testing.T, fc *recvFakeConn) *transport.Transport {
	t.Helper()
	tr, err := transport.New(transport.Options{
		Dialer: transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
			return fc, nil
		}),
		AgentID:   "test-agent",
		SessionID: "sess-recv-int",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	transport.SetConnForTest(tr, fc)
	return tr
}

// drainEvent pops the next event off the recv eventCh within the given
// timeout, failing the test if none arrives.
func drainEvent(t *testing.T, h *transport.RecvSessionHandle, timeout time.Duration) (string, uint32, uint64) {
	t.Helper()
	select {
	case ev := <-h.EventCh():
		return transport.FrameForTest(ev), transport.GenForTest(ev), transport.SeqForTest(ev)
	case <-time.After(timeout):
		t.Fatalf("drainEvent: no event within %s", timeout)
		return "", 0, 0
	}
}

// ===== Round-22 Test 1 =====
// TestRecvMultiplexer_PreservesWireOrderingAcrossBatchAckAndHeartbeat —
// round-22 Finding 1. Drive a deterministic mixed sequence of BatchAck
// and ServerHeartbeat frames; assert the events reach the main
// goroutine via eventCh in the SAME order they were pushed onto Recv.
// This is the load-bearing invariant for the heartbeat-generation
// substitution rule.
func TestRecvMultiplexer_PreservesWireOrderingAcrossBatchAckAndHeartbeat(t *testing.T) {
	t.Parallel()

	fc := newRecvFakeConn()
	tr := newIntegrationTransport(t, fc)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h := transport.StartRecvForTest(tr, ctx)
	// Close the fake conn BEFORE teardown so the recv goroutine returns
	// from the blocking Recv() call (which cond.Wait() does not unblock
	// on ctx-cancel alone). teardownRecv waits for the goroutine to
	// signal done, so without the prior Close it would deadlock.
	defer transport.TeardownRecvForTest(tr)
	defer fc.Close()

	// Wire-order push: BatchAck(1, 100), HB(99), BatchAck(1, 200), HB(150).
	// Heartbeats keep gen=0 on the wire (the multiplexer leaves it zero
	// and substitutes at apply time on the main goroutine).
	pushSeq := []struct {
		frame string
		gen   uint32
		seq   uint64
		msg   *wtpv1.ServerMessage
	}{
		{"batch_ack", 1, 100, recvBatchAck(1, 100)},
		{"server_heartbeat", 0, 99, recvHeartbeat(99)},
		{"batch_ack", 1, 200, recvBatchAck(1, 200)},
		{"server_heartbeat", 0, 150, recvHeartbeat(150)},
	}
	for _, p := range pushSeq {
		fc.Push(p.msg)
	}

	for i, want := range pushSeq {
		gotFrame, gotGen, gotSeq := drainEvent(t, h, time.Second)
		if gotFrame != want.frame {
			t.Fatalf("event[%d] frame: got %q, want %q", i, gotFrame, want.frame)
		}
		if gotGen != want.gen {
			t.Fatalf("event[%d] gen: got %d, want %d", i, gotGen, want.gen)
		}
		if gotSeq != want.seq {
			t.Fatalf("event[%d] seq: got %d, want %d", i, gotSeq, want.seq)
		}
	}
}

// ===== Round-22 Test 2 =====
// TestRecvMultiplexer_ReconnectDoesNotLeakStateAcrossSessions —
// round-22 Finding 2. Start one recvSession, drain it, tear it down,
// start a fresh recvSession. Assert: (a) the new session's eventCh
// is empty (no stale event from the first session bleeds through),
// (b) the new session's ctx is alive, (c) the OLD session's ctx is
// cancelled.
func TestRecvMultiplexer_ReconnectDoesNotLeakStateAcrossSessions(t *testing.T) {
	t.Parallel()

	fc1 := newRecvFakeConn()
	tr := newIntegrationTransport(t, fc1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h1 := transport.StartRecvForTest(tr, ctx)
	fc1.Push(recvBatchAck(1, 100))
	if frame, _, seq := drainEvent(t, h1, time.Second); frame != "batch_ack" || seq != 100 {
		t.Fatalf("session 1 first event: got (%q, %d), want (batch_ack, 100)", frame, seq)
	}

	// Tear down the first session — close the fake conn first so the
	// recv goroutine returns from its blocking Recv() (cond-wait does
	// not unblock on ctx-cancel alone). teardownRecv waits for the
	// goroutine to signal done; that signal arrives only AFTER Recv
	// returns, hence the explicit fc1.Close() ahead of teardown.
	fc1.Close()
	transport.TeardownRecvForTest(tr)
	if err := h1.Ctx().Err(); err == nil {
		t.Fatal("session 1 ctx still alive after teardown")
	}

	// Re-attach a fresh fake conn (mirrors what runConnecting would do
	// after a redial) and start a new recvSession.
	fc2 := newRecvFakeConn()
	transport.SetConnForTest(tr, fc2)
	h2 := transport.StartRecvForTest(tr, ctx)
	defer transport.TeardownRecvForTest(tr)
	defer fc2.Close()

	// New session's eventCh must be empty — no stale events from
	// session 1 may have crossed into session 2.
	if got := h2.EventLen(); got != 0 {
		t.Fatalf("session 2 eventCh: got %d queued events, want 0 (stale leak)", got)
	}
	if err := h2.Ctx().Err(); err != nil {
		t.Fatalf("session 2 ctx: got %v, want alive", err)
	}

	// Sanity check: session 2 demuxes its own frames cleanly.
	fc2.Push(recvBatchAck(2, 50))
	if frame, gen, seq := drainEvent(t, h2, time.Second); frame != "batch_ack" || gen != 2 || seq != 50 {
		t.Fatalf("session 2 first event: got (%q, %d, %d), want (batch_ack, 2, 50)", frame, gen, seq)
	}
}

// ===== Round-22 Test 3 =====
// TestRecvMultiplexer_PerConnectionCancelUnblocksBlockedRecv —
// round-22 Finding 2. Fill the recv eventCh to capacity, push one
// more frame so the recv goroutine blocks on send, then trigger
// per-connection cancel. Assert the recv goroutine exits within a
// short timeout. This is the load-bearing assertion that the
// per-connection ctx (NOT the transport-wide ctx) is what unblocks
// the recv goroutine.
func TestRecvMultiplexer_PerConnectionCancelUnblocksBlockedRecv(t *testing.T) {
	t.Parallel()

	fc := newRecvFakeConn()
	tr := newIntegrationTransport(t, fc)

	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := transport.StartRecvForTest(tr, parent)
	// Defer cleanup so the goroutine exits cleanly even on test failure
	// paths (Close before Teardown — see ordering test for the reason).
	defer transport.TeardownRecvForTest(tr)
	defer fc.Close()

	// Fill the eventCh to capacity. The recv goroutine pushes events
	// as fast as Recv() returns frames, so once the buffer fills the
	// next push will block on send until either (a) main drains, or
	// (b) per-connection ctx is cancelled.
	cap := h.EventCap()
	for i := 0; i < cap; i++ {
		fc.Push(recvBatchAck(uint32(i+1), uint64(i+1)*10))
	}

	// Wait for the goroutine to drain the queue into the channel.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if h.EventLen() == cap {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if h.EventLen() != cap {
		t.Fatalf("eventCh fill: got len=%d, want %d", h.EventLen(), cap)
	}

	// Push the wedge frame; the recv goroutine will block on send.
	fc.Push(recvBatchAck(99, 9999))

	// Verify nothing else escapes the channel — main is "wedged"
	// (we never drain). A small delay confirms the recv goroutine
	// is actually blocked rather than racing the assertion.
	time.Sleep(20 * time.Millisecond)
	if h.EventLen() != cap {
		t.Fatalf("eventCh leaked past wedge: got len=%d, want %d", h.EventLen(), cap)
	}

	// Trigger per-connection cancel. The recv goroutine MUST observe
	// rs.ctx.Done() in its blocking select and exit immediately.
	cancelStart := time.Now()
	h.Cancel()

	// Drain enough events to unblock the goroutine for verification.
	// We expect the recv goroutine to be gone by the time the cancel
	// returns; we drain to give it a clean exit window.
	go func() {
		// Drain at most cap+1 events to allow the wedge frame to
		// arrive if the goroutine wakes up; we don't depend on this
		// for the assertion below.
		for i := 0; i < cap+1; i++ {
			select {
			case <-h.EventCh():
			case <-time.After(100 * time.Millisecond):
				return
			}
		}
	}()

	// Wait for the recv goroutine's ctx to register cancellation.
	deadline = time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if h.Ctx().Err() != nil {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if h.Ctx().Err() == nil {
		t.Fatalf("recv ctx still alive %s after cancel", time.Since(cancelStart))
	}

	// The transport-wide parent ctx must still be alive — the
	// per-connection cancel must NOT propagate up.
	if parent.Err() != nil {
		t.Fatalf("parent ctx unexpectedly cancelled: %v", parent.Err())
	}
}

// ===== Round-22 Test 4a =====
// TestRecvMultiplexer_GoawaySurfacesFailClosedError — round-22
// Finding 4. The recv goroutine MUST surface a fatal error onto
// errCh when it sees a Goaway frame (instead of silently dropping).
// Tasks 18/19/20 will replace the branch with a real handler.
func TestRecvMultiplexer_GoawaySurfacesFailClosedError(t *testing.T) {
	t.Parallel()

	fc := newRecvFakeConn()
	tr := newIntegrationTransport(t, fc)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h := transport.StartRecvForTest(tr, ctx)
	defer transport.TeardownRecvForTest(tr)
	defer fc.Close()

	fc.Push(&wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_Goaway{
			Goaway: &wtpv1.Goaway{},
		},
	})

	select {
	case err := <-h.ErrCh():
		if err == nil {
			t.Fatal("errCh delivered nil error")
		}
		if !strings.Contains(err.Error(), "goaway") {
			t.Fatalf("error message: got %q, want substring 'goaway'", err.Error())
		}
	case <-time.After(time.Second):
		t.Fatal("recv did not surface Goaway as fail-closed error")
	}
}

// ===== Round-22 Test 4b =====
// TestRecvMultiplexer_SessionUpdateSurfacesFailClosedError — sibling
// of the Goaway test. ServerUpdate frames must also fail-closed under
// round-22 Finding 4 until a real handler lands in Tasks 18/19/20.
func TestRecvMultiplexer_SessionUpdateSurfacesFailClosedError(t *testing.T) {
	t.Parallel()

	fc := newRecvFakeConn()
	tr := newIntegrationTransport(t, fc)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h := transport.StartRecvForTest(tr, ctx)
	defer transport.TeardownRecvForTest(tr)
	defer fc.Close()

	fc.Push(&wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_ServerUpdate{
			ServerUpdate: &wtpv1.SessionUpdate{},
		},
	})

	select {
	case err := <-h.ErrCh():
		if err == nil {
			t.Fatal("errCh delivered nil error")
		}
		if !strings.Contains(err.Error(), "session_update") {
			t.Fatalf("error message: got %q, want substring 'session_update'", err.Error())
		}
	case <-time.After(time.Second):
		t.Fatal("recv did not surface ServerUpdate as fail-closed error")
	}
}
