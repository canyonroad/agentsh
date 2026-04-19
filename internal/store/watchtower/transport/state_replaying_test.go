package transport_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// newReplayingTransport constructs a Transport with the supplied Conn
// already attached so RunReplaying can be exercised in isolation from
// the Connecting state. Mirrors the field assignment runConnecting
// performs after a successful dial.
func newReplayingTransport(t *testing.T, conn transport.Conn) *transport.Transport {
	t.Helper()
	tr, err := transport.New(transport.Options{
		Dialer: transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
			t.Fatal("Dial should not be invoked by Replaying state in isolation")
			return nil, errors.New("unreachable")
		}),
		AgentID:   "test-agent",
		SessionID: "sess-1",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	transport.SetConnForTest(tr, conn)
	return tr
}

// nonEmptyMsg is a non-stub EventBatch builder used by tests that want
// to assert send-path invariants without relying on the empty-message
// stub default. Returns a unique ClientMessage per call so a sequence
// of records produces distinguishable wire frames.
func nonEmptyMsg(_ []wal.Record) (*wtpv1.ClientMessage, error) {
	return &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{
			EventBatch: &wtpv1.EventBatch{
				FromSequence: 1,
				ToSequence:   1,
				Generation:   0,
			},
		},
	}, nil
}

// TestRunReplaying_HappyPathReturnsLiveAndRetainsConn verifies the success
// transition: the Replayer drains 3 records, the Conn observes at least
// one EventBatch send, and runReplaying returns StateLive without
// closing t.conn (the Live state will reuse it).
func TestRunReplaying_HappyPathReturnsLiveAndRetainsConn(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   64 * 1024,
		MaxTotalBytes: 1 << 20,
		SyncMode:      wal.SyncImmediate,
	})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	for i := int64(0); i < 3; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	rdr, err := w.NewReader(0)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	conn := newFakeConn()
	tr := newReplayingTransport(t, conn)

	restore := transport.SetBuildEventBatchFnForTest(nonEmptyMsg)
	defer restore()

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	st, err := tr.RunReplaying(ctx, r)
	if err != nil {
		t.Fatalf("RunReplaying: unexpected error: %v", err)
	}
	if st != transport.StateLive {
		t.Fatalf("state: got %s, want StateLive", st)
	}

	// At least one EventBatch must have hit the wire (3 records,
	// MaxBatchRecords=100 → one combined batch).
	select {
	case <-conn.sendCh:
		// drained one batch; that's the contract.
	default:
		t.Fatal("expected at least one EventBatch send before transition to Live")
	}

	// Conn MUST stay attached for the Live handler. This is the
	// inverse of the runConnecting contract — Replaying is the ONLY
	// per-state handler that retains t.conn across a successful
	// transition.
	if got, want := conn.closeCalls, 0; got != want {
		t.Fatalf("Close calls on happy path: got %d, want %d (Live state owns the conn)", got, want)
	}
	if !transport.HasConnForTest(tr) {
		t.Fatal("Transport.conn was cleared on happy-path RunReplaying; Live handler needs it")
	}
}

// TestRunReplaying_SendFailureClosesConn verifies the per-state error
// invariant: if conn.Send fails partway through replay, runReplaying
// MUST Close() the conn exactly once and clear t.conn before returning
// StateConnecting. This mirrors the runConnecting hold-then-teardown
// pattern. Without the Close+nil pair, the run loop would either reuse
// a dead conn or leak the underlying gRPC stream during reconnect
// backoff.
func TestRunReplaying_SendFailureClosesConn(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   64 * 1024,
		MaxTotalBytes: 1 << 20,
		SyncMode:      wal.SyncImmediate,
	})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	for i := int64(0); i < 3; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	rdr, err := w.NewReader(0)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	conn := newFakeConn()
	conn.sendErr = errors.New("write: broken pipe")
	tr := newReplayingTransport(t, conn)

	restore := transport.SetBuildEventBatchFnForTest(nonEmptyMsg)
	defer restore()

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	st, err := tr.RunReplaying(ctx, r)
	if err == nil {
		t.Fatal("expected error from RunReplaying when Send fails")
	}
	if !strings.Contains(err.Error(), "send EventBatch") {
		t.Fatalf("err: got %v, want substring %q", err, "send EventBatch")
	}
	if st != transport.StateConnecting {
		t.Fatalf("state: got %s, want StateConnecting", st)
	}
	if got, want := conn.closeCalls, 1; got != want {
		t.Fatalf("Close calls: got %d, want %d (every error path on a held Conn must Close exactly once)", got, want)
	}
	if got, want := conn.closeSendCalls, 0; got != want {
		t.Fatalf("CloseSend calls: got %d, want %d (CloseSend is half-close, not teardown)", got, want)
	}
	if transport.HasConnForTest(tr) {
		t.Fatal("Transport.conn must be nil after error path so the next dial replaces it cleanly")
	}
}

// errReader is a Reader-shaped helper exposed via the WAL: it forces
// TryNext to surface a hard error so the replayer-error branch can be
// driven without smashing internal WAL state. We synthesize the error
// path by closing the WAL Reader (Close marks it as "closed" → TryNext
// returns ErrReaderClosed wrapped by Replayer.NextBatch).

// TestRunReplaying_ReplayerErrorClosesConn verifies the replayer-error
// branch: when NextBatch surfaces a non-ctx error (here driven by a
// closed Reader), runReplaying MUST Close + nil t.conn before returning
// StateConnecting.
func TestRunReplaying_ReplayerErrorClosesConn(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   64 * 1024,
		MaxTotalBytes: 1 << 20,
		SyncMode:      wal.SyncImmediate,
	})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()
	if _, err := w.Append(0, 0, []byte{0}); err != nil {
		t.Fatalf("append: %v", err)
	}
	rdr, err := w.NewReader(0)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})

	// Close the Reader BEFORE driving runReplaying so the very first
	// TryNext returns ErrReaderClosed and the replay-error branch
	// fires deterministically.
	if err := rdr.Close(); err != nil {
		t.Fatalf("rdr.Close: %v", err)
	}

	conn := newFakeConn()
	tr := newReplayingTransport(t, conn)

	restore := transport.SetBuildEventBatchFnForTest(nonEmptyMsg)
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	st, err := tr.RunReplaying(ctx, r)
	if err == nil {
		t.Fatal("expected error when Reader returns a hard failure")
	}
	if !strings.Contains(err.Error(), "replay batch") {
		t.Fatalf("err: got %v, want substring %q", err, "replay batch")
	}
	if st != transport.StateConnecting {
		t.Fatalf("state: got %s, want StateConnecting", st)
	}
	if got, want := conn.closeCalls, 1; got != want {
		t.Fatalf("Close calls: got %d, want %d", got, want)
	}
	if got, want := conn.closeSendCalls, 0; got != want {
		t.Fatalf("CloseSend calls: got %d, want %d", got, want)
	}
	if transport.HasConnForTest(tr) {
		t.Fatal("Transport.conn must be nil after error path")
	}
}

// blockingConn wraps fakeConn but stalls Send until the test signals via
// release. Used by the ctx-cancellation test so the replayer is mid-
// drain when ctx is cancelled — proves the cancellation propagates
// through the Replayer's NextBatch ctx check rather than through the
// next blocking I/O call.
type blockingConn struct {
	*fakeConn
	release chan struct{}
}

func (b *blockingConn) Send(msg *wtpv1.ClientMessage) error {
	<-b.release
	return b.fakeConn.Send(msg)
}

// TestRunReplaying_CtxCancelClosesConn verifies the ctx-cancellation
// branch: when ctx is cancelled mid-replay, runReplaying surfaces the
// ctx error AND closes t.conn exactly once. The Replayer's NextBatch
// returns ctx.Err() at the top of its loop, which runReplaying treats
// as any other replay error.
func TestRunReplaying_CtxCancelClosesConn(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   64 * 1024,
		MaxTotalBytes: 1 << 20,
		SyncMode:      wal.SyncImmediate,
	})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	defer w.Close()

	// Enough records that the loop will keep iterating after the
	// blocking Send returns; cancellation must fire BEFORE the
	// replayer reaches done.
	for i := int64(0); i < 5; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	rdr, err := w.NewReader(0)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	bc := &blockingConn{fakeConn: newFakeConn(), release: make(chan struct{})}
	tr := newReplayingTransport(t, bc)

	restore := transport.SetBuildEventBatchFnForTest(nonEmptyMsg)
	defer restore()

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 1, // force one batch per record so the loop iterates
		MaxBatchBytes:   16 * 1024,
	})

	ctx, cancel := context.WithCancel(context.Background())

	type result struct {
		st  transport.State
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		st, err := tr.RunReplaying(ctx, r)
		resCh <- result{st, err}
	}()

	// Cancel BEFORE releasing the blocking Send so the next NextBatch
	// observes ctx.Err(). Then release so the goroutine can exit.
	cancel()
	close(bc.release)

	select {
	case res := <-resCh:
		if res.err == nil {
			t.Fatal("expected error after ctx cancel")
		}
		if !errors.Is(res.err, context.Canceled) {
			t.Fatalf("err: got %v, want errors.Is(context.Canceled)", res.err)
		}
		if res.st != transport.StateConnecting {
			t.Fatalf("state: got %s, want StateConnecting", res.st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunReplaying did not return after ctx cancel")
	}

	if got, want := bc.closeCalls, 1; got != want {
		t.Fatalf("Close calls: got %d, want %d", got, want)
	}
	if got, want := bc.closeSendCalls, 0; got != want {
		t.Fatalf("CloseSend calls: got %d, want %d", got, want)
	}
	if transport.HasConnForTest(tr) {
		t.Fatal("Transport.conn must be nil after ctx-cancel error path")
	}
}
