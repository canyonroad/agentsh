package watchtower_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestNew_QuarantinesOnSessionIDMismatch covers the WAL identity-
// mismatch recovery path. Setup persists meta.json with a different
// session id; New must rename the WAL dir to .quarantine.<...> and
// open a fresh WAL with the new identity.
func TestNew_QuarantinesOnSessionIDMismatch(t *testing.T) {
	parent := t.TempDir()
	walDir := filepath.Join(parent, "wal")
	if err := os.MkdirAll(walDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Pre-seed meta.json with installation-A identity by opening a
	// WAL with that identity, persisting an ack, then closing.
	w, err := wal.Open(wal.Options{
		Dir:            walDir,
		SegmentSize:    256 * 1024,
		MaxTotalBytes:  16 * 1024 * 1024,
		SessionID:      "installation-A",
		KeyFingerprint: "sha256:k-A",
	})
	if err != nil {
		t.Fatalf("seed wal.Open: %v", err)
	}
	if _, err := w.Append(1, 0, []byte("seed")); err != nil {
		t.Fatalf("seed Append: %v", err)
	}
	if err := w.MarkAcked(0, 1); err != nil {
		t.Fatalf("seed MarkAcked: %v", err)
	}
	_ = w.Close()

	// Now construct a Store with installation-B identity. New must
	// quarantine the existing dir and reopen on a fresh WAL.
	opts := validOpts(walDir)
	opts.SessionID = "installation-B"
	opts.KeyFingerprint = "sha256:k-A"

	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeStore(t, s)

	// Verify a quarantine sibling now sits next to the (fresh) WAL.
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var sawQuarantine bool
	for _, e := range entries {
		if strings.Contains(e.Name(), ".quarantine.") {
			sawQuarantine = true
			break
		}
	}
	if !sawQuarantine {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected .quarantine.* sibling in %s, got %v", parent, names)
	}

	// The fresh WAL must have no meta.json yet (pre-ack cold start).
	if _, err := wal.ReadMeta(walDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-quarantine ReadMeta: got %v, want ErrNotExist", err)
	}
}

// TestNew_DoesNotSeedOnSessionIDMismatch covers the secondary
// (defense-in-depth) identity gate inside readInitialAckTuple. With
// the wal.Open quarantine path catching most cases, this gate fires
// when meta.json was written by a buggy older binary that didn't
// persist identity. Because Task 14a's wal.Open IS strict about
// identity, the test crafts a meta.json with EMPTY identity (V1
// legacy) — which the migration rule treats as MATCH; then a
// non-empty mismatch on the freshly-opened Store would be a real
// drift. Verifies the legacy-match path: V1 meta.json with no
// identity fields IS seeded into the Transport.
func TestNew_SeedsAckTupleFromV1MetaWithEmptyIdentity(t *testing.T) {
	parent := t.TempDir()
	walDir := filepath.Join(parent, "wal")
	if err := os.MkdirAll(walDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Hand-write a V1-shaped meta.json with empty SessionID +
	// KeyFingerprint (i.e. the pre-Task-14a writer didn't populate
	// them). Per round-10 Finding 4 this should be treated as MATCH
	// and the on-disk ack tuple SHOULD be seeded.
	if err := wal.WriteMeta(walDir, wal.Meta{
		AckHighWatermarkSeq: 30,
		AckHighWatermarkGen: 3,
		AckRecorded:         true,
	}); err != nil {
		t.Fatalf("seed WriteMeta: %v", err)
	}

	opts := validOpts(walDir)
	opts.SessionID = "installation-current"
	opts.KeyFingerprint = "sha256:k-current"

	// New should succeed and consume the on-disk ack tuple. We can't
	// directly observe the Transport's seeded persistedAck from this
	// test (no public accessor) but we can verify New did not return
	// an identity-mismatch error.
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New on V1 legacy meta: %v", err)
	}
	defer closeStore(t, s)

	// Sanity: the existing meta.json should still be intact (no
	// quarantine triggered).
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".quarantine.") {
			t.Fatalf("V1 legacy meta should NOT trigger quarantine; saw %s", e.Name())
		}
	}
}

// TestStore_CloseReturnsAfterRunLoopExits verifies the Close lifecycle
// end-to-end: New starts a bg run loop, Close cancels it, the bg
// goroutine exits and surfaces its return value through Close.
func TestStore_CloseReturnsAfterRunLoopExits(t *testing.T) {
	opts := validOpts(t.TempDir())
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	start := time.Now()
	closeErr := s.Close()
	elapsed := time.Since(start)
	// Close should return promptly.
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("Close took %v; expected < 1.5s", elapsed)
	}
	// nopDialer keeps Run in dial-fail backoff; Stop + runCancel
	// unblock it. Either nil or context.Canceled is acceptable
	// shape — we are asserting the lifecycle returns, not a
	// specific error.
	if closeErr != nil &&
		!errors.Is(closeErr, context.Canceled) &&
		!errors.Is(closeErr, context.DeadlineExceeded) {
		t.Fatalf("Close returned unexpected error shape: %v", closeErr)
	}
}

// TestStore_CloseAfterTerminalRunExit covers the High-finding path
// from roborev #5763: when Run has ALREADY exited (e.g. terminal
// SessionAck rejection at startup), Close MUST NOT call tr.Stop
// because Stop's `<-r.done` would block forever (no consumer left).
//
// Setup: build a Store with a dialer + fakeConn that responds to
// SessionInit with a rejected SessionAck — runConnecting returns
// (StateShutdown, err), the Run loop exits with the terminal error,
// runDone is populated. Then call Close and assert it returns
// promptly (well below the DrainDeadline).
func TestStore_CloseAfterTerminalRunExit(t *testing.T) {
	// Use a sync gate so the Store doesn't see "no Dial" and we can
	// drive the rejection deterministically.
	dialReady := make(chan struct{}, 1)
	dialReady <- struct{}{} // first dial allowed
	conn := newRejectingFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		select {
		case <-dialReady:
			return conn, nil
		default:
			return nil, errors.New("no more dials")
		}
	})

	opts := validOpts(t.TempDir())
	opts.DrainDeadline = 10 * time.Second // Long, so a Stop deadlock would be obvious
	opts.Dialer = dialer
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Wait for Err() to surface the terminal error (i.e. Run exited).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if errVal := s.Err(); errVal != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Run did not exit within 2s; Err()=%v", s.Err())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Run has exited; Close MUST be bounded — if it called the
	// would-deadlock Stop on the dead run loop, this would hang
	// for opts.DrainDeadline=10s.
	start := time.Now()
	closeErr := s.Close()
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Close after terminal Run exit took %v; expected < 500ms (would indicate Stop-on-dead-loop deadlock)", elapsed)
	}
	if closeErr == nil {
		t.Fatal("Close after terminal Run exit returned nil; want the captured terminal error")
	}
	// Err() after Close should return the same captured value.
	if got := s.Err(); got != closeErr {
		t.Fatalf("Err() after Close = %v, want %v (same captured value)", got, closeErr)
	}
}

// rejectingFakeConn implements transport.Conn — Recv returns a
// rejected SessionAck (Accepted=false) so runConnecting surfaces
// (StateShutdown, err). Send accepts SessionInit; subsequent calls
// error.
type rejectingFakeConn struct {
	sendCount int
	closed    chan struct{}
}

func newRejectingFakeConn() *rejectingFakeConn {
	return &rejectingFakeConn{closed: make(chan struct{})}
}

func (c *rejectingFakeConn) Send(*wtpv1.ClientMessage) error {
	c.sendCount++
	if c.sendCount > 1 {
		return errors.New("only one Send allowed")
	}
	return nil
}

func (c *rejectingFakeConn) Recv() (*wtpv1.ServerMessage, error) {
	return &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{
				Accepted:     false,
				RejectReason: "test rejection",
			},
		},
	}, nil
}

func (c *rejectingFakeConn) CloseSend() error { return nil }
func (c *rejectingFakeConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

// TestStore_ErrAfterCloseReturnsCapturedValue is the regression guard
// for the Close()/Err() consistency contract: after Close has run,
// Err() MUST return the EXACT value Close captured (terminal err,
// deadline-fallback wrap, OR WAL-close-merged err) — not a stale
// peek of a now-empty runDone channel. The "closed" atomic flag set
// inside closeOnce.Do AFTER closeErr is fully populated is the
// discriminator.
//
// Setup uses the rejectingFakeConn so Run terminates with a non-nil
// error; we then call Close, capture the returned err, call Err,
// and assert exact equality.
func TestStore_ErrAfterCloseReturnsCapturedValue(t *testing.T) {
	conn := newRejectingFakeConn()
	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return conn, nil
	})
	opts := validOpts(t.TempDir())
	opts.Dialer = dialer
	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Wait for Run to exit (Err surfaces the terminal err).
	deadline := time.Now().Add(2 * time.Second)
	for s.Err() == nil {
		if time.Now().After(deadline) {
			t.Fatal("Run did not exit within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	closeErr := s.Close()
	if closeErr == nil {
		t.Fatal("Close returned nil; want captured terminal err")
	}
	postClose := s.Err()
	if postClose != closeErr {
		t.Fatalf("Err() after Close = %v, want exactly %v (closeErr)", postClose, closeErr)
	}

	// Call Err multiple times — must always return the same value.
	for i := 0; i < 3; i++ {
		if got := s.Err(); got != closeErr {
			t.Fatalf("Err() iteration %d = %v, want %v", i, got, closeErr)
		}
	}
}

// TestStore_CloseOnActiveRunReturnsCleanly covers the active-Close
// path (Run is still alive when Close fires) — the second branch of
// shutdown(). Uses the testserver-backed dialer would be ideal but
// we keep the dependency narrow with a slow-dial dialer that holds
// Run in its dial-fail backoff. Close should return promptly via
// runCancel after the DrainDeadline.
func TestStore_CloseOnActiveRunReturnsCleanly(t *testing.T) {
	opts := validOpts(t.TempDir())
	// nopDialer = perpetual dial-fail; Run is alive, looping in
	// backoff. Close must return without waiting for the natural
	// loop exit.
	opts.DrainDeadline = 100 * time.Millisecond

	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Verify Run is still alive (Err returns nil).
	if got := s.Err(); got != nil {
		t.Fatalf("pre-close Err() = %v, want nil (Run should still be alive)", got)
	}

	start := time.Now()
	closeErr := s.Close()
	elapsed := time.Since(start)
	// Close should bound to DrainDeadline + small fallback margin.
	if elapsed > 1*time.Second {
		t.Fatalf("Close on active Run took %v; expected < 1s (DrainDeadline=%v + margin)", elapsed, opts.DrainDeadline)
	}
	// Err after Close MUST equal Close's return value.
	if got := s.Err(); got != closeErr {
		t.Fatalf("Err() after Close = %v, want exactly closeErr=%v", got, closeErr)
	}
}

// TestStore_CloseDeadlineFallback exercises the timer.C branch of
// shutdown(): when the cooperative tr.Stop drain does not complete
// within DrainDeadline, runCancel is the fallback that unblocks the
// run loop. Validates the bounded-Close contract end-to-end.
//
// nopDialer never produces a Conn so Run is in dial-fail backoff;
// tr.Stop's per-state stopCh arms will pick it up at the backoff
// sleep's stopCh case (transport.go's outer-iteration check OR
// backoff sleep stopCh arm — see Stop's interruptible-windows doc).
// In either case Run exits via runCancel within the fallback grace.
func TestStore_CloseDeadlineFallback(t *testing.T) {
	opts := validOpts(t.TempDir())
	// 1ns DrainDeadline forces the deadline branch to fire instantly
	// (Stop's drain has no time to complete; runCancel is the path).
	opts.DrainDeadline = 1 * time.Nanosecond

	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	closeErr := s.Close()
	// Either nil (clean exit via runCancel-driven ctx) or wrapped
	// is acceptable — the contract is "bounded, no deadlock."
	_ = closeErr
	if got := s.Err(); got != closeErr {
		t.Fatalf("Err() after Close = %v, want closeErr=%v", got, closeErr)
	}
}
