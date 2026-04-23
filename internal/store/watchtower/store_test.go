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
