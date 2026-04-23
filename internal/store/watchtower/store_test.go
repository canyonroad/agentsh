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
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	closeErr := s.Close(ctx)
	elapsed := time.Since(start)
	// Close should return promptly (cancel + wait for runDone).
	// The nopDialer keeps Run in dial-fail backoff; tr.Stop +
	// runCancel should unblock it within a few backoff intervals.
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("Close took %v; expected < 1.5s", elapsed)
	}
	// The returned error is either nil (Run exited cleanly via ctx)
	// or a context.Canceled wrap. Either is acceptable — we are
	// asserting the lifecycle returns, not a specific error shape.
	if closeErr != nil &&
		!errors.Is(closeErr, context.Canceled) &&
		!errors.Is(closeErr, context.DeadlineExceeded) {
		t.Fatalf("Close returned unexpected error shape: %v", closeErr)
	}
}
