package watchtower_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestStore_DropsMidBatchTriggersReplay is the Phase 11 component test
// for the spec's "drop → replay" contract: with DropAfterBatchN=2 the
// server terminates the stream after the second batch, forcing the
// Transport back through Connecting → Replaying → Live. The Replayer
// re-sends every record whose (gen, seq) is above the remote ack
// cursor, so the union of all batches the server has recorded after
// reconnect MUST cover the full [1..50] sequence window.
//
// Uses AssertReplayObserved (not AssertSequenceRange): duplicates are
// expected — the second stream re-sends sequences that already arrived
// on the first stream before it was dropped — and the contract this
// test is verifying is only that no sequence is PERMANENTLY missing,
// not that exactly one copy of each was observed.
func TestStore_DropsMidBatchTriggersReplay(t *testing.T) {
	// Unskipped: the recv-goroutine startup gap, the inflight
	// increment-only bug, and the wire-encoding stub — the three
	// blockers documented in the original transport.Run "SCAFFOLDING
	// ONLY" header — are all closed (see Run's updated docstring).
	// runLive's recvErrCh / recvEventCh arms are now alive, server-
	// side stream closes are visible, and BatchAck releases inflight
	// slots so the send path no longer stalls at MaxInflight.

	srv := testserver.New(testserver.Options{
		DropAfterBatchN:     2,
		DropAfterBatchNOnce: true,
	})
	defer srv.Close()

	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:drop-replay",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 10,
		BatchMaxBytes:   8 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	const total = 50
	for i := uint64(1); i <= total; i++ {
		ev := types.Event{
			Type:      "exec",
			SessionID: "s",
			Timestamp: time.Now(),
			Chain:     &types.ChainState{Sequence: i, Generation: 1},
		}
		if err := s.AppendEvent(context.Background(), ev); err != nil {
			t.Fatalf("AppendEvent seq=%d: %v", i, err)
		}
	}

	// Poll AssertReplayObserved until the replayed batches cover the
	// full [1..50] window. Deadline of 5s is generous — the drop
	// fires after batch 2 (~20 records), reconnect backoff is 200ms,
	// and the replayer re-sends 30+ records in a handful of batches.
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := srv.AssertReplayObserved(1, total); err == nil {
			return
		} else {
			lastErr = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Dump batches for diagnostics when the deadline expires.
	t.Logf("observed batches at deadline:")
	for i, b := range srv.Batches() {
		u := b.GetUncompressed()
		var seqs []uint64
		if u != nil {
			for _, ev := range u.GetEvents() {
				seqs = append(seqs, ev.GetSequence())
			}
		}
		t.Logf("  batch %d: from=%d to=%d gen=%d seqs=%v", i, b.GetFromSequence(), b.GetToSequence(), b.GetGeneration(), seqs)
	}
	t.Logf("store Err()=%v", s.Err())
	t.Fatalf("replay did not deliver all %d sequences within 5s: %v", total, lastErr)
}
