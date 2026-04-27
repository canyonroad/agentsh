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

// TestStore_ServerRestart_AcksCatchUp verifies that when the server is
// closed mid-stream and a new server takes its place, the client
// reconnects and the new server eventually sees all previously-pending
// records via replay (because no SessionAck arrived for them).
func TestStore_ServerRestart_AcksCatchUp(t *testing.T) {
	// srv1 is configured with a large AckDelay so it never sends
	// BatchAck within the 150ms observation window. When we close it,
	// the transport's persisted ack cursor remains at (0,0) — forcing
	// a full replay to srv2.
	srv1 := testserver.New(testserver.Options{
		AckDelay: 10 * time.Second,
	})
	router := testserver.NewRoutingDialer(srv1)

	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:restart-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 5,
		BatchMaxBytes:   4 * 1024,
		BatchMaxAge:     30 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          router,
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	const total = 10
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

	// Let some records land on srv1 before we pull the plug.
	time.Sleep(150 * time.Millisecond)
	srv1.Close()

	// Stand up a second server and re-point the router so the next
	// reconnect lands there.
	srv2 := testserver.New(testserver.Options{})
	defer srv2.Close()
	router.Switch(srv2)

	// Poll until srv2 has observed all 10 sequences via replay.
	// Because srv1 sent no SessionAck (it was simply closed), the
	// Transport's persisted ack cursor is still at (0, 0) and the
	// Replayer re-sends all 10 records from the WAL.
	//
	// We use AssertReplayObserved rather than AssertSequenceRange:
	// some records may arrive as duplicates if they were batched and
	// sent to srv2 more than once during reconnect oscillation.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := srv2.AssertReplayObserved(1, total); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Deadline expired — dump diagnostics.
	t.Logf("srv2 batches at deadline:")
	for i, b := range srv2.Batches() {
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
	t.Fatalf("srv2 did not observe all %d sequences after restart: %v", total, srv2.AssertReplayObserved(1, total))
}
