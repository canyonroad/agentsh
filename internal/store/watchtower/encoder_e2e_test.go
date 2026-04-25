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

// TestStore_AppendEvent_DeliversRealEventBatch asserts the end-to-end
// store → transport → testserver path actually produces a real
// wtpv1.EventBatch frame with the appended record's sequence and
// generation visible in the UncompressedEvents body.
//
// Roborev #6126 (Medium): "this revert can blackhole delivery without
// any test failure" — pinpointing the gap that the prior store-level
// suite drove AppendEvent without ever asserting the resulting batch
// hit the wire. This test fills that gap so the encoder can never
// regress to a no-op stub silently again.
func TestStore_AppendEvent_DeliversRealEventBatch(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:e2e-encoder",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 4,
		BatchMaxBytes:   8 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	for i := uint64(1); i <= 4; i++ {
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

	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := srv.AssertSequenceRange(1, 4); err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("did not observe seq=[1..4] within 3s: %v", lastErr)
	}

	// Drill into the recorded batches: at least one must carry a real
	// UncompressedEvents body with our generation / sequence range. A
	// stub encoder would produce empty ClientMessages and addBatch
	// would record zero EventBatch frames; AssertSequenceRange would
	// fail above. This block adds a belt-and-braces wire-shape check.
	batches := srv.Batches()
	if len(batches) == 0 {
		t.Fatalf("server recorded 0 batches; expected at least 1")
	}
	sawRealBody := false
	for _, b := range batches {
		body := b.GetUncompressed()
		if body == nil {
			continue
		}
		if len(body.GetEvents()) == 0 {
			continue
		}
		if b.GetGeneration() != 1 {
			t.Fatalf("EventBatch.Generation=%d, want 1", b.GetGeneration())
		}
		sawRealBody = true
		break
	}
	if !sawRealBody {
		t.Fatalf("no batch carried a non-empty UncompressedEvents body; encoder may have regressed to a stub")
	}
}
