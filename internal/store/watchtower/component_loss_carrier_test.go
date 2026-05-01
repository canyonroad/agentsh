package watchtower_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

func skipLossCarrierOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("integration test skipped on Windows: active WAL readers can race segment seal/rename with ERROR_SHARING_VIOLATION")
	}
}

// TestStore_OverflowEmitsTransportLossOnWire exercises WAL overflow
// (configured via tiny WALMaxTotalSize), asserts the testserver
// receives a ClientMessage{TransportLoss{reason: OVERFLOW}} AND the
// session does NOT restart (pre-spec regression: overflow caused
// ErrRecordLossEncountered → session teardown).
func TestStore_OverflowEmitsTransportLossOnWire(t *testing.T) {
	skipLossCarrierOnWindows(t)

	// SuppressBatchAck: without it, the testserver acks every
	// EventBatch as it arrives, the agent advances persistedAck, and
	// the WAL GCs fully-acked sealed segments via
	// segmentFullyAckedLocked — keeping totalBytes under the 8 KiB
	// cap on slow runners (Windows file I/O, macOS FUSE-T) so
	// overflow never fires. Suppressing the ack pins persistedAck at
	// zero for the test's lifetime, so segments accumulate
	// deterministically and overflow always trips. The TransportLoss
	// frame's recv path is unaffected.
	srv := testserver.New(testserver.Options{SuppressBatchAck: true})
	defer srv.Close()
	router := testserver.NewRoutingDialer(srv)

	// WALSegmentSize=4 KiB, WALMaxTotalSize=8 KiB. validate() requires
	// WALSegmentSize <= WALMaxTotalSize/2, so this is the tightest valid
	// budget. Each ~1 KiB payload record takes roughly one segment;
	// after 2 sealed segments we hit the cap and overflow fires.
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		WALSegmentSize:  4 * 1024,
		WALMaxTotalSize: 8 * 1024,
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:overflow-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 1,
		BatchMaxBytes:   4 * 1024,
		BatchMaxAge:     5 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          router,
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	// Pump enough events to overflow the WAL while the server is reachable.
	// Each event carries a padded argv to ensure the record payload is large
	// enough to fill a segment quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	padding := strings.Repeat("x", 512)
	for i := uint64(1); i <= 200; i++ {
		ev := types.Event{
			Type:      "exec",
			SessionID: "s",
			Timestamp: time.Now(),
			Chain:     &types.ChainState{Sequence: i, Generation: 1},
			Filename:  "/usr/bin/test",
			Argv:      []string{padding},
		}
		// Ignore append errors — overflow is the goal and the store
		// may reject some appends once the WAL is full.
		_ = s.AppendEvent(ctx, ev)
	}

	// Wait for the testserver to observe at least one TransportLoss.
	loss, err := srv.WaitForTransportLoss(15 * time.Second)
	if err != nil {
		t.Fatalf("WaitForTransportLoss: %v", err)
	}
	if loss.Reason != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW {
		t.Fatalf("TransportLoss.Reason = %v; want OVERFLOW", loss.Reason)
	}

	// Regression: session must not have restarted — the overflow must NOT
	// have caused ErrRecordLossEncountered → session teardown.
	got, err := srv.WaitForSessionInits(1, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForSessionInits: %v", err)
	}
	if got != 1 {
		t.Fatalf("SessionInits = %d; want exactly 1 (no session restart)", got)
	}
}

// TestStore_CRCCorruptionEmitsTransportLossOnWire manufactures CRC
// corruption mid-WAL, restarts the store (so replay walks the corrupted
// segment), asserts a TransportLoss{reason: CRC_CORRUPTION} reaches the
// wire AND the session does NOT fail-closed.
func TestStore_CRCCorruptionEmitsTransportLossOnWire(t *testing.T) {
	skipLossCarrierOnWindows(t)

	// SuppressBatchAck: without it, the testserver acks every
	// EventBatch as it arrives, the agent advances persistedAck, and
	// the WAL GCs fully-acked sealed segments via
	// segmentFullyAckedLocked before s1.Close returns on slow runners
	// (macOS FUSE-T, Windows file I/O). corruptOneSegment then finds
	// only the live INPROGRESS segment and the test fails. Pinning
	// the per-batch ack at zero keeps sealed segments alive across
	// the close → corruption → reopen sequence. The s2 replay's
	// CRC_CORRUPTION TransportLoss is delivered independently of the
	// per-batch ack path.
	srv := testserver.New(testserver.Options{SuppressBatchAck: true})
	defer srv.Close()
	router := testserver.NewRoutingDialer(srv)

	walDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step A: write some records, close the store cleanly. The records
	// reach the testserver via normal flow; we want them durable on
	// disk so the next-store replay traverses the same segment.
	//
	// WALSegmentSize=512 gives a record budget of 496 bytes, which is
	// enough for a fully-marshalled CompactEvent (IntegrityRecord +
	// StubMapper JSON payload ~ 300-400 bytes). Five appends produce
	// multiple sealed segments plus one live INPROGRESS.
	// Corrupting a sealed segment ensures it survives the reopen (recovery
	// only truncates the live INPROGRESS tail).
	s1, err := watchtower.New(ctx, watchtower.Options{
		WALDir:          walDir,
		WALSegmentSize:  512,
		WALMaxTotalSize: 512 * 1024,
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:crc-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 5,
		BatchMaxBytes:   4 * 1024,
		BatchMaxAge:     20 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          router,
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("watchtower.New(s1): %v", err)
	}
	for i := uint64(1); i <= 5; i++ {
		ev := types.Event{
			Type:      "exec",
			SessionID: "s",
			Timestamp: time.Now(),
			Chain:     &types.ChainState{Sequence: i, Generation: 1},
		}
		if err := s1.AppendEvent(ctx, ev); err != nil {
			t.Fatalf("AppendEvent[%d]: %v", i, err)
		}
	}
	s1.Close()

	// Step B: corrupt one sealed segment's CRC on disk.
	corruptOneSegment(t, walDir)

	// Step C: open a new store on the same WAL; replay walks the
	// corrupted segment and emits a CRC_CORRUPTION TransportLoss.
	s2, err := watchtower.New(ctx, watchtower.Options{
		WALDir:          walDir,
		WALSegmentSize:  512,
		WALMaxTotalSize: 512 * 1024,
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:crc-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 5,
		BatchMaxBytes:   4 * 1024,
		BatchMaxAge:     20 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          router,
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("watchtower.New(s2): %v", err)
	}
	defer s2.Close()

	loss, err := srv.WaitForTransportLoss(15 * time.Second)
	if err != nil {
		t.Fatalf("WaitForTransportLoss: %v", err)
	}
	if loss.Reason != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_CRC_CORRUPTION {
		t.Fatalf("Reason = %v; want CRC_CORRUPTION", loss.Reason)
	}

	// SessionInits should be 2 (one per Store), not 3+ (no client-side
	// restart on top of the two distinct lifetimes).
	got, err := srv.WaitForSessionInits(2, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForSessionInits: %v", err)
	}
	if got != 2 {
		t.Fatalf("SessionInits = %d; want exactly 2 (one per Store, no extra restarts)", got)
	}
}

// corruptOneSegment finds a sealed *.seg file in walDir/segments and flips
// a byte deep in its data region to trigger CRC failure on next read.
// Mirrors the approach used in internal/store/watchtower/wal/crc_test.go:
// corrupt offset = SegmentHeaderSize(16) + 30, well into the first record's
// payload region.
func corruptOneSegment(t *testing.T, walDir string) {
	t.Helper()
	segDir := filepath.Join(walDir, "segments")
	entries, err := os.ReadDir(segDir)
	if err != nil {
		t.Fatalf("corruptOneSegment: read %s: %v", segDir, err)
	}
	var sealed string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".INPROGRESS") {
			continue
		}
		if strings.HasSuffix(name, ".seg") {
			sealed = name
			break
		}
	}
	if sealed == "" {
		t.Fatalf("corruptOneSegment: no sealed .seg file in %s; entries=%v", segDir, entries)
	}
	path := filepath.Join(segDir, sealed)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corruptOneSegment: read %s: %v", path, err)
	}
	// SegmentHeaderSize=16; offset 16+30=46 is within the first record's
	// payload region. Any payload-region flip invalidates the CRC.
	const corruptOff = 16 + 30
	if len(data) <= corruptOff {
		t.Fatalf("corruptOneSegment: %s too short (%d bytes) to corrupt at off=%d", sealed, len(data), corruptOff)
	}
	data[corruptOff] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("corruptOneSegment: write %s: %v", path, err)
	}
}
