package watchtower_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"github.com/agentsh/agentsh/pkg/types"
)

// skipOnWindowsCIIfSlow centralizes the rationale for skipping these
// end-to-end gRPC+WAL integration tests on Windows. The compress
// package itself, the encoder/decoder logic, the validator, and the
// metrics surface are all exercised by unit tests that DO run on
// Windows. The wire goldens also exercise the proto-level invariants
// on Windows. What these integration tests add — driving real network
// + real WAL fsync + reconnect/replay timing — is sensitive to the
// slow disk I/O and scheduler quanta on Windows CI runners and has
// flaked across multiple unrelated tests in this package
// (TestStore_OverflowEmitsTransportLossOnWire from PR #255 has shown
// the same pattern). The agent's primary deployment targets are
// Linux and macOS daemons; the Linux + macOS matrix slots already
// cover these tests under realistic conditions.
func skipOnWindowsCIIfSlow(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("integration test skipped on Windows: end-to-end gRPC+WAL timing is unreliable on Windows CI runners; unit tests + wire goldens cover the compression path on this platform")
	}
}

// TestStore_CompressionRoundTrip drives a Transport configured for each
// compression algorithm against the testserver, sends a known sequence
// of events, and asserts the testserver recovers the same sequences AND
// that the recorded batches actually exercised the compress path
// (i.e., compressed_payload bytes are present rather than the uncompressed
// fallback).
func TestStore_CompressionRoundTrip(t *testing.T) {
	skipOnWindowsCIIfSlow(t)
	cases := []struct {
		algo     string
		wantAlgo wtpv1.Compression
	}{
		{"zstd", wtpv1.Compression_COMPRESSION_ZSTD},
		{"gzip", wtpv1.Compression_COMPRESSION_GZIP},
	}
	for _, tc := range cases {
		t.Run(tc.algo, func(t *testing.T) {
			srv := testserver.New(testserver.Options{})
			defer srv.Close()

			s, err := watchtower.New(context.Background(), watchtower.Options{
				WALDir:          t.TempDir(),
				Mapper:          compact.StubMapper{},
				Allocator:       audit.NewSequenceAllocator(),
				AgentID:         "a",
				SessionID:       "s",
				KeyFingerprint:  "sha256:" + tc.algo + "-roundtrip",
				HMACKeyID:       "k1",
				HMACSecret:      bytes.Repeat([]byte("a"), 32),
				HMACAlgorithm:   "hmac-sha256",
				BatchMaxRecords: 10,
				BatchMaxBytes:   8 * 1024,
				BatchMaxAge:     50 * time.Millisecond,
				AllowStubMapper: true,
				Dialer:          srv.DialerFor(),
				CompressionAlgo: tc.algo,
				ZstdLevel:       3,
				GzipLevel:       6,
				Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
			})
			if err != nil {
				t.Fatalf("watchtower.New: %v", err)
			}
			defer s.Close()

			const total = 30
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

			// Wait for the full sequence to land at the receiver.
			// AssertReplayObserved tolerates duplicates so a reconnect+
			// replay during the test window does not fail the test.
			// Deadline of 60s is generous; this loop exits as soon as
			// the assertion passes, so happy-path runtime is unchanged.
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				if err := srv.AssertReplayObserved(1, total); err == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err := srv.AssertReplayObserved(1, total); err != nil {
				t.Fatalf("AssertReplayObserved after deadline: %v", err)
			}

			// Confirm at least one batch was actually compressed (not silently
			// falling back to uncompressed). Since fail-open emits Compression: NONE
			// for the failing batch, a 100% compressed observation pins the
			// happy-path wiring.
			batches := srv.Batches()
			var compressedSeen, totalSeen int
			for _, b := range batches {
				totalSeen++
				if b.GetCompression() == tc.wantAlgo && b.GetCompressedPayload() != nil {
					compressedSeen++
				}
			}
			if compressedSeen == 0 {
				t.Fatalf("no batches recorded with compression=%v + non-nil compressed_payload (total=%d batches); compress wiring is not exercising the codec", tc.wantAlgo, totalSeen)
			}
			t.Logf("algo=%s: %d/%d batches compressed", tc.algo, compressedSeen, totalSeen)
		})
	}
}

// TestStore_CompressionSizeEnvelope drives a zstd-configured Transport
// with a batch close to the max_bytes ceiling and confirms the
// resulting compressed_payload sits comfortably below the proto's
// MaxCompressedPayloadBytes (8 MiB) cap.
func TestStore_CompressionSizeEnvelope(t *testing.T) {
	skipOnWindowsCIIfSlow(t)
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:size-envelope",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 1024,
		BatchMaxBytes:   200 * 1024, // ~200 KiB target
		BatchMaxAge:     200 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		CompressionAlgo: "zstd",
		ZstdLevel:       3,
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	// Append enough events to fill several large batches.
	const total = 500
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

	// AssertReplayObserved tolerates duplicates because reconnect+replay
	// can legitimately re-send sequences during the test window — the
	// size envelope test cares about (a) every sequence arriving and
	// (b) the per-batch compressed_payload size cap, neither of which
	// is sensitive to duplicates. AssertSequenceRange would reject any
	// replay-driven duplicate as a test failure even though the
	// behavior is wire-legal.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if err := srv.AssertReplayObserved(1, total); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := srv.AssertReplayObserved(1, total); err != nil {
		t.Fatalf("AssertReplayObserved: %v", err)
	}

	for i, b := range srv.Batches() {
		if cp := b.GetCompressedPayload(); cp != nil {
			if len(cp) > wtpv1.MaxCompressedPayloadBytes {
				t.Fatalf("batch %d compressed_payload %d bytes > MaxCompressedPayloadBytes %d",
					i, len(cp), wtpv1.MaxCompressedPayloadBytes)
			}
		}
	}
}

// TestStore_CompressionWireShapeConformance verifies the per-batch invariant
// that EventBatch.Compression matches the body oneof case across a
// stream that exercises the compress path.
func TestStore_CompressionWireShapeConformance(t *testing.T) {
	skipOnWindowsCIIfSlow(t)
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:wire-shape",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 8,
		BatchMaxBytes:   4 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		CompressionAlgo: "zstd",
		ZstdLevel:       3,
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	const total = 20
	for i := uint64(1); i <= total; i++ {
		ev := types.Event{
			Type:      "exec",
			SessionID: "s",
			Timestamp: time.Now(),
			Chain:     &types.ChainState{Sequence: i, Generation: 1},
		}
		if err := s.AppendEvent(context.Background(), ev); err != nil {
			t.Fatalf("AppendEvent: %v", err)
		}
	}

	// Wait for delivery via the duplicate-tolerant assertion; reconnect+
	// replay during the test window can legitimately re-send sequences.
	// 60s deadline matches the size-envelope test; this loop exits as
	// soon as the assertion passes.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if err := srv.AssertReplayObserved(1, total); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := srv.AssertReplayObserved(1, total); err != nil {
		t.Fatalf("AssertReplayObserved: %v", err)
	}

	for i, b := range srv.Batches() {
		comp := b.GetCompression()
		switch comp {
		case wtpv1.Compression_COMPRESSION_NONE:
			if b.GetUncompressed() == nil {
				t.Errorf("batch %d compression=NONE but body is not UncompressedEvents", i)
			}
			if b.GetCompressedPayload() != nil {
				t.Errorf("batch %d compression=NONE but compressed_payload is non-nil", i)
			}
		case wtpv1.Compression_COMPRESSION_ZSTD, wtpv1.Compression_COMPRESSION_GZIP:
			if b.GetCompressedPayload() == nil {
				t.Errorf("batch %d compression=%v but compressed_payload is nil", i, comp)
			}
			if b.GetUncompressed() != nil {
				t.Errorf("batch %d compression=%v but uncompressed body is set", i, comp)
			}
		default:
			t.Errorf("batch %d unrecognized Compression=%v", i, comp)
		}
	}
}
