package transport

import (
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// Sub-step 17.X recv-multiplexer tests. These tests exercise the recv-side
// wrapper applyAckFromRecv (the SINGLE source of truth for BatchAck and
// ServerHeartbeat dispatch) directly, mirroring how the SessionAck tests
// in state_connecting_clamp_internal_test.go exercise ackSessionAck via
// the SessionAck path.
//
// Each test reuses the clampTestEnv fixture (real *wal.WAL with Task 14a
// identity options, buffer-backed JSON logger, fake metrics) so log/metric
// content can be asserted byte-for-byte without racing on slog.Default().
// The recv arm dispatch invoked by tests is t.applyAckFromRecv directly —
// the recv goroutine itself is a thin demuxer per the round-6 typed-event
// backpressure policy table; the cursor-mutation contract lives entirely
// inside applyAckFromRecv.

// ===== Test 17.X.1 =====
// TestRecvMultiplexer_BatchAckLowerSameGenIsResendNeeded mirrors Task
// 15.1's TestApplyServerAckTuple_LowerSameGenIsResendNeeded for the
// recv path. Pre-seed (100, 7), MarkAcked to fix meta, drive
// applyAckFromRecv("batch_ack", 7, 50). Assert: persistedAck unchanged at
// (100, 7); remoteReplayCursor regressed to (50, 7); meta unchanged at
// (7, 100); IncResendNeeded=1; SetAckHighWatermark zero calls; WARN buffer
// empty; INFO buffer has exactly one entry with frame="batch_ack",
// server_seq=50, server_gen=7, local_persisted_seq=100, local_persisted_gen=7.
func TestRecvMultiplexer_BatchAckLowerSameGenIsResendNeeded(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 200)
	if err := env.w.MarkAcked(7, 100); err != nil {
		t.Fatalf("MarkAcked seed: %v", err)
	}

	env.tr.applyAckFromRecv("batch_ack", 7, 50)

	if got := PersistedAckForTest(env.tr); got != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck moved on ResendNeeded: %+v", got)
	}
	if got := RemoteReplayCursorForTest(env.tr); got != (AckCursor{Sequence: 50, Generation: 7}) {
		t.Fatalf("remoteReplayCursor: got %+v, want {50,7}", got)
	}

	m := readMetaForTest(t, env.walDir)
	if m.AckHighWatermarkGen != 7 || m.AckHighWatermarkSeq != 100 {
		t.Fatalf("meta after ResendNeeded: got (%d, %d), want (7, 100)",
			m.AckHighWatermarkGen, m.AckHighWatermarkSeq)
	}
	if env.metrics.resendNeeded != 1 {
		t.Fatalf("IncResendNeeded calls: got %d, want 1", env.metrics.resendNeeded)
	}
	if len(env.metrics.ackHWMs) != 0 {
		t.Fatalf("SetAckHighWatermark unexpectedly called: %v", env.metrics.ackHWMs)
	}
	if len(env.metrics.anomalousAckReasons) != 0 {
		t.Fatalf("anomaly metric unexpectedly incremented: %v", env.metrics.anomalousAckReasons)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 0 {
		t.Fatalf("unexpected WARN on ResendNeeded: %+v", entries)
	}
	if got := countLevel(entries, "INFO"); got != 1 {
		t.Fatalf("INFO entries: got %d, want 1: %+v", got, entries)
	}
	info := firstLevel(entries, "INFO")
	if info.Attrs["frame"] != "batch_ack" {
		t.Fatalf("INFO frame: got %v, want batch_ack", info.Attrs["frame"])
	}
	if v, ok := info.Attrs["server_seq"].(float64); !ok || uint64(v) != 50 {
		t.Fatalf("INFO server_seq: got %v, want 50", info.Attrs["server_seq"])
	}
	if v, ok := info.Attrs["server_gen"].(float64); !ok || uint32(v) != 7 {
		t.Fatalf("INFO server_gen: got %v, want 7", info.Attrs["server_gen"])
	}
	if v, ok := info.Attrs["local_persisted_seq"].(float64); !ok || uint64(v) != 100 {
		t.Fatalf("INFO local_persisted_seq: got %v, want 100", info.Attrs["local_persisted_seq"])
	}
	if v, ok := info.Attrs["local_persisted_gen"].(float64); !ok || uint32(v) != 7 {
		t.Fatalf("INFO local_persisted_gen: got %v, want 7", info.Attrs["local_persisted_gen"])
	}
}

// ===== Test 17.X.2 =====
// TestRecvMultiplexer_BatchAckHigherSameGenAdvancesPersistedAck — happy
// advance path. Seed (50, 7), append 1..200 in gen=7, drive
// applyAckFromRecv("batch_ack", 7, 100). Assert: both cursors at (100, 7);
// meta updated to (7, 100, true); SetAckHighWatermark(100) recorded;
// WARN/INFO empty.
func TestRecvMultiplexer_BatchAckHigherSameGenAdvancesPersistedAck(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 50, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 200)

	env.tr.applyAckFromRecv("batch_ack", 7, 100)

	if got := PersistedAckForTest(env.tr); got != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck: got %+v, want {100,7}", got)
	}
	if got := RemoteReplayCursorForTest(env.tr); got != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("remoteReplayCursor: got %+v, want {100,7}", got)
	}

	m := readMetaForTest(t, env.walDir)
	if m.AckHighWatermarkGen != 7 || m.AckHighWatermarkSeq != 100 || !m.AckRecorded {
		t.Fatalf("meta after Adopted: got (%d, %d, %v), want (7, 100, true)",
			m.AckHighWatermarkGen, m.AckHighWatermarkSeq, m.AckRecorded)
	}

	if len(env.metrics.ackHWMs) != 1 || env.metrics.ackHWMs[0] != 100 {
		t.Fatalf("SetAckHighWatermark calls: got %v, want [100]", env.metrics.ackHWMs)
	}
	if env.metrics.resendNeeded != 0 || len(env.metrics.anomalousAckReasons) != 0 {
		t.Fatalf("unexpected metric activity: resend=%d anomaly=%v",
			env.metrics.resendNeeded, env.metrics.anomalousAckReasons)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if countLevel(entries, "WARN") != 0 || countLevel(entries, "INFO") != 0 {
		t.Fatalf("unexpected log activity on Adopted: %+v", entries)
	}
}

// ===== Test 17.X.3 =====
// TestRecvMultiplexer_BatchAckServerAckExceedsLocalSeqIsAnomaly — same-gen
// over-watermark. Seed (30, 7), WAL has up to seq 50 in gen 7, drive
// applyAckFromRecv("batch_ack", 7, 60). Assert Anomaly with reason
// server_ack_exceeds_local_seq, both cursors unchanged at (30, 7), exactly
// one WARN with frame="batch_ack" and the full attribute schema.
func TestRecvMultiplexer_BatchAckServerAckExceedsLocalSeqIsAnomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 30, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 50)

	env.tr.applyAckFromRecv("batch_ack", 7, 60)

	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 30, Generation: 7}) {
		t.Fatalf("persistedAck mutated: %+v", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 30, Generation: 7}) {
		t.Fatalf("remoteReplayCursor mutated: %+v", RemoteReplayCursorForTest(env.tr))
	}

	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "server_ack_exceeds_local_seq" {
		t.Fatalf("anomaly metric: got %v, want [server_ack_exceeds_local_seq]", env.metrics.anomalousAckReasons)
	}
	if len(env.metrics.ackHWMs) != 0 {
		t.Fatalf("SetAckHighWatermark unexpectedly called: %v", env.metrics.ackHWMs)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN entries: got %d, want 1: %+v", got, entries)
	}
	w := firstLevel(entries, "WARN")
	if w.Attrs["frame"] != "batch_ack" {
		t.Fatalf("WARN frame: got %v, want batch_ack", w.Attrs["frame"])
	}
	if w.Attrs["reason"] != "server_ack_exceeds_local_seq" {
		t.Fatalf("WARN reason: got %v, want server_ack_exceeds_local_seq", w.Attrs["reason"])
	}
	if v, ok := w.Attrs["server_seq"].(float64); !ok || uint64(v) != 60 {
		t.Fatalf("WARN server_seq: got %v, want 60", w.Attrs["server_seq"])
	}
	if v, ok := w.Attrs["server_gen"].(float64); !ok || uint32(v) != 7 {
		t.Fatalf("WARN server_gen: got %v, want 7", w.Attrs["server_gen"])
	}
	if v, ok := w.Attrs["local_persisted_seq"].(float64); !ok || uint64(v) != 30 {
		t.Fatalf("WARN local_persisted_seq: got %v, want 30", w.Attrs["local_persisted_seq"])
	}
	if v, ok := w.Attrs["local_persisted_gen"].(float64); !ok || uint32(v) != 7 {
		t.Fatalf("WARN local_persisted_gen: got %v, want 7", w.Attrs["local_persisted_gen"])
	}
	if v, ok := w.Attrs["wal_written_data_high_seq"].(float64); !ok || uint64(v) != 50 {
		t.Fatalf("WARN wal_written_data_high_seq: got %v, want 50", w.Attrs["wal_written_data_high_seq"])
	}
	if v, ok := w.Attrs["wal_written_data_high_ok"].(bool); !ok || !v {
		t.Fatalf("WARN wal_written_data_high_ok: got %v, want true", w.Attrs["wal_written_data_high_ok"])
	}
}

// ===== Test 17.X.4 =====
// TestRecvMultiplexer_BatchAckLowerGenIsAnomaly — cross-gen lower. Seed
// (0, 7), drive applyAckFromRecv("batch_ack", 6, 999999). Assert Anomaly
// with reason stale_generation, both cursors unchanged at (0, 7), exactly
// one WARN with frame="batch_ack", INFO buffer empty.
func TestRecvMultiplexer_BatchAckLowerGenIsAnomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 0, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	env.tr.applyAckFromRecv("batch_ack", 6, 999999)

	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 0, Generation: 7}) {
		t.Fatalf("persistedAck mutated: %+v", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 0, Generation: 7}) {
		t.Fatalf("remoteReplayCursor mutated: %+v", RemoteReplayCursorForTest(env.tr))
	}

	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "stale_generation" {
		t.Fatalf("anomaly metric: got %v, want [stale_generation]", env.metrics.anomalousAckReasons)
	}
	if len(env.metrics.ackHWMs) != 0 {
		t.Fatalf("SetAckHighWatermark unexpectedly called: %v", env.metrics.ackHWMs)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN entries: got %d, want 1", got)
	}
	if got := countLevel(entries, "INFO"); got != 0 {
		t.Fatalf("INFO entries: got %d, want 0 (cross-gen lower is NOT a legitimate ResendNeeded)", got)
	}
	w := firstLevel(entries, "WARN")
	if w.Attrs["frame"] != "batch_ack" {
		t.Fatalf("WARN frame: got %v, want batch_ack", w.Attrs["frame"])
	}
	if w.Attrs["reason"] != "stale_generation" {
		t.Fatalf("WARN reason: got %v, want stale_generation", w.Attrs["reason"])
	}
	if v, ok := w.Attrs["server_seq"].(float64); !ok || uint64(v) != 999999 {
		t.Fatalf("WARN server_seq: got %v, want 999999", w.Attrs["server_seq"])
	}
	if v, ok := w.Attrs["server_gen"].(float64); !ok || uint32(v) != 6 {
		t.Fatalf("WARN server_gen: got %v, want 6", w.Attrs["server_gen"])
	}
	if v, ok := w.Attrs["local_persisted_seq"].(float64); !ok || uint64(v) != 0 {
		t.Fatalf("WARN local_persisted_seq: got %v, want 0", w.Attrs["local_persisted_seq"])
	}
	if v, ok := w.Attrs["local_persisted_gen"].(float64); !ok || uint32(v) != 7 {
		t.Fatalf("WARN local_persisted_gen: got %v, want 7", w.Attrs["local_persisted_gen"])
	}
}

// ===== Test 17.X.5 =====
// TestRecvMultiplexer_BatchAckHigherGenButOnlyHeaderExists_Anomaly —
// round-11 SAFETY. Seed (100, 7), append in gen 7 + MarkAcked, then roll
// to gen 8 by appending in gen 8 then... actually, since the WAL doesn't
// expose a direct "header without data" primitive in tests, this case is
// modeled by overriding WrittenDataHighWaterFn to return ok=false for
// gen=8 (mirroring what the WAL would surface for a header-only generation).
// Drive applyAckFromRecv("batch_ack", 8, 0). Assert Anomaly with reason
// unwritten_generation, both cursors unchanged, lower-gen segments still on disk.
func TestRecvMultiplexer_BatchAckHigherGenButOnlyHeaderExists_Anomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	appendDataInGen(t, env.w, 1, 7, 100)
	if err := env.w.MarkAcked(7, 100); err != nil {
		t.Fatalf("MarkAcked: %v", err)
	}

	// Override WrittenDataHighWater to model the "header for gen=8 written
	// but no RecordData appended" state. The real WAL would surface the same
	// (ok=false) for a header-only generation per round-11 SAFETY semantics.
	SetWALWrittenDataHighWaterFnForTest(env.tr, func(gen uint32) (uint64, bool, error) {
		if gen == 8 {
			return 0, false, nil
		}
		return env.w.WrittenDataHighWater(gen)
	})

	env.tr.applyAckFromRecv("batch_ack", 8, 0)

	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck mutated: %+v", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("remoteReplayCursor mutated: %+v", RemoteReplayCursorForTest(env.tr))
	}

	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "unwritten_generation" {
		t.Fatalf("anomaly metric: got %v, want [unwritten_generation]", env.metrics.anomalousAckReasons)
	}
	if len(env.metrics.ackHWMs) != 0 {
		t.Fatalf("SetAckHighWatermark unexpectedly called: %v", env.metrics.ackHWMs)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN entries: got %d, want 1: %+v", got, entries)
	}
	w := firstLevel(entries, "WARN")
	if w.Attrs["frame"] != "batch_ack" {
		t.Fatalf("WARN frame: got %v, want batch_ack", w.Attrs["frame"])
	}
	if w.Attrs["reason"] != "unwritten_generation" {
		t.Fatalf("WARN reason: got %v, want unwritten_generation", w.Attrs["reason"])
	}
	if v, ok := w.Attrs["wal_written_data_high_ok"].(bool); !ok || v {
		t.Fatalf("WARN wal_written_data_high_ok: got %v, want false", w.Attrs["wal_written_data_high_ok"])
	}

	// Lower-gen segments must still be on disk (round-11 SAFETY proof; the
	// round-10 design would have lex-GC'd them via wal.MarkAcked(8, 0)).
	segs, err := readSegmentsDir(t, env.walDir)
	if err != nil {
		t.Fatalf("readSegmentsDir: %v", err)
	}
	if len(segs) == 0 {
		t.Fatal("all segments GC'd; round-11 SAFETY check failed")
	}
}

// ===== Test 17.X.6 =====
// TestRecvMultiplexer_BatchAckHigherGenBeyondPerGenDataHW_Anomaly — round-11
// SAFETY for the higher-gen-with-data case. Seed (100, 7), append in gen 7 +
// MarkAcked, then append 10 records in gen 8. Drive
// applyAckFromRecv("batch_ack", 8, 999). Assert Anomaly with reason
// server_ack_exceeds_local_data, both cursors unchanged, exactly one WARN
// with wal_written_data_high_seq=10.
func TestRecvMultiplexer_BatchAckHigherGenBeyondPerGenDataHW_Anomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	appendDataInGen(t, env.w, 1, 7, 100)
	if err := env.w.MarkAcked(7, 100); err != nil {
		t.Fatalf("MarkAcked: %v", err)
	}
	appendDataInGen(t, env.w, 1, 8, 10)

	env.tr.applyAckFromRecv("batch_ack", 8, 999)

	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck mutated: %+v", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("remoteReplayCursor mutated: %+v", RemoteReplayCursorForTest(env.tr))
	}

	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "server_ack_exceeds_local_data" {
		t.Fatalf("anomaly metric: got %v, want [server_ack_exceeds_local_data]", env.metrics.anomalousAckReasons)
	}
	if len(env.metrics.ackHWMs) != 0 {
		t.Fatalf("SetAckHighWatermark unexpectedly called: %v", env.metrics.ackHWMs)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN entries: got %d, want 1: %+v", got, entries)
	}
	w := firstLevel(entries, "WARN")
	if w.Attrs["frame"] != "batch_ack" {
		t.Fatalf("WARN frame: got %v, want batch_ack", w.Attrs["frame"])
	}
	if w.Attrs["reason"] != "server_ack_exceeds_local_data" {
		t.Fatalf("WARN reason: got %v, want server_ack_exceeds_local_data", w.Attrs["reason"])
	}
	if v, ok := w.Attrs["wal_written_data_high_seq"].(float64); !ok || uint64(v) != 10 {
		t.Fatalf("WARN wal_written_data_high_seq: got %v, want 10", w.Attrs["wal_written_data_high_seq"])
	}
}

// ===== Test 17.X.7 =====
// TestRecvMultiplexer_ServerHeartbeatLowerSameGenIsResendNeeded — the
// ServerHeartbeat sibling of test 17.X.1. Same setup; drive
// applyAckFromRecv("server_heartbeat", 7, 50). Assert the same cursor
// split AND the INFO entry has frame="server_heartbeat" + the metrics fake
// recorded exactly one IncResendNeeded() call.
func TestRecvMultiplexer_ServerHeartbeatLowerSameGenIsResendNeeded(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 200)
	if err := env.w.MarkAcked(7, 100); err != nil {
		t.Fatalf("MarkAcked seed: %v", err)
	}

	env.tr.applyAckFromRecv("server_heartbeat", 7, 50)

	if got := PersistedAckForTest(env.tr); got != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck moved: %+v", got)
	}
	if got := RemoteReplayCursorForTest(env.tr); got != (AckCursor{Sequence: 50, Generation: 7}) {
		t.Fatalf("remoteReplayCursor: got %+v, want {50,7}", got)
	}

	if env.metrics.resendNeeded != 1 {
		t.Fatalf("IncResendNeeded calls: got %d, want 1", env.metrics.resendNeeded)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 0 {
		t.Fatalf("unexpected WARN: %+v", entries)
	}
	if got := countLevel(entries, "INFO"); got != 1 {
		t.Fatalf("INFO entries: got %d, want 1", got)
	}
	info := firstLevel(entries, "INFO")
	if info.Attrs["frame"] != "server_heartbeat" {
		t.Fatalf("INFO frame: got %v, want server_heartbeat", info.Attrs["frame"])
	}
}

// ===== Test 17.X.8 =====
// TestRecvMultiplexer_ServerHeartbeatServerAckExceedsLocalSeqIsAnomaly —
// ServerHeartbeat sibling of 17.X.3. Same setup as the BatchAck test but
// drive applyAckFromRecv("server_heartbeat", 7, 60). Assert WARN entry has
// frame="server_heartbeat", reason="server_ack_exceeds_local_seq",
// wal_written_data_high_seq=50, wal_written_data_high_ok=true; metrics
// fake records exactly one IncAnomalousAck("server_ack_exceeds_local_seq").
func TestRecvMultiplexer_ServerHeartbeatServerAckExceedsLocalSeqIsAnomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 30, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 50)

	env.tr.applyAckFromRecv("server_heartbeat", 7, 60)

	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 30, Generation: 7}) {
		t.Fatalf("persistedAck mutated: %+v", PersistedAckForTest(env.tr))
	}

	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "server_ack_exceeds_local_seq" {
		t.Fatalf("anomaly metric: got %v, want [server_ack_exceeds_local_seq]", env.metrics.anomalousAckReasons)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN entries: got %d, want 1: %+v", got, entries)
	}
	w := firstLevel(entries, "WARN")
	if w.Attrs["frame"] != "server_heartbeat" {
		t.Fatalf("WARN frame: got %v, want server_heartbeat", w.Attrs["frame"])
	}
	if w.Attrs["reason"] != "server_ack_exceeds_local_seq" {
		t.Fatalf("WARN reason: got %v, want server_ack_exceeds_local_seq", w.Attrs["reason"])
	}
	if v, ok := w.Attrs["wal_written_data_high_seq"].(float64); !ok || uint64(v) != 50 {
		t.Fatalf("WARN wal_written_data_high_seq: got %v, want 50", w.Attrs["wal_written_data_high_seq"])
	}
	if v, ok := w.Attrs["wal_written_data_high_ok"].(bool); !ok || !v {
		t.Fatalf("WARN wal_written_data_high_ok: got %v, want true", w.Attrs["wal_written_data_high_ok"])
	}
}

// ===== Test 17.X.9 =====
// TestRecvMultiplexer_BatchAckWALReadFailureIsAnomaly — round-12 Finding 4.
// Seed (30, 7); override walWrittenDataHighWaterFn to return EIO. Drive
// applyAckFromRecv("batch_ack", 7, 60). Assert Anomaly with reason
// wal_read_failure, both cursors unchanged; WARN entry carries
// wal_written_data_high_err="EIO".
func TestRecvMultiplexer_BatchAckWALReadFailureIsAnomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 30, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 50)

	SetWALWrittenDataHighWaterFnForTest(env.tr, func(_ uint32) (uint64, bool, error) {
		return 0, false, errors.New("EIO")
	})

	env.tr.applyAckFromRecv("batch_ack", 7, 60)

	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 30, Generation: 7}) {
		t.Fatalf("persistedAck mutated: %+v", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 30, Generation: 7}) {
		t.Fatalf("remoteReplayCursor mutated: %+v", RemoteReplayCursorForTest(env.tr))
	}

	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "wal_read_failure" {
		t.Fatalf("anomaly metric: got %v, want [wal_read_failure]", env.metrics.anomalousAckReasons)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN entries: got %d, want 1: %+v", got, entries)
	}
	w := firstLevel(entries, "WARN")
	if w.Attrs["frame"] != "batch_ack" {
		t.Fatalf("WARN frame: got %v, want batch_ack", w.Attrs["frame"])
	}
	if w.Attrs["reason"] != "wal_read_failure" {
		t.Fatalf("WARN reason: got %v, want wal_read_failure", w.Attrs["reason"])
	}
	if v, ok := w.Attrs["wal_written_data_high_err"].(string); !ok || v != "EIO" {
		t.Fatalf("WARN wal_written_data_high_err: got %v", w.Attrs["wal_written_data_high_err"])
	}
}

// ===== Test 17.X.10 =====
// TestRecvMultiplexer_BatchAckEmitsMetricOnAdopted — gauge emission contract.
// Seed (50, 1); append 1..1000 in gen=1; drive three sequential BatchAcks
// at (1, 100), (1, 200), (1, 300). After each, assert MarkAcked called and
// metric matches. Fourth call (1, 300) is NoOp — no additional MarkAcked
// or metric.
func TestRecvMultiplexer_BatchAckEmitsMetricOnAdopted(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 50, Generation: 1, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 1, 1000)

	markCount := 0
	SetWALMarkAckedFnForTest(env.tr, func(gen uint32, seq uint64) error {
		markCount++
		return env.w.MarkAcked(gen, seq)
	})

	for _, want := range []uint64{100, 200, 300} {
		env.tr.applyAckFromRecv("batch_ack", 1, want)
		if got := PersistedAckForTest(env.tr); got != (AckCursor{Sequence: want, Generation: 1}) {
			t.Fatalf("persistedAck after Adopted (%d): %+v", want, got)
		}
	}
	if markCount != 3 {
		t.Fatalf("MarkAcked calls: got %d, want 3", markCount)
	}
	if len(env.metrics.ackHWMs) != 3 {
		t.Fatalf("SetAckHighWatermark calls: got %d, want 3 (%v)",
			len(env.metrics.ackHWMs), env.metrics.ackHWMs)
	}
	if env.metrics.ackHWMs[len(env.metrics.ackHWMs)-1] != 300 {
		t.Fatalf("last SetAckHighWatermark: got %d, want 300",
			env.metrics.ackHWMs[len(env.metrics.ackHWMs)-1])
	}

	prevMark := markCount
	prevHWMs := len(env.metrics.ackHWMs)
	env.tr.applyAckFromRecv("batch_ack", 1, 300)
	if markCount != prevMark {
		t.Fatalf("MarkAcked called on NoOp: got %d, was %d", markCount, prevMark)
	}
	if len(env.metrics.ackHWMs) != prevHWMs {
		t.Fatalf("SetAckHighWatermark called on NoOp: got %d, was %d",
			len(env.metrics.ackHWMs), prevHWMs)
	}
}

// ===== Test 17.X.11 =====
// TestRecvMultiplexer_BatchAckAdoptedDoesNotAdvanceOnMarkAckedFailure —
// snapshot-and-rollback path mirrored from Task 15.1's identically-named
// test. Setup: walMarkAckedFn returns an error on the next call;
// InitialAckTuple=(50, 7). Drive applyAckFromRecv("batch_ack", 7, 100).
// Assert: MarkAcked called exactly once; both cursors rolled back to
// (50, 7); persistedAckPresent stays true; SetAckHighWatermark not called;
// the rate-limited ack-anomaly counter is NOT bumped (failure is not an
// anomaly); WARN buffer carries exactly one rollback entry with
// frame="batch_ack", attempted_seq=100, attempted_gen=7.
func TestRecvMultiplexer_BatchAckAdoptedDoesNotAdvanceOnMarkAckedFailure(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 50, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 200)

	injectedErr := errors.New("disk full")
	markCalls := 0
	SetWALMarkAckedFnForTest(env.tr, func(_ uint32, _ uint64) error {
		markCalls++
		return injectedErr
	})

	env.tr.applyAckFromRecv("batch_ack", 7, 100)

	if markCalls != 1 {
		t.Fatalf("MarkAcked calls: got %d, want 1", markCalls)
	}
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 50, Generation: 7}) {
		t.Fatalf("persistedAck not rolled back: %+v", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 50, Generation: 7}) {
		t.Fatalf("remoteReplayCursor not rolled back: %+v", RemoteReplayCursorForTest(env.tr))
	}
	if !PersistedAckPresentForTest(env.tr) {
		t.Fatal("persistedAckPresent rolled back to false")
	}
	if len(env.metrics.ackHWMs) != 0 {
		t.Fatalf("SetAckHighWatermark called on failure path: %v", env.metrics.ackHWMs)
	}
	if len(env.metrics.anomalousAckReasons) != 0 {
		t.Fatalf("anomaly counter incremented on rollback path: %v", env.metrics.anomalousAckReasons)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN: got %d, want 1: %+v", got, entries)
	}
	w := firstLevel(entries, "WARN")
	if w.Attrs["frame"] != "batch_ack" {
		t.Fatalf("WARN frame: got %v, want batch_ack", w.Attrs["frame"])
	}
	if v, ok := w.Attrs["attempted_seq"].(float64); !ok || uint64(v) != 100 {
		t.Fatalf("WARN attempted_seq: got %v, want 100", w.Attrs["attempted_seq"])
	}
	if v, ok := w.Attrs["attempted_gen"].(float64); !ok || uint32(v) != 7 {
		t.Fatalf("WARN attempted_gen: got %v, want 7", w.Attrs["attempted_gen"])
	}
}

// silence unused import warnings for wal package; the wal package is needed
// for clampTestEnv types pulled in transitively in some test rows.
var _ = wal.LossRecord{}
