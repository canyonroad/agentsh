package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"golang.org/x/time/rate"
)

// fakeMetrics records all calls to the transport.Metrics interface for
// assertion. Mirrors the production *internal/metrics.WTPMetrics surface
// the Task 22a/22b wiring will satisfy once those tasks land.
type fakeMetrics struct {
	ackHWMs              []int64
	anomalousAckReasons  []string
	resendNeeded         int
	ackRegressionLoss    int
}

func (f *fakeMetrics) SetAckHighWatermark(seq int64)   { f.ackHWMs = append(f.ackHWMs, seq) }
func (f *fakeMetrics) IncAnomalousAck(reason string)   { f.anomalousAckReasons = append(f.anomalousAckReasons, reason) }
func (f *fakeMetrics) IncResendNeeded()                { f.resendNeeded++ }
func (f *fakeMetrics) IncAckRegressionLoss()           { f.ackRegressionLoss++ }

// logEntry decodes a single JSON-formatted slog record.
type logEntry struct {
	Level string         `json:"level"`
	Msg   string         `json:"msg"`
	Attrs map[string]any `json:"-"`
}

// parseLogBuffer splits a JSON-line slog buffer into entries with all
// non-standard fields lifted into Attrs for assertion.
func parseLogBuffer(t *testing.T, buf *bytes.Buffer) []logEntry {
	t.Helper()
	if buf.Len() == 0 {
		return nil
	}
	var out []logEntry
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		raw := map[string]any{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("failed to parse log line %q: %v", line, err)
		}
		entry := logEntry{
			Level: asString(raw["level"]),
			Msg:   asString(raw["msg"]),
			Attrs: map[string]any{},
		}
		for k, v := range raw {
			switch k {
			case "level", "msg", "time":
			default:
				entry.Attrs[k] = v
			}
		}
		out = append(out, entry)
	}
	return out
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// countLevel returns the number of entries at the given level.
func countLevel(entries []logEntry, level string) int {
	n := 0
	for _, e := range entries {
		if e.Level == level {
			n++
		}
	}
	return n
}

// firstLevel returns the first entry at the given level (or zero value).
func firstLevel(entries []logEntry, level string) logEntry {
	for _, e := range entries {
		if e.Level == level {
			return e
		}
	}
	return logEntry{}
}

// clampTestEnv bundles the per-test fixtures: a real WAL, a Transport
// constructed with a buffer-backed logger and fake metrics, and helpers to
// drive the SessionAck dispatch via a preloaded fakeConn.
type clampTestEnv struct {
	dir     string
	walDir  string
	w       *wal.WAL
	tr      *Transport
	metrics *fakeMetrics
	logBuf  *bytes.Buffer
	logger  *slog.Logger
}

// newClampTestEnv builds a new test environment. SessionID and
// KeyFingerprint default to deterministic test values so meta.json carries
// stable identity.
func newClampTestEnv(t *testing.T, opts Options) *clampTestEnv {
	t.Helper()
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   64 * 1024,
		MaxTotalBytes: 1 << 20,
		SyncMode:      wal.SyncImmediate,
		SessionID:     "sess-clamp",
	})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := &fakeMetrics{}

	if opts.Dialer == nil {
		opts.Dialer = DialerFunc(func(_ context.Context) (Conn, error) {
			return nil, errors.New("Dial should not be invoked")
		})
	}
	if opts.AgentID == "" {
		opts.AgentID = "test-agent"
	}
	if opts.SessionID == "" {
		opts.SessionID = "sess-clamp"
	}
	opts.WAL = w
	opts.Logger = logger
	opts.Metrics = m

	tr, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &clampTestEnv{
		dir:     dir,
		walDir:  dir,
		w:       w,
		tr:      tr,
		metrics: m,
		logBuf:  logBuf,
		logger:  logger,
	}
}

// driveSessionAck preloads a SessionAck onto a freshly-constructed conn,
// runs RunOnce(StateConnecting), and asserts the post-state. Returns the
// recv'd state and any error.
func (env *clampTestEnv) driveSessionAck(t *testing.T, gen uint32, seq uint64, accepted bool) (State, error) {
	t.Helper()
	fc := &internalFakeConn{
		recvMsg: &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_SessionAck{
				SessionAck: &wtpv1.SessionAck{
					Accepted:            accepted,
					AckHighWatermarkSeq: seq,
					Generation:          gen,
				},
			},
		},
	}
	// Re-wire the dialer so RunOnce(Connecting) gets THIS fake conn.
	env.tr.opts.Dialer = DialerFunc(func(_ context.Context) (Conn, error) { return fc, nil })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return env.tr.RunOnce(ctx, StateConnecting)
}

// appendDataInGen writes `count` RecordData entries with sequential seqs
// starting at startSeq into the supplied generation. Verifies each Append
// returned no error and (optionally) that GenerationRolled flips when the
// generation differs from the previous Append.
func appendDataInGen(t *testing.T, w *wal.WAL, startSeq int64, gen uint32, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		if _, err := w.Append(startSeq+int64(i), gen, []byte{byte(i & 0xff)}); err != nil {
			t.Fatalf("Append seq=%d gen=%d: %v", startSeq+int64(i), gen, err)
		}
	}
}

// readMetaForTest re-reads meta.json from the WAL directory.
func readMetaForTest(t *testing.T, dir string) wal.Meta {
	t.Helper()
	m, err := wal.ReadMeta(dir)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	return m
}

// permissiveLimiter returns a rate.Limiter that always Allows. Use in
// tests that want to observe every WARN entry rather than assert on
// rate-limit semantics.
func permissiveLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Inf, 1)
}

// strictLimiter returns a rate.Limiter that emits at most one event per
// hour. Use in TestSessionAck_AnomalyWarnRateLimited to prove the limiter
// is wired correctly.
func strictLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Every(time.Hour), 1)
}

// ===== Test #1 =====
// TestApplyServerAckTuple_HigherSameGenAdvancesPersistedAck — happy
// advance path with a real *wal.WAL. Append 1..200 at gen=7, seed
// (50, 7), drive helper at (7, 100) → Adopted; after dispatch wal.ReadMeta
// shows (7, 100, true) and SetAckHighWatermark(100) recorded.
func TestApplyServerAckTuple_HigherSameGenAdvancesPersistedAck(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 50, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 200)

	outcome := ApplyServerAckTupleForTest(env.tr, 7, 100)
	if outcome.Kind != AckOutcomeAdopted {
		t.Fatalf("kind: got %v, want Adopted", outcome.Kind)
	}
	if !outcome.PersistedAdvanced {
		t.Fatal("PersistedAdvanced must be true on Adopted")
	}
	if got := PersistedAckForTest(env.tr); got != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck: got %+v, want {100,7}", got)
	}
	if got := RemoteReplayCursorForTest(env.tr); got != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("remoteReplayCursor: got %+v, want {100,7}", got)
	}

	// Drive the SessionAck dispatch end-to-end so MarkAcked + metric run.
	// Reset cursors so the dispatch path re-runs the helper with the same
	// (gen, seq) and exercises the side-effect contract.
	env.tr.persistedAck = AckCursor{Sequence: 50, Generation: 7}
	env.tr.persistedAckPresent = true
	env.tr.remoteReplayCursor = AckCursor{Sequence: 50, Generation: 7}
	st, err := env.driveSessionAck(t, 7, 100, true)
	if err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}
	if st != StateReplaying {
		t.Fatalf("state: got %v, want StateReplaying", st)
	}

	// meta.json must reflect the Adopted advance.
	m := readMetaForTest(t, env.walDir)
	if m.AckHighWatermarkGen != 7 || m.AckHighWatermarkSeq != 100 || !m.AckRecorded {
		t.Fatalf("meta after Adopted: got (%d, %d, %v), want (7, 100, true)",
			m.AckHighWatermarkGen, m.AckHighWatermarkSeq, m.AckRecorded)
	}

	// Metric must have been emitted exactly once with the post-clamp seq.
	if len(env.metrics.ackHWMs) != 1 || env.metrics.ackHWMs[0] != 100 {
		t.Fatalf("SetAckHighWatermark calls: got %v, want [100]", env.metrics.ackHWMs)
	}
	if env.metrics.resendNeeded != 0 || len(env.metrics.anomalousAckReasons) != 0 {
		t.Fatalf("unexpected metric activity: resend=%d anomaly=%v",
			env.metrics.resendNeeded, env.metrics.anomalousAckReasons)
	}

	// WARN/INFO buffers empty (Adopted is silent).
	entries := parseLogBuffer(t, env.logBuf)
	if countLevel(entries, "WARN") != 0 || countLevel(entries, "INFO") != 0 {
		t.Fatalf("unexpected log activity on Adopted: %+v", entries)
	}
}

// ===== Test #2 =====
// TestApplyServerAckTuple_LowerSameGenIsResendNeeded — same-gen lex-lower.
// Seed (100, 7), drive MarkAcked first to fix meta. Helper (7, 50) →
// ResendNeeded; persistedAck unchanged; remoteReplayCursor=(50, 7).
// Dispatch: MarkAcked NOT called again, IncResendNeeded once, INFO entry.
func TestApplyServerAckTuple_LowerSameGenIsResendNeeded(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 200)
	// Seed meta.json with an existing (7, 100) ack so a same-gen lower
	// helper call does not race with first-apply.
	if err := env.w.MarkAcked(7, 100); err != nil {
		t.Fatalf("MarkAcked seed: %v", err)
	}

	outcome := ApplyServerAckTupleForTest(env.tr, 7, 50)
	if outcome.Kind != AckOutcomeResendNeeded {
		t.Fatalf("kind: got %v, want ResendNeeded", outcome.Kind)
	}
	if got := PersistedAckForTest(env.tr); got != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck moved on ResendNeeded: %+v", got)
	}
	if got := RemoteReplayCursorForTest(env.tr); got != (AckCursor{Sequence: 50, Generation: 7}) {
		t.Fatalf("remoteReplayCursor: got %+v, want {50,7}", got)
	}

	// Reset for dispatch (helper already mutated the in-memory cursor; the
	// dispatch path re-applies and asserts the side-effect contract).
	env.tr.persistedAck = AckCursor{Sequence: 100, Generation: 7}
	env.tr.persistedAckPresent = true
	env.tr.remoteReplayCursor = AckCursor{Sequence: 100, Generation: 7}

	if _, err := env.driveSessionAck(t, 7, 50, true); err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}

	// meta.json untouched — still (7, 100, true).
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
		t.Fatalf("unexpected anomaly metrics: %v", env.metrics.anomalousAckReasons)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if countLevel(entries, "WARN") != 0 {
		t.Fatalf("unexpected WARN on ResendNeeded: %+v", entries)
	}
	if got := countLevel(entries, "INFO"); got != 1 {
		t.Fatalf("INFO entries: got %d, want 1: %+v", got, entries)
	}
}

// ===== Test #3 =====
// TestApplyServerAckTuple_EqualTuple — NoOp; no metric, no log.
func TestApplyServerAckTuple_EqualTuple(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 100)

	outcome := ApplyServerAckTupleForTest(env.tr, 7, 100)
	if outcome.Kind != AckOutcomeNoOp {
		t.Fatalf("kind: got %v, want NoOp", outcome.Kind)
	}
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck mutated on NoOp")
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("remoteReplayCursor mutated on NoOp")
	}

	if _, err := env.driveSessionAck(t, 7, 100, true); err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}
	if len(env.metrics.ackHWMs) != 0 || env.metrics.resendNeeded != 0 || len(env.metrics.anomalousAckReasons) != 0 {
		t.Fatalf("metrics moved on NoOp: %+v", env.metrics)
	}
	entries := parseLogBuffer(t, env.logBuf)
	if len(entries) != 0 {
		t.Fatalf("unexpected log entries on NoOp: %+v", entries)
	}
}

// ===== Test #4 =====
// TestApplyServerAckTuple_FirstApplyAdoptsServer — InitialAckTuple=nil;
// helper (8, 100) → Adopted, both cursors=(100, 8), persistedAckPresent=true.
// Then helper (8, 50) → ResendNeeded.
func TestApplyServerAckTuple_FirstApplyAdoptsServer(t *testing.T) {
	env := newClampTestEnv(t, Options{
		// no InitialAckTuple
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	// Pre-populate gen=8 RecordData so the same-gen ResendNeeded follow-up
	// has a generation to play with.
	appendDataInGen(t, env.w, 1, 8, 200)

	if PersistedAckPresentForTest(env.tr) {
		t.Fatal("persistedAckPresent should start false with nil InitialAckTuple")
	}

	outcome := ApplyServerAckTupleForTest(env.tr, 8, 100)
	if outcome.Kind != AckOutcomeAdopted || !outcome.PersistedAdvanced {
		t.Fatalf("first-apply: got %+v, want Adopted with PersistedAdvanced", outcome)
	}
	if !PersistedAckPresentForTest(env.tr) {
		t.Fatal("persistedAckPresent must be true after first-apply Adopted")
	}
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 8}) {
		t.Fatalf("persistedAck: got %+v, want {100,8}", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 8}) {
		t.Fatalf("remoteReplayCursor: got %+v, want {100,8}", RemoteReplayCursorForTest(env.tr))
	}

	// Second call: (8, 50) → ResendNeeded.
	outcome2 := ApplyServerAckTupleForTest(env.tr, 8, 50)
	if outcome2.Kind != AckOutcomeResendNeeded {
		t.Fatalf("second call: got %v, want ResendNeeded", outcome2.Kind)
	}
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 8}) {
		t.Fatalf("persistedAck moved on second-call ResendNeeded: %+v", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 50, Generation: 8}) {
		t.Fatalf("remoteReplayCursor: got %+v, want {50,8}", RemoteReplayCursorForTest(env.tr))
	}
}

// ===== Test #5 =====
// TestApplyServerAckTuple_ServerAckExceedsLocalSeqIsAnomaly — same-gen
// over-watermark. WAL has up to seq 50 in gen 7. Seed (30, 7). Helper
// (7, 60) → Anomaly("server_ack_exceeds_local_seq").
func TestApplyServerAckTuple_ServerAckExceedsLocalSeqIsAnomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 30, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 50)

	outcome := ApplyServerAckTupleForTest(env.tr, 7, 60)
	if outcome.Kind != AckOutcomeAnomaly {
		t.Fatalf("kind: got %v, want Anomaly", outcome.Kind)
	}
	if outcome.AnomalyReason != "server_ack_exceeds_local_seq" {
		t.Fatalf("reason: got %q, want server_ack_exceeds_local_seq", outcome.AnomalyReason)
	}
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 30, Generation: 7}) {
		t.Fatalf("persistedAck mutated on Anomaly: %+v", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 30, Generation: 7}) {
		t.Fatalf("remoteReplayCursor mutated on Anomaly: %+v", RemoteReplayCursorForTest(env.tr))
	}

	if _, err := env.driveSessionAck(t, 7, 60, true); err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}
	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "server_ack_exceeds_local_seq" {
		t.Fatalf("anomaly metric: got %v", env.metrics.anomalousAckReasons)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN entries: got %d, want 1: %+v", got, entries)
	}
	w := firstLevel(entries, "WARN")
	if w.Attrs["reason"] != "server_ack_exceeds_local_seq" {
		t.Fatalf("WARN reason: got %v", w.Attrs["reason"])
	}
	if v, ok := w.Attrs["wal_written_data_high_seq"].(float64); !ok || uint64(v) != 50 {
		t.Fatalf("WARN wal_written_data_high_seq: got %v", w.Attrs["wal_written_data_high_seq"])
	}
	if v, ok := w.Attrs["wal_written_data_high_ok"].(bool); !ok || !v {
		t.Fatalf("WARN wal_written_data_high_ok: got %v", w.Attrs["wal_written_data_high_ok"])
	}
}

// ===== Test #5a =====
// TestApplyServerAckTuple_LowerGenIsAnomaly — Seed (100, 8). Helper
// (7, 200) → Anomaly("stale_generation").
func TestApplyServerAckTuple_LowerGenIsAnomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 8, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	outcome := ApplyServerAckTupleForTest(env.tr, 7, 200)
	if outcome.Kind != AckOutcomeAnomaly || outcome.AnomalyReason != "stale_generation" {
		t.Fatalf("got %+v, want Anomaly/stale_generation", outcome)
	}
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 8}) {
		t.Fatalf("persistedAck mutated on Anomaly: %+v", PersistedAckForTest(env.tr))
	}

	if _, err := env.driveSessionAck(t, 7, 200, true); err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}
	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "stale_generation" {
		t.Fatalf("anomaly metric: got %v", env.metrics.anomalousAckReasons)
	}
	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN entries: got %d, want 1", got)
	}
}

// ===== Test #5b =====
// TestApplyServerAckTuple_HigherGenWithinPerGenDataHW_Adopted — open WAL,
// append gen=7 records, roll to gen=8 with a RecordData. Seed (100, 7).
// Helper (8, 5) → Adopted; ReadMeta shows (8, 5, true).
func TestApplyServerAckTuple_HigherGenWithinPerGenDataHW_Adopted(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	appendDataInGen(t, env.w, 1, 7, 100)
	// Seed meta.json with the higher per-gen ack to match InitialAckTuple's
	// view; otherwise WAL.MarkAcked will succeed but not provide a
	// monotonic-cross-gen reference baseline. (MarkAcked accepts the lex
	// advance directly so this is purely cosmetic.)
	if err := env.w.MarkAcked(7, 100); err != nil {
		t.Fatalf("MarkAcked: %v", err)
	}
	// Now roll to gen=8 by appending in gen=8.
	appendDataInGen(t, env.w, 1, 8, 5)

	outcome := ApplyServerAckTupleForTest(env.tr, 8, 5)
	if outcome.Kind != AckOutcomeAdopted || !outcome.PersistedAdvanced {
		t.Fatalf("got %+v, want Adopted/PersistedAdvanced", outcome)
	}
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 5, Generation: 8}) {
		t.Fatalf("persistedAck: got %+v, want {5,8}", PersistedAckForTest(env.tr))
	}

	// Reset for dispatch and run end-to-end.
	env.tr.persistedAck = AckCursor{Sequence: 100, Generation: 7}
	env.tr.persistedAckPresent = true
	env.tr.remoteReplayCursor = AckCursor{Sequence: 100, Generation: 7}
	if _, err := env.driveSessionAck(t, 8, 5, true); err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}
	m := readMetaForTest(t, env.walDir)
	if m.AckHighWatermarkGen != 8 || m.AckHighWatermarkSeq != 5 || !m.AckRecorded {
		t.Fatalf("meta after cross-gen Adopted: got (%d, %d, %v), want (8, 5, true)",
			m.AckHighWatermarkGen, m.AckHighWatermarkSeq, m.AckRecorded)
	}
	if len(env.metrics.ackHWMs) != 1 || env.metrics.ackHWMs[0] != 5 {
		t.Fatalf("SetAckHighWatermark: got %v, want [5]", env.metrics.ackHWMs)
	}
	entries := parseLogBuffer(t, env.logBuf)
	if countLevel(entries, "WARN") != 0 || countLevel(entries, "INFO") != 0 {
		t.Fatalf("Adopted should be silent; got %+v", entries)
	}
}

// ===== Test #5b' =====
// TestApplyServerAckTuple_HigherGenButOnlyHeaderExists_Anomaly — roll to
// gen=8 WITHOUT appending data. Helper (8, 0) → Anomaly("unwritten_generation").
func TestApplyServerAckTuple_HigherGenButOnlyHeaderExists_Anomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	appendDataInGen(t, env.w, 1, 7, 100)
	if err := env.w.MarkAcked(7, 100); err != nil {
		t.Fatalf("MarkAcked: %v", err)
	}
	// We do NOT append in gen=8, so WrittenDataHighWater(8) returns ok=false.

	outcome := ApplyServerAckTupleForTest(env.tr, 8, 0)
	if outcome.Kind != AckOutcomeAnomaly || outcome.AnomalyReason != "unwritten_generation" {
		t.Fatalf("got %+v, want Anomaly/unwritten_generation", outcome)
	}
	// CRITICAL: cursors UNCHANGED.
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck mutated: %+v", PersistedAckForTest(env.tr))
	}
	if RemoteReplayCursorForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("remoteReplayCursor mutated: %+v", RemoteReplayCursorForTest(env.tr))
	}

	if _, err := env.driveSessionAck(t, 8, 0, true); err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}
	m := readMetaForTest(t, env.walDir)
	if m.AckHighWatermarkGen != 7 || m.AckHighWatermarkSeq != 100 {
		t.Fatalf("meta moved on Anomaly: got (%d, %d), want (7, 100)",
			m.AckHighWatermarkGen, m.AckHighWatermarkSeq)
	}
	// Lower-gen segments must still exist on disk (safety proof).
	entries, err := readSegmentsDir(t, env.walDir)
	if err != nil {
		t.Fatalf("readSegmentsDir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("all segments GC'd; safety check failed")
	}
}

// readSegmentsDir lists the segment directory entries, mirroring how the
// WAL itself enumerates files. Used by the safety-check tests to assert
// that lower-gen segments survive an Anomaly.
func readSegmentsDir(t *testing.T, walDir string) ([]string, error) {
	t.Helper()
	dir := filepath.Join(walDir, "segments")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// ===== Test #5c =====
// TestApplyServerAckTuple_HigherSameGenBeyondPerGenDataHW_Anomaly —
// gen=8 has data up to seq=10. Seed (100, 7). Helper (8, 999) →
// Anomaly("server_ack_exceeds_local_data").
func TestApplyServerAckTuple_HigherSameGenBeyondPerGenDataHW_Anomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

	appendDataInGen(t, env.w, 1, 7, 100)
	if err := env.w.MarkAcked(7, 100); err != nil {
		t.Fatalf("MarkAcked: %v", err)
	}
	appendDataInGen(t, env.w, 1, 8, 10)

	outcome := ApplyServerAckTupleForTest(env.tr, 8, 999)
	if outcome.Kind != AckOutcomeAnomaly || outcome.AnomalyReason != "server_ack_exceeds_local_data" {
		t.Fatalf("got %+v, want Anomaly/server_ack_exceeds_local_data", outcome)
	}
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 100, Generation: 7}) {
		t.Fatalf("persistedAck mutated: %+v", PersistedAckForTest(env.tr))
	}

	if _, err := env.driveSessionAck(t, 8, 999, true); err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}
	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "server_ack_exceeds_local_data" {
		t.Fatalf("anomaly metric: got %v", env.metrics.anomalousAckReasons)
	}
	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN: got %d, want 1", got)
	}
	w := firstLevel(entries, "WARN")
	if v, ok := w.Attrs["wal_written_data_high_seq"].(float64); !ok || uint64(v) != 10 {
		t.Fatalf("wal_written_data_high_seq: got %v", w.Attrs["wal_written_data_high_seq"])
	}
}

// ===== Test #5d =====
// TestApplyServerAckTuple_WALReadFailureIsAnomaly — override
// walWrittenDataHighWaterFn to return EIO. Helper (7, 60) → Anomaly("wal_read_failure").
func TestApplyServerAckTuple_WALReadFailureIsAnomaly(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 30, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 50)

	SetWALWrittenDataHighWaterFnForTest(env.tr, func(_ uint32) (uint64, bool, error) {
		return 0, false, errors.New("EIO")
	})

	outcome := ApplyServerAckTupleForTest(env.tr, 7, 60)
	if outcome.Kind != AckOutcomeAnomaly || outcome.AnomalyReason != "wal_read_failure" {
		t.Fatalf("got %+v, want Anomaly/wal_read_failure", outcome)
	}
	if PersistedAckForTest(env.tr) != (AckCursor{Sequence: 30, Generation: 7}) {
		t.Fatalf("persistedAck mutated: %+v", PersistedAckForTest(env.tr))
	}

	if _, err := env.driveSessionAck(t, 7, 60, true); err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}
	if len(env.metrics.anomalousAckReasons) != 1 || env.metrics.anomalousAckReasons[0] != "wal_read_failure" {
		t.Fatalf("anomaly metric: got %v", env.metrics.anomalousAckReasons)
	}

	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN: got %d, want 1", got)
	}
	w := firstLevel(entries, "WARN")
	if v, ok := w.Attrs["wal_written_data_high_err"].(string); !ok || v != "EIO" {
		t.Fatalf("WARN wal_written_data_high_err: got %v", w.Attrs["wal_written_data_high_err"])
	}
}

// ===== Test #6 =====
// TestSessionAck_AnomalyWarnRateLimited — strict limiter; five anomalies
// → exactly one WARN, but five IncAnomalousAck (counter is NOT rate-limited).
func TestSessionAck_AnomalyWarnRateLimited(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 100, Generation: 8, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, strictLimiter())

	for i := 0; i < 5; i++ {
		// Reset cursors so the helper re-evaluates the same Anomaly path.
		env.tr.persistedAck = AckCursor{Sequence: 100, Generation: 8}
		env.tr.persistedAckPresent = true
		env.tr.remoteReplayCursor = AckCursor{Sequence: 100, Generation: 8}
		if _, err := env.driveSessionAck(t, 7, 200, true); err != nil {
			t.Fatalf("driveSessionAck %d: %v", i, err)
		}
	}

	if got, want := len(env.metrics.anomalousAckReasons), 5; got != want {
		t.Fatalf("anomaly counter: got %d, want %d", got, want)
	}
	entries := parseLogBuffer(t, env.logBuf)
	if got := countLevel(entries, "WARN"); got != 1 {
		t.Fatalf("WARN entries (rate-limited): got %d, want 1", got)
	}
}

// ===== Test #7 =====
// TestApplyServerAckTuple_AdoptedDoesNotAdvanceOnMarkAckedFailure — override
// walMarkAckedFn to return error. Seed (50, 7). Helper (7, 100) returns
// Adopted; after dispatch BOTH cursors rolled back to (50, 7).
func TestApplyServerAckTuple_AdoptedDoesNotAdvanceOnMarkAckedFailure(t *testing.T) {
	env := newClampTestEnv(t, Options{
		InitialAckTuple: &AckTuple{Sequence: 50, Generation: 7, Present: true},
	})
	SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
	appendDataInGen(t, env.w, 1, 7, 200)

	injectedErr := errors.New("disk full")
	SetWALMarkAckedFnForTest(env.tr, func(_ uint32, _ uint64) error { return injectedErr })

	if _, err := env.driveSessionAck(t, 7, 100, true); err != nil {
		t.Fatalf("driveSessionAck: %v", err)
	}
	// Cursors rolled back.
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
		t.Fatalf("WARN: got %d, want 1 (the rollback warning): %+v", got, entries)
	}
	w := firstLevel(entries, "WARN")
	if v, ok := w.Attrs["attempted_seq"].(float64); !ok || uint64(v) != 100 {
		t.Fatalf("WARN attempted_seq: got %v, want 100", w.Attrs["attempted_seq"])
	}
	if v, ok := w.Attrs["attempted_gen"].(float64); !ok || uint32(v) != 7 {
		t.Fatalf("WARN attempted_gen: got %v, want 7", w.Attrs["attempted_gen"])
	}
}

// ===== Test #8 =====
// TestApplyServerAckTuple_EmitsMetricOnAdopted — three same-gen monotonic
// advances + one NoOp. Each Adopted bumps MarkAcked count + metric;
// NoOp does nothing.
func TestApplyServerAckTuple_EmitsMetricOnAdopted(t *testing.T) {
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
		// Reset cursors so the dispatch path always exercises the helper
		// from a clean baseline. (In production we would not reset; the
		// monotonic chain advances naturally.)
		env.tr.persistedAck = AckCursor{Sequence: want - 50, Generation: 1}
		env.tr.persistedAckPresent = true
		env.tr.remoteReplayCursor = AckCursor{Sequence: want - 50, Generation: 1}
		if _, err := env.driveSessionAck(t, 1, want, true); err != nil {
			t.Fatalf("driveSessionAck %d: %v", want, err)
		}
		if got := PersistedAckForTest(env.tr); got != (AckCursor{Sequence: want, Generation: 1}) {
			t.Fatalf("persistedAck after Adopted (%d): %+v", want, got)
		}
	}
	if markCount != 3 {
		t.Fatalf("MarkAcked calls: got %d, want 3", markCount)
	}
	if len(env.metrics.ackHWMs) != 3 {
		t.Fatalf("SetAckHighWatermark calls: got %d, want 3 (%v)", len(env.metrics.ackHWMs), env.metrics.ackHWMs)
	}
	if env.metrics.ackHWMs[len(env.metrics.ackHWMs)-1] != 300 {
		t.Fatalf("last SetAckHighWatermark: got %d, want 300", env.metrics.ackHWMs[len(env.metrics.ackHWMs)-1])
	}

	// Fourth call: NoOp. cursors at (300, 1).
	prevMark := markCount
	prevHWMs := len(env.metrics.ackHWMs)
	if _, err := env.driveSessionAck(t, 1, 300, true); err != nil {
		t.Fatalf("driveSessionAck NoOp: %v", err)
	}
	if markCount != prevMark {
		t.Fatalf("MarkAcked called on NoOp: got %d, was %d", markCount, prevMark)
	}
	if len(env.metrics.ackHWMs) != prevHWMs {
		t.Fatalf("SetAckHighWatermark called on NoOp: got %d, was %d",
			len(env.metrics.ackHWMs), prevHWMs)
	}
}

// TestApplyServerAckTuple_FirstApplyValidatesAgainstWAL — round-14 Finding 1
// regression. Without InitialAckTuple (persistedAckPresent=false), the
// helper MUST validate the server tuple against local WAL data before
// adopting; an unbounded server tuple cannot be allowed to seed the
// persistedAck cursor (which drives the GC predicate) at an impossible
// position. Three sub-cases mirror the production validation rules:
//
//  1. server_seq_zero_adopts: seq=0 is vacuous, adopted unconditionally.
//  2. server_seq_beyond_local_data: WAL has gen=8 records 1..50, server
//     reports (gen=8, seq=200). Helper MUST return Anomaly(
//     "server_ack_exceeds_local_data") with cursors UNCHANGED and
//     persistedAckPresent still false.
//  3. unwritten_generation: WAL has gen=7 only, server reports (gen=8,
//     seq=10). Helper MUST return Anomaly("unwritten_generation") with
//     cursors UNCHANGED and persistedAckPresent still false.
//
// The fourth sub-case (wal_read_failure) is exercised separately via the
// WrittenDataHighWater seam below.
func TestApplyServerAckTuple_FirstApplyValidatesAgainstWAL(t *testing.T) {
	t.Run("server_seq_zero_adopts", func(t *testing.T) {
		env := newClampTestEnv(t, Options{}) // no InitialAckTuple
		SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())

		outcome := ApplyServerAckTupleForTest(env.tr, 5, 0)
		if outcome.Kind != AckOutcomeAdopted {
			t.Fatalf("kind: got %v, want Adopted (seq=0 vacuous case)", outcome.Kind)
		}
		if !outcome.PersistedAdvanced {
			t.Fatal("PersistedAdvanced must be true on first-apply Adopted")
		}
		if !PersistedAckPresentForTest(env.tr) {
			t.Fatal("persistedAckPresent must flip to true on first-apply Adopted")
		}
		if got := PersistedAckForTest(env.tr); got != (AckCursor{Sequence: 0, Generation: 5}) {
			t.Fatalf("persistedAck: got %+v, want {0,5}", got)
		}
	})

	t.Run("server_seq_beyond_local_data_is_anomaly", func(t *testing.T) {
		env := newClampTestEnv(t, Options{}) // no InitialAckTuple
		SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
		appendDataInGen(t, env.w, 1, 8, 50) // gen=8 records 1..50 only

		outcome := ApplyServerAckTupleForTest(env.tr, 8, 200)
		if outcome.Kind != AckOutcomeAnomaly {
			t.Fatalf("kind: got %v, want Anomaly", outcome.Kind)
		}
		if outcome.AnomalyReason != "server_ack_exceeds_local_data" {
			t.Fatalf("reason: got %q, want server_ack_exceeds_local_data", outcome.AnomalyReason)
		}
		if PersistedAckPresentForTest(env.tr) {
			t.Fatal("persistedAckPresent must remain false on first-apply Anomaly")
		}
		if got := PersistedAckForTest(env.tr); got != (AckCursor{}) {
			t.Fatalf("persistedAck mutated on first-apply Anomaly: %+v", got)
		}
		if got := RemoteReplayCursorForTest(env.tr); got != (AckCursor{}) {
			t.Fatalf("remoteReplayCursor mutated on first-apply Anomaly: %+v", got)
		}
	})

	t.Run("unwritten_generation_is_anomaly", func(t *testing.T) {
		env := newClampTestEnv(t, Options{}) // no InitialAckTuple
		SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
		appendDataInGen(t, env.w, 1, 7, 50) // only gen=7 has data

		outcome := ApplyServerAckTupleForTest(env.tr, 8, 10)
		if outcome.Kind != AckOutcomeAnomaly {
			t.Fatalf("kind: got %v, want Anomaly", outcome.Kind)
		}
		if outcome.AnomalyReason != "unwritten_generation" {
			t.Fatalf("reason: got %q, want unwritten_generation", outcome.AnomalyReason)
		}
		if PersistedAckPresentForTest(env.tr) {
			t.Fatal("persistedAckPresent must remain false on first-apply Anomaly")
		}
	})

	t.Run("wal_read_failure_is_anomaly", func(t *testing.T) {
		env := newClampTestEnv(t, Options{}) // no InitialAckTuple
		SetAckAnomalyLimiterForTest(env.tr, permissiveLimiter())
		// Inject a hard read failure from WrittenDataHighWater.
		injErr := errors.New("simulated wal read failure")
		SetWALWrittenDataHighWaterFnForTest(env.tr, func(uint32) (uint64, bool, error) {
			return 0, false, injErr
		})

		outcome := ApplyServerAckTupleForTest(env.tr, 8, 5)
		if outcome.Kind != AckOutcomeAnomaly {
			t.Fatalf("kind: got %v, want Anomaly", outcome.Kind)
		}
		if outcome.AnomalyReason != "wal_read_failure" {
			t.Fatalf("reason: got %q, want wal_read_failure", outcome.AnomalyReason)
		}
		if PersistedAckPresentForTest(env.tr) {
			t.Fatal("persistedAckPresent must remain false on first-apply WAL failure")
		}
	})
}
