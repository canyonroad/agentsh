package metrics

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWTPMetrics_AppendAndExpose(t *testing.T) {
	c := New()
	w := c.WTP()

	w.IncEventsAppended(5)
	w.IncEventsAcked(3)
	w.IncBatchesSent(1)
	w.AddBytesSent(2048)
	w.IncTransportLoss(2)
	w.IncReconnects(WTPReconnectReasonDialFailed)
	w.SetSessionState(WTPStateLive)
	w.SetWALSegments(7)
	w.SetWALBytes(16 * 1024 * 1024)
	w.SetAckHighWatermark(42)
	w.ObserveSendLatency(150 * time.Millisecond)

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	for _, want := range []string{
		"wtp_events_appended_total 5",
		"wtp_events_acked_total 3",
		"wtp_batches_sent_total 1",
		"wtp_bytes_sent_total 2048",
		"wtp_transport_loss_total 2",
		`wtp_reconnects_total{reason="dial_failed"} 1`,
		"wtp_session_state 2",
		"wtp_wal_segments 7",
		"wtp_wal_bytes 16777216",
		"wtp_ack_high_watermark 42",
		"wtp_send_latency_seconds_count 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestWTPMetrics_NilSafe(t *testing.T) {
	var c *Collector
	w := c.WTP()
	// All accessors must no-op on nil collector.
	w.IncEventsAppended(1)
	w.SetSessionState(WTPStateConnecting)
	w.AddBytesSent(99)
}

func TestWTPMetrics_LossUnknownReasonExposed(t *testing.T) {
	c := New()
	c.WTP().IncWTPLossUnknownReason(3)

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	out := rr.Body.String()

	if !strings.Contains(out, "# HELP wtp_loss_unknown_reason_total") {
		t.Fatalf("HELP missing for wtp_loss_unknown_reason_total:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE wtp_loss_unknown_reason_total counter") {
		t.Fatalf("TYPE missing for wtp_loss_unknown_reason_total:\n%s", out)
	}
	if !strings.Contains(out, "wtp_loss_unknown_reason_total 3") {
		t.Fatalf("counter line wrong:\n%s", out)
	}
}

func TestWTPMetrics_HistogramBucketBoundaries(t *testing.T) {
	c := New()
	w := c.WTP()

	// 5ms — boundary of the 0.005 bucket (and all higher buckets)
	w.ObserveSendLatency(5 * time.Millisecond)
	// 30ms — boundary of the 0.05 bucket (skips 0.001, 0.005, 0.01, 0.025)
	w.ObserveSendLatency(30 * time.Millisecond)
	// 60s — exceeds final 30 bucket; only +Inf catches it
	w.ObserveSendLatency(60 * time.Second)

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	// Expected per-bucket cumulative counts:
	//   le=0.001 → 0  (5ms > 1ms; 30ms > 1ms; 60s > 1ms)
	//   le=0.005 → 1  (5ms ≤ 5ms; 30ms > 5ms; 60s > 5ms)
	//   le=0.01  → 1  (5ms ≤ 10ms; 30ms > 10ms)
	//   le=0.025 → 1  (5ms ≤ 25ms; 30ms > 25ms)
	//   le=0.05  → 2  (5ms and 30ms both ≤ 50ms; 60s > 50ms)
	//   le=0.1   → 2
	//   le=0.25  → 2
	//   le=0.5   → 2
	//   le=1     → 2
	//   le=2.5   → 2
	//   le=5     → 2
	//   le=10    → 2
	//   le=30    → 2
	//   le=+Inf  → 3
	expectations := map[string]int{
		`wtp_send_latency_seconds_bucket{le="0.001"}`: 0,
		`wtp_send_latency_seconds_bucket{le="0.005"}`: 1,
		`wtp_send_latency_seconds_bucket{le="0.01"}`:  1,
		`wtp_send_latency_seconds_bucket{le="0.025"}`: 1,
		`wtp_send_latency_seconds_bucket{le="0.05"}`:  2,
		`wtp_send_latency_seconds_bucket{le="0.1"}`:   2,
		`wtp_send_latency_seconds_bucket{le="0.25"}`:  2,
		`wtp_send_latency_seconds_bucket{le="0.5"}`:   2,
		`wtp_send_latency_seconds_bucket{le="1"}`:     2,
		`wtp_send_latency_seconds_bucket{le="2.5"}`:   2,
		`wtp_send_latency_seconds_bucket{le="5"}`:     2,
		`wtp_send_latency_seconds_bucket{le="10"}`:    2,
		`wtp_send_latency_seconds_bucket{le="30"}`:    2,
		`wtp_send_latency_seconds_bucket{le="+Inf"}`:  3,
	}
	for prefix, want := range expectations {
		line := prefix + " " + strconv.Itoa(want)
		if !strings.Contains(body, line) {
			t.Errorf("missing or wrong-count bucket line %q\nbody:\n%s", line, body)
		}
	}
	// count = 3, sum = 0.005 + 0.030 + 60 = 60.035
	if !strings.Contains(body, "wtp_send_latency_seconds_count 3") {
		t.Errorf("expected wtp_send_latency_seconds_count 3\nbody:\n%s", body)
	}
}

func TestWTPMetrics_ReconnectReasonValidationAndEscape(t *testing.T) {
	c := New()
	w := c.WTP()

	// Valid reasons render exactly as-named.
	w.IncReconnects(WTPReconnectReasonDialFailed)
	w.IncReconnects(WTPReconnectReasonStreamRecvError)
	w.IncReconnects(WTPReconnectReasonStreamRecvError)
	// Invalid (unknown enum) collapses to WTPReconnectReasonUnknown — proves the
	// cardinality cap. We intentionally bypass the typed enum here by casting
	// a raw string to confirm the validator catches it.
	w.IncReconnects(WTPReconnectReason("evil\"label\\value"))

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	// Valid reasons land on their own labels.
	for _, want := range []string{
		`wtp_reconnects_total{reason="dial_failed"} 1`,
		`wtp_reconnects_total{reason="stream_recv_error"} 2`,
		`wtp_reconnects_total{reason="unknown"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing line %q\nbody:\n%s", want, body)
		}
	}
	// The raw escaped string must NOT appear as a label — validator forbids it.
	if strings.Contains(body, `evil`) {
		t.Errorf("invalid reason leaked through validator into output:\n%s", body)
	}
}

func TestWTPMetrics_WALCorruptionCounter(t *testing.T) {
	c := New()
	w := c.WTP()

	// Initial scrape: counter must be present at zero.
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_wal_corruption_total 0") {
		t.Errorf("expected zero-valued wtp_wal_corruption_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	// After increments, the value must reflect the sum.
	w.IncWALCorruption(1)
	w.IncWALCorruption(4)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_wal_corruption_total 5") {
		t.Errorf("expected wtp_wal_corruption_total 5 after increments\nbody:\n%s", rr.Body.String())
	}
}

func TestWTPMetrics_ReconnectsAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	// Note: no IncReconnects calls. Per spec the family must still be present
	// with zero-valued series for every enumerated reason.
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	expectedReasons := []string{
		"ack_timeout",
		"dial_failed",
		"heartbeat_timeout",
		"recv_unknown_frame",
		"send_error",
		"server_goaway",
		"server_update_unsupported",
		"stream_recv_error",
		"unknown",
	}
	for _, reason := range expectedReasons {
		want := fmt.Sprintf(`wtp_reconnects_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued reconnect series %q\nbody:\n%s", want, body)
		}
	}
	// After one increment, only that reason flips to 1; the others stay 0.
	c.WTP().IncReconnects(WTPReconnectReasonAckTimeout)
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_reconnects_total{reason="ack_timeout"} 1`) {
		t.Errorf("expected ack_timeout=1 after one IncReconnects\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_reconnects_total{reason="dial_failed"} 0`) {
		t.Errorf("expected other reasons to remain 0 after one increment\nbody:\n%s", body)
	}
}

// TestWTPMetrics_AnomalousAckAlwaysEmittedAllReasons mirrors the
// reconnects-always-emitted contract for the Task 22 anomaly counter:
// every canonical AckOutcomeAnomaly reason MUST appear in the
// Prometheus exposition with a zero value before any IncAnomalousAck
// call. After one increment the targeted label flips to 1; others
// stay 0. Out-of-band reasons (a future IncAnomalousAck call with a
// reason NOT in the canonical list) MUST also surface so an unknown
// sub-case is observable rather than silently dropped.
func TestWTPMetrics_AnomalousAckAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	expectedReasons := []string{
		"stale_generation",
		"unwritten_generation",
		"server_ack_exceeds_local_seq",
		"server_ack_exceeds_local_data",
		"wal_read_failure",
	}
	for _, reason := range expectedReasons {
		want := fmt.Sprintf(`wtp_anomalous_ack_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued anomalous_ack series %q\nbody:\n%s", want, body)
		}
	}

	// After one increment, only that reason flips to 1.
	c.WTP().IncAnomalousAck("stale_generation")
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_anomalous_ack_total{reason="stale_generation"} 1`) {
		t.Errorf("expected stale_generation=1 after one IncAnomalousAck\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_anomalous_ack_total{reason="unwritten_generation"} 0`) {
		t.Errorf("expected other reasons to remain 0\nbody:\n%s", body)
	}

	// Out-of-band reason: an IncAnomalousAck with a reason NOT in
	// the canonical list must still surface in the exposition so the
	// new sub-case is observable.
	c.WTP().IncAnomalousAck("future_unknown_reason")
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_anomalous_ack_total{reason="future_unknown_reason"} 1`) {
		t.Errorf("expected out-of-band reason to surface\nbody:\n%s", body)
	}
}

// --------------------------------------------------------------------
// Task 22a Step 1: failing tests for the new sink-failure counters.
// --------------------------------------------------------------------

func TestWTPMetrics_DroppedInvalidUTF8(t *testing.T) {
	c := New()
	w := c.WTP()

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_utf8_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_invalid_utf8_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedInvalidUTF8(2)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_utf8_total 2") {
		t.Errorf("expected wtp_dropped_invalid_utf8_total 2 after IncDroppedInvalidUTF8(2)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedInvalidUTF8(); got != 2 {
		t.Errorf("DroppedInvalidUTF8 accessor returned %d, want 2", got)
	}
}

func TestWTPMetrics_DroppedSequenceOverflow(t *testing.T) {
	c := New()
	w := c.WTP()

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_sequence_overflow_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_sequence_overflow_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedSequenceOverflow(3)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_sequence_overflow_total 3") {
		t.Errorf("expected wtp_dropped_sequence_overflow_total 3 after IncDroppedSequenceOverflow(3)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedSequenceOverflow(); got != 3 {
		t.Errorf("DroppedSequenceOverflow accessor returned %d, want 3", got)
	}
}

func TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	body := scrape(t, c)
	for _, want := range []string{
		`wtp_session_init_failures_total{reason="invalid_utf8"} 0`,
		`wtp_session_init_failures_total{reason="recv_failed"} 0`,
		`wtp_session_init_failures_total{reason="rejected"} 0`,
		`wtp_session_init_failures_total{reason="send_failed"} 0`,
		`wtp_session_init_failures_total{reason="unexpected_message"} 0`,
		`wtp_session_init_failures_total{reason="unknown"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing always-emit line %q\nbody:\n%s", want, body)
		}
	}
	c.WTP().IncSessionInitFailures(WTPSessionFailureReasonInvalidUTF8)
	body = scrape(t, c)
	if !strings.Contains(body, `wtp_session_init_failures_total{reason="invalid_utf8"} 1`) {
		t.Errorf("expected invalid_utf8=1 after one IncSessionInitFailures\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_session_init_failures_total{reason="unknown"} 0`) {
		t.Errorf("expected unknown to remain 0 after invalid_utf8 increment\nbody:\n%s", body)
	}
}

func TestWTPMetrics_SessionRotationFailuresAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	body := scrape(t, c)
	for _, want := range []string{
		`wtp_session_rotation_failures_total{reason="invalid_utf8"} 0`,
		`wtp_session_rotation_failures_total{reason="recv_failed"} 0`,
		`wtp_session_rotation_failures_total{reason="rejected"} 0`,
		`wtp_session_rotation_failures_total{reason="send_failed"} 0`,
		`wtp_session_rotation_failures_total{reason="unexpected_message"} 0`,
		`wtp_session_rotation_failures_total{reason="unknown"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing always-emit line %q\nbody:\n%s", want, body)
		}
	}
	c.WTP().IncSessionRotationFailures(WTPSessionFailureReasonInvalidUTF8)
	body = scrape(t, c)
	if !strings.Contains(body, `wtp_session_rotation_failures_total{reason="invalid_utf8"} 1`) {
		t.Errorf("expected invalid_utf8=1 after one IncSessionRotationFailures\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_session_rotation_failures_total{reason="unknown"} 0`) {
		t.Errorf("expected unknown to remain 0 after invalid_utf8 increment\nbody:\n%s", body)
	}
}

func TestWTPMetrics_SessionFailureReasonValidationAndEscape(t *testing.T) {
	c := New()
	w := c.WTP()

	w.IncSessionInitFailures(WTPSessionFailureReasonInvalidUTF8)
	w.IncSessionInitFailures(WTPSessionFailureReason("evil\"label\\value"))
	w.IncSessionRotationFailures(WTPSessionFailureReasonInvalidUTF8)
	w.IncSessionRotationFailures(WTPSessionFailureReason("evil\"label\\value"))

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	for _, want := range []string{
		`wtp_session_init_failures_total{reason="invalid_utf8"} 1`,
		`wtp_session_init_failures_total{reason="unknown"} 1`,
		`wtp_session_rotation_failures_total{reason="invalid_utf8"} 1`,
		`wtp_session_rotation_failures_total{reason="unknown"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing line %q\nbody:\n%s", want, body)
		}
	}
	if strings.Contains(body, `evil`) {
		t.Errorf("invalid reason leaked through validator into output:\n%s", body)
	}
}

func TestWTPMetrics_DroppedInvalidMapper(t *testing.T) {
	c := New()
	w := c.WTP()

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_mapper_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_invalid_mapper_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedInvalidMapper(1)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_mapper_total 1") {
		t.Errorf("expected wtp_dropped_invalid_mapper_total 1 after IncDroppedInvalidMapper(1)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedInvalidMapper(); got != 1 {
		t.Errorf("DroppedInvalidMapper accessor returned %d, want 1", got)
	}
}

func TestWTPMetrics_DroppedInvalidTimestamp(t *testing.T) {
	c := New()
	w := c.WTP()

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_timestamp_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_invalid_timestamp_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedInvalidTimestamp(2)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_invalid_timestamp_total 2") {
		t.Errorf("expected wtp_dropped_invalid_timestamp_total 2 after IncDroppedInvalidTimestamp(2)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedInvalidTimestamp(); got != 2 {
		t.Errorf("DroppedInvalidTimestamp accessor returned %d, want 2", got)
	}
}

func TestWTPMetrics_DroppedMapperFailure(t *testing.T) {
	c := New()
	w := c.WTP()

	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_mapper_failure_total 0") {
		t.Errorf("expected zero-valued wtp_dropped_mapper_failure_total in initial scrape\nbody:\n%s", rr.Body.String())
	}

	w.IncDroppedMapperFailure(4)

	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rr.Body.String(), "wtp_dropped_mapper_failure_total 4") {
		t.Errorf("expected wtp_dropped_mapper_failure_total 4 after IncDroppedMapperFailure(4)\nbody:\n%s", rr.Body.String())
	}
	if got := c.WTP().DroppedMapperFailure(); got != 4 {
		t.Errorf("DroppedMapperFailure accessor returned %d, want 4", got)
	}
}

func TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	expectedReasons := []string{
		"classifier_bypass",
		"decompress_error",
		"event_batch_body_unset",
		"event_batch_compression_mismatch",
		"event_batch_compression_unspecified",
		"goaway_code_unspecified",
		"payload_too_large",
		"session_init_algorithm_unspecified",
		"session_update_generation_invalid",
		"unknown",
	}
	for _, reason := range expectedReasons {
		want := fmt.Sprintf(`wtp_dropped_invalid_frame_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued series %q\nbody:\n%s", want, body)
		}
	}

	c.WTP().IncDroppedInvalidFrame(WTPInvalidFrameReasonEventBatchBodyUnset)
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_dropped_invalid_frame_total{reason="event_batch_body_unset"} 1`) {
		t.Errorf("expected event_batch_body_unset=1 after one IncDroppedInvalidFrame\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_dropped_invalid_frame_total{reason="unknown"} 0`) {
		t.Errorf("expected unknown to remain 0 after event_batch_body_unset increment\nbody:\n%s", body)
	}

	c.WTP().IncDroppedInvalidFrame(WTPInvalidFrameReason("evil\"label\\value"))
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_dropped_invalid_frame_total{reason="classifier_bypass"} 1`) {
		t.Errorf("expected classifier_bypass=1 after invalid-reason fallback\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_dropped_invalid_frame_total{reason="unknown"} 0`) {
		t.Errorf("expected unknown to remain 0 after invalid-reason fallback\nbody:\n%s", body)
	}
	if strings.Contains(body, `evil`) {
		t.Errorf("invalid reason leaked through validator into output:\n%s", body)
	}
}

func TestIncDroppedInvalidFrame_InvalidLabelLogsAndCollapses(t *testing.T) {
	ResetClassifierBypassLimiterForTest()
	t.Cleanup(ResetClassifierBypassLimiterForTest)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	c := New()
	const badRaw = "not-a-canonical-reason"
	c.WTP().IncDroppedInvalidFrame(WTPInvalidFrameReason(badRaw))

	if got := c.WTP().DroppedInvalidFrame(WTPInvalidFrameReasonClassifierBypass); got != 1 {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want 1", got)
	}
	if got := c.WTP().DroppedInvalidFrame(WTPInvalidFrameReasonUnknown); got != 0 {
		t.Errorf("DroppedInvalidFrame(unknown) = %d, want 0 (must NOT collapse to unknown)", got)
	}

	logOutput := buf.String()
	if want := "invalid invalid-frame reason label"; !strings.Contains(logOutput, want) {
		t.Errorf("expected WARN log message %q in captured log output\nlog:\n%s", want, logOutput)
	}
	if want := `"raw_reason":"` + badRaw + `"`; !strings.Contains(logOutput, want) {
		t.Errorf("expected raw_reason field %q in captured log output\nlog:\n%s", want, logOutput)
	}
	if want := `"reason":"classifier_bypass"`; !strings.Contains(logOutput, want) {
		t.Errorf("expected reason=classifier_bypass field in captured log output\nlog:\n%s", logOutput)
	}
	if got := strings.Count(strings.TrimRight(logOutput, "\n"), "\n") + 1; got != 1 {
		t.Errorf("expected exactly one WARN log entry, got %d\nlog:\n%s", got, logOutput)
	}
}

// --------------------------------------------------------------------
// Task 22a Step 4: metrics-internal parity assertions for the
// WTPInvalidFrameReason enum. These tests use package-private state
// (wtpInvalidFrameReasonsValid, validationReasonsShared,
// metricsOnlyReasons) to assert the four invariants the enum must
// hold. The cross-package parity test against wtpv1.AllValidationReasons
// is deferred to Task 22b.
// --------------------------------------------------------------------

func TestWTPInvalidFrameReason_ValidationReasonsAllValid(t *testing.T) {
	for _, r := range validationReasonsShared {
		if _, ok := wtpInvalidFrameReasonsValid[r]; !ok {
			t.Errorf("validationReasonsShared contains %q but wtpInvalidFrameReasonsValid does not", r)
		}
	}
}

func TestWTPInvalidFrameReason_MetricsOnlyReasonsAllValid(t *testing.T) {
	for _, r := range metricsOnlyReasons {
		if _, ok := wtpInvalidFrameReasonsValid[r]; !ok {
			t.Errorf("metricsOnlyReasons contains %q but wtpInvalidFrameReasonsValid does not", r)
		}
	}
}

func TestWTPInvalidFrameReason_ValidationAndMetricsOnlyDisjoint(t *testing.T) {
	validation := make(map[WTPInvalidFrameReason]struct{}, len(validationReasonsShared))
	for _, r := range validationReasonsShared {
		validation[r] = struct{}{}
	}
	for _, r := range metricsOnlyReasons {
		if _, ok := validation[r]; ok {
			t.Errorf("reason %q appears in BOTH validationReasonsShared and metricsOnlyReasons (must be disjoint)", r)
		}
	}
}

func TestWTPInvalidFrameReason_ValidationPlusMetricsOnlyCoversAllValid(t *testing.T) {
	covered := make(map[WTPInvalidFrameReason]struct{}, len(wtpInvalidFrameReasonsValid))
	for _, r := range validationReasonsShared {
		covered[r] = struct{}{}
	}
	for _, r := range metricsOnlyReasons {
		covered[r] = struct{}{}
	}
	for r := range wtpInvalidFrameReasonsValid {
		if _, ok := covered[r]; !ok {
			t.Errorf("wtpInvalidFrameReasonsValid contains %q but neither validationReasonsShared nor metricsOnlyReasons covers it", r)
		}
	}
}

func TestWTPMetrics_WALQuarantineAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	// Always-emit contract: every enumerated reason present at zero.
	expectedReasons := []string{
		"key_fingerprint_mismatch",
		"session_id_mismatch",
		"unknown_identity_mismatch",
	}
	for _, reason := range expectedReasons {
		want := fmt.Sprintf(`wtp_wal_quarantine_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued series %q\nbody:\n%s", want, body)
		}
	}

	// After one increment, only that reason flips to 1; the others stay 0.
	c.WTP().IncWALQuarantine(WTPWALQuarantineReasonSessionIDMismatch)
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_wal_quarantine_total{reason="session_id_mismatch"} 1`) {
		t.Errorf("expected session_id_mismatch=1 after one IncWALQuarantine\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_wal_quarantine_total{reason="key_fingerprint_mismatch"} 0`) {
		t.Errorf("expected key_fingerprint_mismatch to remain 0\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_wal_quarantine_total{reason="unknown_identity_mismatch"} 0`) {
		t.Errorf("expected unknown_identity_mismatch to remain 0\nbody:\n%s", body)
	}

	// Invalid (unknown enum) collapses to WTPWALQuarantineReasonUnknown.
	// Bypass the typed enum by casting a raw string.
	c.WTP().IncWALQuarantine(WTPWALQuarantineReason("evil\"label\\value"))
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	if !strings.Contains(body, `wtp_wal_quarantine_total{reason="unknown_identity_mismatch"} 1`) {
		t.Errorf("expected unknown_identity_mismatch=1 after invalid-label collapse\nbody:\n%s", body)
	}
	if strings.Contains(body, `evil`) {
		t.Errorf("invalid reason leaked through validator into output:\n%s", body)
	}
}

// TestWTPMetrics_ReconnectsAlwaysEmittedIncludesFailClosedControlFrameLabels
// is the Task 22c regression guard for the two new fail-closed-recv
// reason labels (server_update_unsupported, recv_unknown_frame).
// Mirrors the Task 3 always-emit pattern: zero-init at registration,
// then increment, then assert (a) the targeted labels flip to 1 AND
// (b) every other reason in the canonical set stays at 0 (cross-
// series mutation guard — without (b) a future bug that mis-keys an
// increment under another label would still pass the test).
//
// Tests the SCHEMA only; emitter call sites in transport land in
// Tasks 18/19, and structured WARN logging lands in Task 22d. Step 4
// of Task 22c (spec rewrite to "live operator surface") is gated on
// all three predecessor tasks landing.
func TestWTPMetrics_ReconnectsAlwaysEmittedIncludesFailClosedControlFrameLabels(t *testing.T) {
	c := New()
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()

	for _, reason := range []string{"server_update_unsupported", "recv_unknown_frame"} {
		want := fmt.Sprintf(`wtp_reconnects_total{reason=%q} 0`, reason)
		if !strings.Contains(body, want) {
			t.Errorf("missing zero-valued reconnect series %q (Task 22c always-emit)\nbody:\n%s", want, body)
		}
	}

	c.WTP().IncReconnects(WTPReconnectReasonServerUpdateUnsupported)
	c.WTP().IncReconnects(WTPReconnectReasonRecvUnknownFrame)
	rr = httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body = rr.Body.String()
	for _, want := range []string{
		`wtp_reconnects_total{reason="server_update_unsupported"} 1`,
		`wtp_reconnects_total{reason="recv_unknown_frame"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q after IncReconnects\nbody:\n%s", want, body)
		}
	}

	// Cross-series mutation guard: every OTHER reason must still
	// emit at zero. Without this assertion a regression that mis-
	// keyed the new-label increment under another label (e.g. a
	// switch fallthrough that bumped `unknown` instead of
	// `server_update_unsupported`) would still pass the increment
	// assertions above.
	//
	// The "other" set is derived from the canonical
	// wtpReconnectReasonsEmitOrder slice (this test file lives in
	// `package metrics`, so the unexported slice is in scope) so a
	// future reconnect-reason addition automatically extends the
	// guard — without this, a hardcoded list would silently miss
	// the new reason.
	targeted := map[WTPReconnectReason]struct{}{
		WTPReconnectReasonServerUpdateUnsupported: {},
		WTPReconnectReasonRecvUnknownFrame:        {},
	}
	for _, reason := range wtpReconnectReasonsEmitOrder {
		if _, ok := targeted[reason]; ok {
			continue
		}
		want := fmt.Sprintf(`wtp_reconnects_total{reason=%q} 0`, string(reason))
		if !strings.Contains(body, want) {
			t.Errorf("expected non-targeted reason %q to remain at 0; cross-series mutation suspected\nbody:\n%s", reason, body)
		}
	}
}

// --------------------------------------------------------------------
// Task 4 (batch-compression plan): metrics surface for compression.
// --------------------------------------------------------------------

func TestWTPMetrics_BatchCompressionRatio(t *testing.T) {
	c := New()
	w := c.WTP()
	w.ObserveBatchCompressionRatio("zstd", 0.25)
	w.ObserveBatchCompressionRatio("zstd", 0.40)
	w.ObserveBatchCompressionRatio("gzip", 0.55)

	body := scrape(t, c)
	for _, want := range []string{
		`wtp_batch_compression_ratio_count{algo="zstd"} 2`,
		`wtp_batch_compression_ratio_count{algo="gzip"} 1`,
		`wtp_batch_compression_ratio_bucket{algo="zstd",le="0.5"} 2`, // both 0.25 and 0.40 land here
		`wtp_batch_compression_ratio_bucket{algo="gzip",le="0.5"} 0`, // 0.55 is above 0.5
		`wtp_batch_compression_ratio_bucket{algo="gzip",le="0.75"} 1`,
		`wtp_batch_compression_ratio_bucket{algo="zstd",le="+Inf"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing line %q\nbody:\n%s", want, body)
		}
	}
}

func TestWTPMetrics_BatchCompressionRatio_AlwaysEmitsBothAlgos(t *testing.T) {
	c := New()
	body := scrape(t, c)
	// Without any Observe calls, both algos must still appear at zero in
	// the canonical bucket set, count, and sum.
	for _, want := range []string{
		`wtp_batch_compression_ratio_count{algo="zstd"} 0`,
		`wtp_batch_compression_ratio_count{algo="gzip"} 0`,
		`wtp_batch_compression_ratio_sum{algo="zstd"} 0`,
		`wtp_batch_compression_ratio_sum{algo="gzip"} 0`,
		`wtp_batch_compression_ratio_bucket{algo="zstd",le="+Inf"} 0`,
		`wtp_batch_compression_ratio_bucket{algo="gzip",le="+Inf"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing always-emit line %q\nbody:\n%s", want, body)
		}
	}
}

func TestWTPMetrics_BatchByteCounters(t *testing.T) {
	c := New()
	w := c.WTP()
	w.AddBatchUncompressedBytes("zstd", 10000)
	w.AddBatchCompressedBytes("zstd", 2500)

	body := scrape(t, c)
	for _, want := range []string{
		`wtp_batch_uncompressed_bytes_total{algo="zstd"} 10000`,
		`wtp_batch_compressed_bytes_total{algo="zstd"} 2500`,
		// Always-emit for the other algo at zero.
		`wtp_batch_uncompressed_bytes_total{algo="gzip"} 0`,
		`wtp_batch_compressed_bytes_total{algo="gzip"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing line %q\nbody:\n%s", want, body)
		}
	}
}

func TestWTPMetrics_CompressErrorAlwaysEmittedAllAlgos(t *testing.T) {
	c := New()
	body := scrape(t, c)
	for _, want := range []string{
		`wtp_compress_error_total{algo="zstd"} 0`,
		`wtp_compress_error_total{algo="gzip"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing initial-zero line %q\nbody:\n%s", want, body)
		}
	}
	c.WTP().IncCompressError("zstd")
	body = scrape(t, c)
	if !strings.Contains(body, `wtp_compress_error_total{algo="zstd"} 1`) {
		t.Errorf("missing post-inc line\nbody:\n%s", body)
	}
	if !strings.Contains(body, `wtp_compress_error_total{algo="gzip"} 0`) {
		t.Errorf("gzip should still be zero\nbody:\n%s", body)
	}
}

func TestWTPMetrics_DecompressErrorAlwaysEmittedAllAlgosAndReasons(t *testing.T) {
	c := New()
	body := scrape(t, c)
	for _, algo := range []string{"zstd", "gzip"} {
		for _, reason := range []string{"decode_error", "oversize", "proto_unmarshal"} {
			want := fmt.Sprintf(`wtp_decompress_error_total{algo=%q,reason=%q} 0`, algo, reason)
			if !strings.Contains(body, want) {
				t.Errorf("missing always-emit line %q\nbody:\n%s", want, body)
			}
		}
	}
	c.WTP().IncDecompressError("zstd", "oversize")
	body = scrape(t, c)
	if !strings.Contains(body, `wtp_decompress_error_total{algo="zstd",reason="oversize"} 1`) {
		t.Errorf("missing post-inc line\nbody:\n%s", body)
	}
}

// scrape renders the Prometheus exposition for the Collector and returns
// it as a string. Used by Task 4 compression-metrics tests.
func scrape(t *testing.T, c *Collector) string {
	t.Helper()
	rr := httptest.NewRecorder()
	c.Handler(HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	return rr.Body.String()
}

func TestWTPMetrics_SessionInitFailures_PerReasonInc(t *testing.T) {
	c := New()
	w := c.WTP()

	// Each of the 6 reasons gets a distinct increment count so a
	// mismatched-label bug surfaces as a cross-counts mismatch.
	for i := 0; i < 1; i++ {
		w.IncSessionInitFailures(WTPSessionFailureReasonInvalidUTF8)
	}
	for i := 0; i < 2; i++ {
		w.IncSessionInitFailures(WTPSessionFailureReasonSendFailed)
	}
	for i := 0; i < 3; i++ {
		w.IncSessionInitFailures(WTPSessionFailureReasonRecvFailed)
	}
	for i := 0; i < 4; i++ {
		w.IncSessionInitFailures(WTPSessionFailureReasonUnexpectedMessage)
	}
	for i := 0; i < 5; i++ {
		w.IncSessionInitFailures(WTPSessionFailureReasonRejected)
	}
	for i := 0; i < 6; i++ {
		w.IncSessionInitFailures(WTPSessionFailureReasonUnknown)
	}

	body := scrape(t, c)
	for _, want := range []string{
		`wtp_session_init_failures_total{reason="invalid_utf8"} 1`,
		`wtp_session_init_failures_total{reason="recv_failed"} 3`,
		`wtp_session_init_failures_total{reason="rejected"} 5`,
		`wtp_session_init_failures_total{reason="send_failed"} 2`,
		`wtp_session_init_failures_total{reason="unexpected_message"} 4`,
		`wtp_session_init_failures_total{reason="unknown"} 6`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing line %q\nbody:\n%s", want, body)
		}
	}
}
