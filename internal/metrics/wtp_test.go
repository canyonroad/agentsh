package metrics

import (
	"fmt"
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
	w.IncDroppedMissingChain(1)
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
		"wtp_dropped_missing_chain_total 1",
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
		"send_error",
		"server_goaway",
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
