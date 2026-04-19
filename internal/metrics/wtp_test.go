package metrics

import (
	"net/http/httptest"
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
	w.IncReconnects("dial_failed")
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
