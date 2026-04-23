package metrics

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// WTPSessionState mirrors the four-state transport machine.
type WTPSessionState int

const (
	WTPStateConnecting WTPSessionState = 0
	WTPStateReplaying  WTPSessionState = 1
	WTPStateLive       WTPSessionState = 2
	WTPStateShutdown   WTPSessionState = 3
)

// WTPReconnectReason is a fixed, low-cardinality classification of why
// the WTP transport reconnected. Adding new reasons requires updating
// both the spec §Metrics section and the wtpReconnectReasonsValid table
// below.
type WTPReconnectReason string

const (
	WTPReconnectReasonDialFailed       WTPReconnectReason = "dial_failed"
	WTPReconnectReasonStreamRecvError  WTPReconnectReason = "stream_recv_error"
	WTPReconnectReasonSendError        WTPReconnectReason = "send_error"
	WTPReconnectReasonAckTimeout       WTPReconnectReason = "ack_timeout"
	WTPReconnectReasonHeartbeatTimeout WTPReconnectReason = "heartbeat_timeout"
	WTPReconnectReasonServerGoaway     WTPReconnectReason = "server_goaway"
	WTPReconnectReasonUnknown          WTPReconnectReason = "unknown"
)

var wtpReconnectReasonsValid = map[WTPReconnectReason]struct{}{
	WTPReconnectReasonDialFailed:       {},
	WTPReconnectReasonStreamRecvError:  {},
	WTPReconnectReasonSendError:        {},
	WTPReconnectReasonAckTimeout:       {},
	WTPReconnectReasonHeartbeatTimeout: {},
	WTPReconnectReasonServerGoaway:     {},
	WTPReconnectReasonUnknown:          {},
}

// wtpReconnectReasonsEmitOrder is the canonical, sorted-by-string emission
// order for the wtp_reconnects_total family. Using a fixed slice keeps
// Prometheus exposition deterministic and lets emitWTPMetrics emit
// zero-valued series for reasons that have not yet fired (per the
// always-emit contract in the design spec).
var wtpReconnectReasonsEmitOrder = []WTPReconnectReason{
	WTPReconnectReasonAckTimeout,
	WTPReconnectReasonDialFailed,
	WTPReconnectReasonHeartbeatTimeout,
	WTPReconnectReasonSendError,
	WTPReconnectReasonServerGoaway,
	WTPReconnectReasonStreamRecvError,
	WTPReconnectReasonUnknown,
}

// WTPMetrics is the per-Collector facade for wtp_* series. Returned by
// (*Collector).WTP(). Methods are nil-safe so test code and disabled-sink
// paths don't need to special-case it.
type WTPMetrics struct {
	c *Collector
}

func (c *Collector) WTP() *WTPMetrics { return &WTPMetrics{c: c} }

func (w *WTPMetrics) IncEventsAppended(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpEventsAppended.Add(n)
}

func (w *WTPMetrics) IncEventsAcked(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpEventsAcked.Add(n)
}

func (w *WTPMetrics) IncBatchesSent(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpBatchesSent.Add(n)
}

func (w *WTPMetrics) AddBytesSent(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpBytesSent.Add(n)
}

func (w *WTPMetrics) IncTransportLoss(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpTransportLoss.Add(n)
}

func (w *WTPMetrics) IncReconnects(reason WTPReconnectReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpReconnectReasonsValid[reason]; !ok {
		reason = WTPReconnectReasonUnknown
	}
	ptr, _ := w.c.wtpReconnectsByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

func (w *WTPMetrics) SetSessionState(state WTPSessionState) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpSessionState.Store(int64(state))
}

func (w *WTPMetrics) SetWALSegments(n int64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpWALSegments.Store(n)
}

func (w *WTPMetrics) SetWALBytes(n int64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpWALBytes.Store(n)
}

func (w *WTPMetrics) SetAckHighWatermark(seq int64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpAckHighWatermark.Store(seq)
}

func (w *WTPMetrics) IncDroppedMissingChain(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedMissingChain.Add(n)
}

func (w *WTPMetrics) IncWALCorruption(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpWALCorruption.Add(n)
}

// wtpAnomalousAckReasons is the canonical, ordered list of the five
// disjoint AckOutcomeAnomaly reasons per the Transport's
// applyServerAckTuple helper. Listed explicitly so the Prometheus
// emit is stable (sorted by enum order, not map iteration order) AND
// so every reason emits at zero on registration — operators can
// distinguish "no anomalies yet" from "metric absent after restart".
//
// MUST stay in sync with the AnomalyReason constants surfaced by
// applyServerAckTuple. Adding a sub-case there means appending the
// label here.
var wtpAnomalousAckReasons = []string{
	"stale_generation",
	"unwritten_generation",
	"server_ack_exceeds_local_seq",
	"server_ack_exceeds_local_data",
	"wal_read_failure",
}

// IncAnomalousAck increments the per-reason counter for a server ack
// tuple that landed in one of the five disjoint AckOutcomeAnomaly
// sub-cases. Reasons are short snake_case strings — see
// wtpAnomalousAckReasons for the canonical list. An unknown reason
// is recorded under the literal label so observability does not
// silently drop a new sub-case before the registry catches up.
// Nil-safe.
func (w *WTPMetrics) IncAnomalousAck(reason string) {
	if w == nil || w.c == nil {
		return
	}
	ptr, _ := w.c.wtpAnomalousAckByReason.LoadOrStore(reason, &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// IncResendNeeded increments the counter for legitimate stale-server
// recovery: server's ack tuple lex-precedes persistedAck, only
// remoteReplayCursor regressed (no MarkAcked call). Nil-safe.
func (w *WTPMetrics) IncResendNeeded() {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpResendNeeded.Add(1)
}

// IncAckRegressionLoss increments the counter for synthesized in-
// memory loss markers produced when computeReplayStart's case A or C
// observed an ack_regression_after_gc gap. Nil-safe.
func (w *WTPMetrics) IncAckRegressionLoss() {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpAckRegressionLoss.Add(1)
}

// Latency histogram buckets, in seconds. Chosen to cover sub-millisecond
// localhost (testserver) through pathological 30s reconnect-edge sends.
var wtpLatencyBucketsSeconds = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

func (w *WTPMetrics) ObserveSendLatency(d time.Duration) {
	if w == nil || w.c == nil {
		return
	}
	secs := d.Seconds()
	w.c.wtpLatencyMu.Lock()
	defer w.c.wtpLatencyMu.Unlock()
	w.c.wtpLatencyCount++
	w.c.wtpLatencySum += secs
	for i, ub := range wtpLatencyBucketsSeconds {
		if secs <= ub {
			w.c.wtpLatencyBuckets[i]++
		}
	}
	w.c.wtpLatencyBuckets[len(wtpLatencyBucketsSeconds)]++ // +Inf bucket
}

// emitWTPMetrics writes the wtp_* series in Prometheus text format.
// Called from Collector.Handler. Kept private here so wtp.go owns the
// formatting and metrics.go owns the dispatch.
func (c *Collector) emitWTPMetrics(w io.Writer) {
	fmt.Fprint(w, "# HELP wtp_events_appended_total Events appended to the WTP sink.\n")
	fmt.Fprint(w, "# TYPE wtp_events_appended_total counter\n")
	fmt.Fprintf(w, "wtp_events_appended_total %d\n", c.wtpEventsAppended.Load())

	fmt.Fprint(w, "# HELP wtp_events_acked_total Events acknowledged by the WTP server.\n")
	fmt.Fprint(w, "# TYPE wtp_events_acked_total counter\n")
	fmt.Fprintf(w, "wtp_events_acked_total %d\n", c.wtpEventsAcked.Load())

	fmt.Fprint(w, "# HELP wtp_batches_sent_total Batches sent to the WTP server.\n")
	fmt.Fprint(w, "# TYPE wtp_batches_sent_total counter\n")
	fmt.Fprintf(w, "wtp_batches_sent_total %d\n", c.wtpBatchesSent.Load())

	fmt.Fprint(w, "# HELP wtp_bytes_sent_total Bytes sent to the WTP server (post-compression).\n")
	fmt.Fprint(w, "# TYPE wtp_bytes_sent_total counter\n")
	fmt.Fprintf(w, "wtp_bytes_sent_total %d\n", c.wtpBytesSent.Load())

	fmt.Fprint(w, "# HELP wtp_transport_loss_total Transport-loss markers emitted by the WTP sink.\n")
	fmt.Fprint(w, "# TYPE wtp_transport_loss_total counter\n")
	fmt.Fprintf(w, "wtp_transport_loss_total %d\n", c.wtpTransportLoss.Load())

	// Always emit the wtp_reconnects_total family with all enumerated reasons
	// so dashboards have a stable schema regardless of runtime activity (per
	// the always-emit contract in the design spec).
	fmt.Fprint(w, "# HELP wtp_reconnects_total WTP transport reconnects by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_reconnects_total counter\n")
	for _, r := range wtpReconnectReasonsEmitOrder {
		var n uint64
		if v, ok := c.wtpReconnectsByReason.Load(string(r)); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_reconnects_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
	}

	fmt.Fprint(w, "# HELP wtp_session_state Current WTP session state (0=connecting,1=replaying,2=live,3=shutdown).\n")
	fmt.Fprint(w, "# TYPE wtp_session_state gauge\n")
	fmt.Fprintf(w, "wtp_session_state %d\n", c.wtpSessionState.Load())

	fmt.Fprint(w, "# HELP wtp_wal_segments Number of WAL segment files on disk.\n")
	fmt.Fprint(w, "# TYPE wtp_wal_segments gauge\n")
	fmt.Fprintf(w, "wtp_wal_segments %d\n", c.wtpWALSegments.Load())

	fmt.Fprint(w, "# HELP wtp_wal_bytes Total bytes used by WAL on disk.\n")
	fmt.Fprint(w, "# TYPE wtp_wal_bytes gauge\n")
	fmt.Fprintf(w, "wtp_wal_bytes %d\n", c.wtpWALBytes.Load())

	fmt.Fprint(w, "# HELP wtp_ack_high_watermark Highest acked sequence from the WTP server.\n")
	fmt.Fprint(w, "# TYPE wtp_ack_high_watermark gauge\n")
	fmt.Fprintf(w, "wtp_ack_high_watermark %d\n", c.wtpAckHighWatermark.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_missing_chain_total Events dropped because ev.Chain was nil.\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_missing_chain_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_missing_chain_total %d\n", c.wtpDroppedMissingChain.Load())

	fmt.Fprint(w, "# HELP wtp_wal_corruption_total CRC corruption events encountered during WAL replay.\n")
	fmt.Fprint(w, "# TYPE wtp_wal_corruption_total counter\n")
	fmt.Fprintf(w, "wtp_wal_corruption_total %d\n", c.wtpWALCorruption.Load())

	// Cursor-feedback counters introduced with the Store integration
	// (Task 22). Anomalous-ack is per-reason; resend-needed and
	// ack-regression-loss are scalar. The anomalous-ack series is
	// emitted in canonical-reason order with zeroes for never-fired
	// reasons so "no anomalies yet" is distinguishable from "metric
	// absent after restart" and so the exposition order is stable
	// across scrapes.
	fmt.Fprint(w, "# HELP wtp_anomalous_ack_total Server ack tuples that fell into one of the AckOutcomeAnomaly sub-cases, by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_anomalous_ack_total counter\n")
	for _, reason := range wtpAnomalousAckReasons {
		var n uint64
		if v, ok := c.wtpAnomalousAckByReason.Load(reason); ok {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_anomalous_ack_total{reason=%q} %d\n", reason, n)
	}
	// Surface any reasons NOT in the canonical list as well, so an
	// out-of-band IncAnomalousAck("new_reason") is still observable.
	c.wtpAnomalousAckByReason.Range(func(k, v any) bool {
		reason := k.(string)
		for _, known := range wtpAnomalousAckReasons {
			if reason == known {
				return true
			}
		}
		fmt.Fprintf(w, "wtp_anomalous_ack_total{reason=%q} %d\n", reason, v.(*atomic.Uint64).Load())
		return true
	})

	fmt.Fprint(w, "# HELP wtp_resend_needed_total Server ack tuples that landed in the ResendNeeded branch (legitimate stale-server recovery).\n")
	fmt.Fprint(w, "# TYPE wtp_resend_needed_total counter\n")
	fmt.Fprintf(w, "wtp_resend_needed_total %d\n", c.wtpResendNeeded.Load())

	fmt.Fprint(w, "# HELP wtp_ack_regression_loss_total Synthesized in-memory loss markers from computeReplayStart Case A or C.\n")
	fmt.Fprint(w, "# TYPE wtp_ack_regression_loss_total counter\n")
	fmt.Fprintf(w, "wtp_ack_regression_loss_total %d\n", c.wtpAckRegressionLoss.Load())

	// Snapshot under lock to avoid blocking ObserveSendLatency callers
	// during a slow scrape.
	c.wtpLatencyMu.Lock()
	bucketsSnapshot := c.wtpLatencyBuckets
	sumSnapshot := c.wtpLatencySum
	countSnapshot := c.wtpLatencyCount
	c.wtpLatencyMu.Unlock()

	fmt.Fprint(w, "# HELP wtp_send_latency_seconds Latency of WTP batch sends.\n")
	fmt.Fprint(w, "# TYPE wtp_send_latency_seconds histogram\n")
	for i, ub := range wtpLatencyBucketsSeconds {
		fmt.Fprintf(w, "wtp_send_latency_seconds_bucket{le=\"%g\"} %d\n", ub, bucketsSnapshot[i])
	}
	fmt.Fprintf(w, "wtp_send_latency_seconds_bucket{le=\"+Inf\"} %d\n", bucketsSnapshot[len(wtpLatencyBucketsSeconds)])
	fmt.Fprintf(w, "wtp_send_latency_seconds_sum %g\n", sumSnapshot)
	fmt.Fprintf(w, "wtp_send_latency_seconds_count %d\n", countSnapshot)
}
