package metrics

import (
	"fmt"
	"io"
	"log/slog"
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
	// WTPReconnectReasonServerUpdateUnsupported and
	// WTPReconnectReasonRecvUnknownFrame are the Task 22c dedicated
	// labels for the fail-closed recv branches that previously
	// would have collapsed onto WTPReconnectReasonUnknown. The
	// labels exist at zero from the moment Task 22c lands; emitter
	// call sites land in Tasks 18/19 (recv-multiplexer fail-closed
	// paths) and the structured WARN logging lands in Task 22d.
	//
	// BACKWARDS-COMPATIBILITY for the `unknown` label. Because no
	// non-test IncReconnects call site exists today for either of
	// these branches (verified at commit 0b28f74e), there is no
	// production traffic to "shift" — the labels move from
	// non-existent to live in a single transition once Tasks 18/19
	// land. The `unknown` label is RESERVED for truly unmapped
	// reconnect causes after this task; if a future fail-closed
	// branch is added without a dedicated label it should be
	// treated as a bug, not as expected unknown-bucket growth.
	//
	// MONITORING-ARTIFACT PREREQUISITE for the Tasks 18/19 emitter
	// wiring. Operator-facing dashboards/alerts that filter on
	// wtp_reconnects_total{reason=~...} will see TWO new series flip
	// from zero to non-zero the moment the emitter call sites land.
	// Per Task 22c Step 5 the operator team must update those
	// artifacts BEFORE Tasks 18/19 ship — without that update,
	// alerts keyed on a `reason=~"unknown"`-only filter would
	// undercount the new branches and dashboards would silently miss
	// them. The gate is enforced procedurally:
	//
	//   - The authoritative monitoring inventory + named-owner
	//     sign-off lives in
	//     `docs/superpowers/operator/wtp-monitoring-migration.md`,
	//     which is CREATED OR UPDATED by Task 27a Step 1a (the file
	//     does not yet exist in this tree at the time Task 22c
	//     ships — Task 27a creates it).
	//   - Task 18 and Task 19 each carry an explicit "Prerequisite
	//     (rollout-order gate)" line in the implementation plan
	//     naming this dependency. The gate is doc-enforced (plan
	//     execution) NOT runtime-enforced (no CI/build check), so
	//     implementers of Tasks 18/19 are responsible for verifying
	//     Step 5 sign-off before landing emitter wiring.
	//
	// If Task 27a's monitoring-migration artifact has not yet
	// landed when Tasks 18/19 are scheduled, treat that as the gate
	// being unsatisfied: either land the artifact first (pulled
	// forward from Task 27a) or block the emitter wiring.
	WTPReconnectReasonServerUpdateUnsupported WTPReconnectReason = "server_update_unsupported"
	WTPReconnectReasonRecvUnknownFrame        WTPReconnectReason = "recv_unknown_frame"
	WTPReconnectReasonUnknown                 WTPReconnectReason = "unknown"
)

var wtpReconnectReasonsValid = map[WTPReconnectReason]struct{}{
	WTPReconnectReasonDialFailed:              {},
	WTPReconnectReasonStreamRecvError:         {},
	WTPReconnectReasonSendError:               {},
	WTPReconnectReasonAckTimeout:              {},
	WTPReconnectReasonHeartbeatTimeout:        {},
	WTPReconnectReasonServerGoaway:            {},
	WTPReconnectReasonServerUpdateUnsupported: {},
	WTPReconnectReasonRecvUnknownFrame:        {},
	WTPReconnectReasonUnknown:                 {},
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
	WTPReconnectReasonRecvUnknownFrame,
	WTPReconnectReasonSendError,
	WTPReconnectReasonServerGoaway,
	WTPReconnectReasonServerUpdateUnsupported,
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

	// Task 22a: sink-failure unlabeled counters.
	fmt.Fprint(w, "# HELP wtp_dropped_invalid_utf8_total Records dropped because the canonical encoder reported invalid UTF-8.\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_invalid_utf8_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_invalid_utf8_total %d\n", c.wtpDroppedInvalidUTF8.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_sequence_overflow_total Records dropped because Chain.Sequence exceeded math.MaxInt64.\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_sequence_overflow_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_sequence_overflow_total %d\n", c.wtpDroppedSequenceOverflow.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_invalid_mapper_total Records dropped because compact.Encode rejected the mapper (defense in depth).\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_invalid_mapper_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_invalid_mapper_total %d\n", c.wtpDroppedInvalidMapper.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_invalid_timestamp_total Records dropped because compact.Encode rejected ev.Timestamp (zero or pre-epoch).\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_invalid_timestamp_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_invalid_timestamp_total %d\n", c.wtpDroppedInvalidTimestamp.Load())

	fmt.Fprint(w, "# HELP wtp_dropped_mapper_failure_total Records dropped because compact.Encode wrapped a mapper-side error.\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_mapper_failure_total counter\n")
	fmt.Fprintf(w, "wtp_dropped_mapper_failure_total %d\n", c.wtpDroppedMapperFailure.Load())

	fmt.Fprint(w, "# HELP wtp_loss_unknown_reason_total Loss markers dropped because the in-WAL Reason string had no wire enum mapping. Non-zero indicates a producer added a new reason without updating ToWireReason — programming bug.\n")
	fmt.Fprint(w, "# TYPE wtp_loss_unknown_reason_total counter\n")
	fmt.Fprintf(w, "wtp_loss_unknown_reason_total %d\n", c.wtpLossUnknownReason.Load())

	// Task 22a: labeled families. Always-emit contract — every
	// enumerated reason appears in the exposition with a (possibly
	// zero) value on every scrape, so dashboards never see "no data"
	// vs. "zero events" ambiguity.
	fmt.Fprint(w, "# HELP wtp_dropped_invalid_frame_total WTP peer frames dropped at the protocol-validation boundary, by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_dropped_invalid_frame_total counter\n")
	for _, r := range wtpInvalidFrameReasonsEmitOrder {
		var n uint64
		if v, ok := c.wtpDroppedInvalidFrameByReason.Load(string(r)); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_dropped_invalid_frame_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
	}

	fmt.Fprint(w, "# HELP wtp_session_init_failures_total WTP session-init failures by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_session_init_failures_total counter\n")
	for _, r := range wtpSessionFailureReasonsEmitOrder {
		var n uint64
		if v, ok := c.wtpSessionInitFailuresByReason.Load(string(r)); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_session_init_failures_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
	}

	fmt.Fprint(w, "# HELP wtp_session_rotation_failures_total WTP session-rotation failures by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_session_rotation_failures_total counter\n")
	for _, r := range wtpSessionFailureReasonsEmitOrder {
		var n uint64
		if v, ok := c.wtpSessionRotationFailuresByReason.Load(string(r)); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_session_rotation_failures_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
	}

	fmt.Fprint(w, "# HELP wtp_wal_quarantine_total WTP WAL identity-mismatch quarantines by reason.\n")
	fmt.Fprint(w, "# TYPE wtp_wal_quarantine_total counter\n")
	for _, r := range wtpWALQuarantineReasonsEmitOrder {
		var n uint64
		if v, ok := c.wtpWALQuarantineByReason.Load(string(r)); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_wal_quarantine_total{reason=%q} %d\n", escapeLabelValue(string(r)), n)
	}

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

	// Task 4: batch-compression metrics. Five families, all with `algo`
	// labels. Always-emit cross product so dashboards have a stable
	// schema before any compression happens.

	fmt.Fprint(w, "# HELP wtp_batch_compression_ratio Compressed/uncompressed size ratio per WTP batch.\n")
	fmt.Fprint(w, "# TYPE wtp_batch_compression_ratio histogram\n")
	for _, algo := range wtpCompressionAlgos {
		var h *compressionRatioBuckets
		switch algo {
		case "zstd":
			h = &c.wtpBatchCompressionRatioZstd
		case "gzip":
			h = &c.wtpBatchCompressionRatioGzip
		}
		h.mu.Lock()
		bs := h.buckets
		sum := h.sum
		count := h.count
		h.mu.Unlock()
		for i, ub := range wtpCompressionRatioBucketsValues {
			fmt.Fprintf(w, "wtp_batch_compression_ratio_bucket{algo=%q,le=\"%g\"} %d\n", algo, ub, bs[i])
		}
		fmt.Fprintf(w, "wtp_batch_compression_ratio_bucket{algo=%q,le=\"+Inf\"} %d\n", algo, bs[len(wtpCompressionRatioBucketsValues)])
		fmt.Fprintf(w, "wtp_batch_compression_ratio_sum{algo=%q} %g\n", algo, sum)
		fmt.Fprintf(w, "wtp_batch_compression_ratio_count{algo=%q} %d\n", algo, count)
	}

	fmt.Fprint(w, "# HELP wtp_batch_compressed_bytes_total Bytes emitted as EventBatch.compressed_payload, by algorithm.\n")
	fmt.Fprint(w, "# TYPE wtp_batch_compressed_bytes_total counter\n")
	for _, algo := range wtpCompressionAlgos {
		var n uint64
		if v, ok := c.wtpBatchCompressedBytesByAlgo.Load(algo); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_batch_compressed_bytes_total{algo=%q} %d\n", algo, n)
	}

	fmt.Fprint(w, "# HELP wtp_batch_uncompressed_bytes_total Marshaled UncompressedEvents size pre-compression, by algorithm.\n")
	fmt.Fprint(w, "# TYPE wtp_batch_uncompressed_bytes_total counter\n")
	for _, algo := range wtpCompressionAlgos {
		var n uint64
		if v, ok := c.wtpBatchUncompressedBytesByAlgo.Load(algo); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_batch_uncompressed_bytes_total{algo=%q} %d\n", algo, n)
	}

	fmt.Fprint(w, "# HELP wtp_compress_error_total Sender-side fail-open fallbacks: encoder returned an error and the batch was emitted as COMPRESSION_NONE.\n")
	fmt.Fprint(w, "# TYPE wtp_compress_error_total counter\n")
	for _, algo := range wtpCompressionAlgos {
		var n uint64
		if v, ok := c.wtpCompressErrorByAlgo.Load(algo); ok && v != nil {
			n = v.(*atomic.Uint64).Load()
		}
		fmt.Fprintf(w, "wtp_compress_error_total{algo=%q} %d\n", algo, n)
	}

	fmt.Fprint(w, "# HELP wtp_decompress_error_total Receiver-side decode failures by algorithm and reason.\n")
	fmt.Fprint(w, "# TYPE wtp_decompress_error_total counter\n")
	for _, algo := range wtpCompressionAlgos {
		for _, reason := range wtpDecompressReasons {
			var n uint64
			key := algo + "|" + reason
			if v, ok := c.wtpDecompressErrorByLabels.Load(key); ok && v != nil {
				n = v.(*atomic.Uint64).Load()
			}
			fmt.Fprintf(w, "wtp_decompress_error_total{algo=%q,reason=%q} %d\n", algo, reason, n)
		}
	}
}

// ----- Task 22a: sink-failure metrics --------------------------------
//
// SCOPE & ROLLOUT NOTE. This task lands the metric DEFINITIONS,
// exposition, and validation logic for nine new counter families.
// Wiring status SPLITS into two groups per the table below:
//
//	Counter family                              Wired by                                 Status (as of Task 22a R2)
//	wtp_dropped_invalid_utf8_total              AppendEvent (Task 23 follow-up)          WIRED — recordCanonicalFailure
//	wtp_dropped_sequence_overflow_total         AppendEvent (Task 23 follow-up)          WIRED — recordSequenceOverflow
//	wtp_dropped_invalid_mapper_total            AppendEvent (Task 23 follow-up)          WIRED — recordCompactEncodeFailure (defense-in-depth)
//	wtp_dropped_invalid_timestamp_total         AppendEvent (Task 23 follow-up)          WIRED — recordCompactEncodeFailure
//	wtp_dropped_mapper_failure_total            AppendEvent (Task 23 follow-up)          WIRED — recordCompactEncodeFailure (catch-all)
//	wtp_dropped_invalid_frame_total{reason}     transport receivers (Task 17 Step 4a)    NOT YET WIRED — emits zero
//	wtp_session_init_failures_total{reason}     transport (Phase 8)                      NOT YET WIRED — emits zero
//	wtp_session_rotation_failures_total{reason} transport (Phase 8)                      NOT YET WIRED — emits zero
//	wtp_wal_quarantine_total{reason}            store wal.Open recovery path             LIVE as of Task 22a R2
//	                                            (openWALWithIdentityRecovery,
//	                                            internal/store/watchtower/store.go)
//
// "Task 22a complete" therefore has TWO meanings depending on the
// counter:
//
//   - For wtp_wal_quarantine_total: the metric is fully live.
//     Operators MAY add alerts on the
//     {key_fingerprint_mismatch, session_id_mismatch} labels per the
//     spec §"Quarantine policy" + §"Operational signals" runbook
//     entries.
//   - For all other Task 22a counters: the series are stable and
//     visible at zero (always-emit contract); operators should NOT
//     alert on values until the listed wiring task ships. A
//     permanently-zero series under a still-NOT-YET-WIRED row above
//     is expected, not a healthy signal.
//
// MIGRATION NOTE. This task also REMOVES the legacy
// wtp_dropped_missing_chain_total counter (Task 3). Removal is
// safe-by-construction — the missing-chain class is now propagated
// from AppendEvent as a wrapped compact.ErrMissingChain rather than
// silently dropped, so the underlying event the counter tracked no
// longer exists. There is NO zero-emit deprecation window — the
// field, accessor, and emit lines are all deleted in this task. Per
// spec §"Migration guidance: removed wtp_dropped_missing_chain_total"
// and §"Rollout precondition," operator monitoring artifacts MUST be
// updated to drop or redirect references to that series BEFORE this
// code rolls to production. Implementers should not re-introduce the
// counter; see also the "Superseded by Task 22a Step 3.5" admonitions
// in the historical Task 3 plan body.

// WTPSessionFailureReason is a fixed, low-cardinality classification of
// why a session-init or session-rotation step failed. Adding new
// reasons requires updating both the spec §Metrics section and the
// wtpSessionFailureReasonsValid table below.
type WTPSessionFailureReason string

const (
	WTPSessionFailureReasonInvalidUTF8       WTPSessionFailureReason = "invalid_utf8"
	WTPSessionFailureReasonSendFailed        WTPSessionFailureReason = "send_failed"
	WTPSessionFailureReasonRecvFailed        WTPSessionFailureReason = "recv_failed"
	WTPSessionFailureReasonUnexpectedMessage WTPSessionFailureReason = "unexpected_message"
	WTPSessionFailureReasonRejected          WTPSessionFailureReason = "rejected"
	WTPSessionFailureReasonUnknown           WTPSessionFailureReason = "unknown"
)

var wtpSessionFailureReasonsValid = map[WTPSessionFailureReason]struct{}{
	WTPSessionFailureReasonInvalidUTF8:       {},
	WTPSessionFailureReasonSendFailed:        {},
	WTPSessionFailureReasonRecvFailed:        {},
	WTPSessionFailureReasonUnexpectedMessage: {},
	WTPSessionFailureReasonRejected:          {},
	WTPSessionFailureReasonUnknown:           {},
}

// wtpSessionFailureReasonsEmitOrder is the canonical sort-by-string
// emission order. Keeps Prometheus exposition deterministic and lets
// emitWTPMetrics emit zero-valued series for reasons that have not yet
// fired (always-emit contract).
var wtpSessionFailureReasonsEmitOrder = []WTPSessionFailureReason{
	WTPSessionFailureReasonInvalidUTF8,
	WTPSessionFailureReasonRecvFailed,
	WTPSessionFailureReasonRejected,
	WTPSessionFailureReasonSendFailed,
	WTPSessionFailureReasonUnexpectedMessage,
	WTPSessionFailureReasonUnknown,
}

// WTPInvalidFrameReason is a fixed, low-cardinality classification of
// why a peer frame was dropped at the protocol-validation boundary.
// The reason set splits into two disjoint categories:
//
//   - Validator-emitted (proto-side wtpv1.ValidationReason has byte-
//     equal constants — Task 17 Step 4 + Task 22b parity test).
//   - Metrics-only (no proto-side counterpart): WTPInvalidFrameReason
//     DecompressError (emitted downstream of the validator by
//     streaming decompression) and WTPInvalidFrameReasonClassifierBypass
//     (emitted by the receiver-side errors.As-false defense-in-depth
//     guard, OR by IncDroppedInvalidFrame's invalid-label collapse).
//
// IMPORTANT — `unknown` vs `classifier_bypass`: these are DISJOINT
// reasons with disjoint operator interpretations. `unknown` means the
// validator returned ReasonUnknown for a new oneof discriminator
// (peer-side schema drift). `classifier_bypass` means the receiver's
// errors.As returned false (local-side caller bug). Operators MUST
// NOT treat them as interchangeable.
type WTPInvalidFrameReason string

const (
	WTPInvalidFrameReasonEventBatchBodyUnset            WTPInvalidFrameReason = "event_batch_body_unset"
	WTPInvalidFrameReasonEventBatchCompressionUnspec    WTPInvalidFrameReason = "event_batch_compression_unspecified"
	WTPInvalidFrameReasonEventBatchCompressionMismatch  WTPInvalidFrameReason = "event_batch_compression_mismatch"
	WTPInvalidFrameReasonSessionInitAlgorithmUnspec     WTPInvalidFrameReason = "session_init_algorithm_unspecified"
	WTPInvalidFrameReasonPayloadTooLarge                WTPInvalidFrameReason = "payload_too_large"
	WTPInvalidFrameReasonDecompressError                WTPInvalidFrameReason = "decompress_error"
	WTPInvalidFrameReasonGoawayCodeUnspecified          WTPInvalidFrameReason = "goaway_code_unspecified"
	WTPInvalidFrameReasonSessionUpdateGenerationInvalid WTPInvalidFrameReason = "session_update_generation_invalid"
	// WTPInvalidFrameReasonClassifierBypass is the metrics-only reason
	// emitted by the receiver-side errors.As-false defense-in-depth
	// guard AND by IncDroppedInvalidFrame's invalid-label collapse.
	// Disjoint from WTPInvalidFrameReasonUnknown — see the type-doc
	// above.
	WTPInvalidFrameReasonClassifierBypass WTPInvalidFrameReason = "classifier_bypass"
	WTPInvalidFrameReasonUnknown          WTPInvalidFrameReason = "unknown"
)

var wtpInvalidFrameReasonsValid = map[WTPInvalidFrameReason]struct{}{
	WTPInvalidFrameReasonEventBatchBodyUnset:            {},
	WTPInvalidFrameReasonEventBatchCompressionUnspec:    {},
	WTPInvalidFrameReasonEventBatchCompressionMismatch:  {},
	WTPInvalidFrameReasonSessionInitAlgorithmUnspec:     {},
	WTPInvalidFrameReasonPayloadTooLarge:                {},
	WTPInvalidFrameReasonDecompressError:                {},
	WTPInvalidFrameReasonGoawayCodeUnspecified:          {},
	WTPInvalidFrameReasonSessionUpdateGenerationInvalid: {},
	WTPInvalidFrameReasonClassifierBypass:               {},
	WTPInvalidFrameReasonUnknown:                        {},
}

// wtpInvalidFrameReasonsEmitOrder mirrors the wtpSessionFailureReasonsEmitOrder
// pattern: a fixed slice keeps Prometheus exposition deterministic and
// lets emitWTPMetrics emit zero-valued series on every scrape. Order is
// alphabetical-by-string for stable output.
var wtpInvalidFrameReasonsEmitOrder = []WTPInvalidFrameReason{
	WTPInvalidFrameReasonClassifierBypass,
	WTPInvalidFrameReasonDecompressError,
	WTPInvalidFrameReasonEventBatchBodyUnset,
	WTPInvalidFrameReasonEventBatchCompressionMismatch,
	WTPInvalidFrameReasonEventBatchCompressionUnspec,
	WTPInvalidFrameReasonGoawayCodeUnspecified,
	WTPInvalidFrameReasonPayloadTooLarge,
	WTPInvalidFrameReasonSessionInitAlgorithmUnspec,
	WTPInvalidFrameReasonSessionUpdateGenerationInvalid,
	WTPInvalidFrameReasonUnknown,
}

// validationReasonsShared backs the ValidationReasons() getter. It is
// the SUBSET of WTPInvalidFrameReason values that are also returned by
// wtpv1.AllValidationReasons() — i.e. the validator-emitted reasons
// shared across the proto and metrics packages. Adding a new validator-
// shared reason MUST also append it to allValidationReasons in
// proto/canyonroad/wtp/v1/validate.go (Task 22b parity test catches
// drift).
var validationReasonsShared = []WTPInvalidFrameReason{
	WTPInvalidFrameReasonEventBatchBodyUnset,
	WTPInvalidFrameReasonEventBatchCompressionUnspec,
	WTPInvalidFrameReasonEventBatchCompressionMismatch,
	WTPInvalidFrameReasonSessionInitAlgorithmUnspec,
	WTPInvalidFrameReasonPayloadTooLarge,
	WTPInvalidFrameReasonGoawayCodeUnspecified,
	WTPInvalidFrameReasonSessionUpdateGenerationInvalid,
	WTPInvalidFrameReasonUnknown,
}

// metricsOnlyReasons backs the MetricsOnlyReasons() getter. It is the
// SUBSET of WTPInvalidFrameReason values that have NO proto-side
// counterpart — emitted by code paths downstream of the validator
// (decompress_error) OR by the receiver-side defense-in-depth guard /
// metrics-side invalid-label collapse (classifier_bypass).
var metricsOnlyReasons = []WTPInvalidFrameReason{
	WTPInvalidFrameReasonClassifierBypass,
	WTPInvalidFrameReasonDecompressError,
}

// ValidWTPInvalidFrameReasons returns a copy of the set of metrics-side
// frame-validation reasons that are recognized by IncDroppedInvalidFrame.
// Returned as map[WTPInvalidFrameReason]struct{} so parity tests can
// range over keys without touching the unexported state. STABLE
// PRODUCTION API.
func ValidWTPInvalidFrameReasons() map[WTPInvalidFrameReason]struct{} {
	out := make(map[WTPInvalidFrameReason]struct{}, len(wtpInvalidFrameReasonsValid))
	for k := range wtpInvalidFrameReasonsValid {
		out[k] = struct{}{}
	}
	return out
}

// ValidationReasons returns a fresh copy of the validator-emitted
// (SHARED with wtpv1.AllValidationReasons()) frame-validation reasons.
// Consumers (notably the Task 22b parity test) range over this slice
// to assert the proto-side and metrics-side enums stay in sync.
// STABLE PRODUCTION API.
func ValidationReasons() []WTPInvalidFrameReason {
	out := make([]WTPInvalidFrameReason, len(validationReasonsShared))
	copy(out, validationReasonsShared)
	return out
}

// MetricsOnlyReasons returns a fresh copy of the metrics-only frame-
// validation reasons (those without a proto-side wtpv1.ValidationReason
// counterpart). Today: classifier_bypass and decompress_error.
// STABLE PRODUCTION API.
func MetricsOnlyReasons() []WTPInvalidFrameReason {
	out := make([]WTPInvalidFrameReason, len(metricsOnlyReasons))
	copy(out, metricsOnlyReasons)
	return out
}

// WTPWALQuarantineReason is a fixed, low-cardinality classification of
// why the Store-wiring layer quarantined an existing WAL directory.
// Adding new reasons requires updating both the spec §"Quarantine
// policy" subsection and the wtpWALQuarantineReasonsValid table.
type WTPWALQuarantineReason string

const (
	WTPWALQuarantineReasonSessionIDMismatch      WTPWALQuarantineReason = "session_id_mismatch"
	WTPWALQuarantineReasonKeyFingerprintMismatch WTPWALQuarantineReason = "key_fingerprint_mismatch"
	WTPWALQuarantineReasonContextDigestMismatch  WTPWALQuarantineReason = "context_digest_mismatch"
	WTPWALQuarantineReasonUnknown                WTPWALQuarantineReason = "unknown_identity_mismatch"
)

var wtpWALQuarantineReasonsValid = map[WTPWALQuarantineReason]struct{}{
	WTPWALQuarantineReasonSessionIDMismatch:      {},
	WTPWALQuarantineReasonKeyFingerprintMismatch: {},
	WTPWALQuarantineReasonContextDigestMismatch:  {},
	WTPWALQuarantineReasonUnknown:                {},
}

// wtpWALQuarantineReasonsEmitOrder is the canonical sort-by-string
// emission order. Mirrors wtpReconnectReasonsEmitOrder.
var wtpWALQuarantineReasonsEmitOrder = []WTPWALQuarantineReason{
	WTPWALQuarantineReasonContextDigestMismatch,
	WTPWALQuarantineReasonKeyFingerprintMismatch,
	WTPWALQuarantineReasonSessionIDMismatch,
	WTPWALQuarantineReasonUnknown,
}

// IncDroppedInvalidUTF8 increments wtp_dropped_invalid_utf8_total by n.
// Wired by AppendEvent (Task 23) when canonical encoding rejects a
// payload as non-UTF-8.
func (w *WTPMetrics) IncDroppedInvalidUTF8(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedInvalidUTF8.Add(n)
}

func (w *WTPMetrics) DroppedInvalidUTF8() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedInvalidUTF8.Load()
}

// IncDroppedSequenceOverflow increments wtp_dropped_sequence_overflow_total
// by n. Wired by AppendEvent (Task 23) when ev.Chain.Sequence exceeds
// math.MaxInt64.
func (w *WTPMetrics) IncDroppedSequenceOverflow(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedSequenceOverflow.Add(n)
}

func (w *WTPMetrics) DroppedSequenceOverflow() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedSequenceOverflow.Load()
}

// IncSessionInitFailures increments wtp_session_init_failures_total
// {reason=<reason>}. Unknown reasons collapse to
// WTPSessionFailureReasonUnknown to bound label cardinality.
func (w *WTPMetrics) IncSessionInitFailures(reason WTPSessionFailureReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpSessionFailureReasonsValid[reason]; !ok {
		reason = WTPSessionFailureReasonUnknown
	}
	ptr, _ := w.c.wtpSessionInitFailuresByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// IncSessionRotationFailures increments wtp_session_rotation_failures_total
// {reason=<reason>}. Same validation as IncSessionInitFailures.
func (w *WTPMetrics) IncSessionRotationFailures(reason WTPSessionFailureReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpSessionFailureReasonsValid[reason]; !ok {
		reason = WTPSessionFailureReasonUnknown
	}
	ptr, _ := w.c.wtpSessionRotationFailuresByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// IncDroppedInvalidMapper increments wtp_dropped_invalid_mapper_total
// by n. Wired by AppendEvent (Task 23) when compact.Encode returns
// ErrInvalidMapper. Defense in depth — Store.New rejects the same
// condition at construction; non-zero indicates a code path mutated
// the mapper post-construction.
func (w *WTPMetrics) IncDroppedInvalidMapper(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedInvalidMapper.Add(n)
}

func (w *WTPMetrics) DroppedInvalidMapper() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedInvalidMapper.Load()
}

// IncDroppedInvalidTimestamp increments wtp_dropped_invalid_timestamp_total
// by n. Wired by AppendEvent (Task 23) when compact.Encode returns
// ErrInvalidTimestamp.
func (w *WTPMetrics) IncDroppedInvalidTimestamp(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedInvalidTimestamp.Add(n)
}

func (w *WTPMetrics) DroppedInvalidTimestamp() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedInvalidTimestamp.Load()
}

// IncDroppedMapperFailure increments wtp_dropped_mapper_failure_total
// by n. Wired by AppendEvent (Task 23) for the catch-all default branch
// when compact.Encode wraps a mapper-side error.
func (w *WTPMetrics) IncDroppedMapperFailure(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpDroppedMapperFailure.Add(n)
}

func (w *WTPMetrics) DroppedMapperFailure() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpDroppedMapperFailure.Load()
}

// IncWTPLossUnknownReason increments wtp_loss_unknown_reason_total by n.
// Called by transport.encodeBatchMessage when ToWireReason returns
// ok=false — i.e., a producer added a new wal.LossReason* string without
// updating ToWireReason. The marker is dropped (not emitted as
// UNSPECIFIED) to preserve wire-format conformance. Non-zero values
// indicate a programming bug.
func (w *WTPMetrics) IncWTPLossUnknownReason(n uint64) {
	if w == nil || w.c == nil {
		return
	}
	w.c.wtpLossUnknownReason.Add(n)
}

func (w *WTPMetrics) WTPLossUnknownReason() uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	return w.c.wtpLossUnknownReason.Load()
}

// IncDroppedInvalidFrame increments wtp_dropped_invalid_frame_total
// {reason=<reason>}. Unknown reason values collapse to
// WTPInvalidFrameReasonClassifierBypass (NOT WTPInvalidFrameReasonUnknown
// — those are disjoint per spec §"Operator runbook"; an invalid label
// from a caller is a metrics-side defect indicator) and trigger a
// WARN-level structured log carrying the offending raw_reason so
// operators paged on classifier_bypass can identify the callsite.
//
// CALLER CONTRACT (load-bearing): the `reason` argument MUST be one of
// the WTPInvalidFrameReason* constants — i.e. a fixed, internally-
// controlled enumeration. Callers MUST NOT pass peer-derived strings
// (raw protobuf field values, server-supplied tags, etc.) under any
// circumstances. The invalid-label collapse path logs the raw_reason
// verbatim; if a caller forwards a high-cardinality or peer-controlled
// string here, the resulting WARN log can be turned into a log-spam
// vector by a malicious or buggy peer. Use errors.As against
// *wtpv1.ValidationError and forward `WTPInvalidFrameReason(ve.Reason)`
// when the validator emitted the error; for downstream paths
// (decompression, defense-in-depth) use the dedicated metrics-only
// constants directly. INTENDED callers (transport receivers via
// Task 17 Step 4a, AppendEvent decompression path) are not yet
// landed; new and existing callers MUST be reviewed against this
// contract when wiring lands.
//
// The raw_reason is treated as internal under this contract — it is
// safe to log verbatim per spec §"Operator runbook" and the invalid-
// frame log sanitization rule. This complements the receiver-side
// WARN log emitted by Task 17 Step 4a's defense-in-depth guard.
func (w *WTPMetrics) IncDroppedInvalidFrame(reason WTPInvalidFrameReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpInvalidFrameReasonsValid[reason]; !ok {
		// Emit the WARN only if the metrics-side per-path rate-limiter
		// allows; the metric counter ALWAYS increments regardless so
		// the true volume is visible in /metrics even when the WARN is
		// sampled. The receiver-side defense-in-depth WARN has its OWN
		// per-path bucket — see wtp_ratelimit.go for why the two paths
		// are independent (non-starvation guarantee).
		if AllowMetricsClassifierBypassWARN() {
			slog.Warn("invalid invalid-frame reason label",
				slog.String("raw_reason", string(reason)),
				slog.String("reason", string(WTPInvalidFrameReasonClassifierBypass)),
			)
		}
		reason = WTPInvalidFrameReasonClassifierBypass
	}
	ptr, _ := w.c.wtpDroppedInvalidFrameByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// DroppedInvalidFrame returns the current count for one frame-
// validation reason. Unknown reasons return 0.
func (w *WTPMetrics) DroppedInvalidFrame(reason WTPInvalidFrameReason) uint64 {
	if w == nil || w.c == nil {
		return 0
	}
	if _, ok := wtpInvalidFrameReasonsValid[reason]; !ok {
		return 0
	}
	v, ok := w.c.wtpDroppedInvalidFrameByReason.Load(string(reason))
	if !ok || v == nil {
		return 0
	}
	return v.(*atomic.Uint64).Load()
}

// IncWALQuarantine increments wtp_wal_quarantine_total{reason=<reason>}.
// Called by the Store-layer wal.Open recovery path on identity
// mismatch. Unknown reasons fall back to WTPWALQuarantineReasonUnknown
// to bound label cardinality.
func (w *WTPMetrics) IncWALQuarantine(reason WTPWALQuarantineReason) {
	if w == nil || w.c == nil {
		return
	}
	if _, ok := wtpWALQuarantineReasonsValid[reason]; !ok {
		reason = WTPWALQuarantineReasonUnknown
	}
	ptr, _ := w.c.wtpWALQuarantineByReason.LoadOrStore(string(reason), &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// ----- Task 4: batch-compression metrics ----------------------------
//
// Five new families. All carry an `algo` label whose canonical, fixed
// value set is wtpCompressionAlgos (currently "gzip", "zstd"). Adding
// a new algorithm requires:
//
//   - extending wtpCompressionAlgos (in alphabetical order for stable
//     emission),
//   - adding a per-algo compressionRatioBuckets field on Collector,
//   - extending the algo-switch in ObserveBatchCompressionRatio and the
//     histogram-emit block in emitWTPMetrics.
//
// All five series follow the always-emit contract: every (algo) and
// (algo, reason) combination in the canonical cross product appears in
// the very first scrape with a zero value, even when no Observe/Inc
// calls have happened yet. Counter helpers reject unrecognized algos so
// out-of-band callers (typo, bug) don't pollute label cardinality —
// bounded by the fixed set above.

// wtpCompressionRatioBucketsValues is the fixed upper-bound set for the
// wtp_batch_compression_ratio histogram. compressionRatioBuckets.buckets
// is sized to len(wtpCompressionRatioBucketsValues)+1 (the implicit +Inf
// bucket).
var wtpCompressionRatioBucketsValues = []float64{0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0}

// wtpCompressionAlgos is the canonical algo emission order
// (alphabetical) shared by every batch-compression series.
var wtpCompressionAlgos = []string{"gzip", "zstd"}

// wtpDecompressReasons is the canonical reason set for the
// wtp_decompress_error_total counter. Always-emit cross product is
// len(wtpCompressionAlgos) * len(wtpDecompressReasons).
var wtpDecompressReasons = []string{"decode_error", "oversize", "proto_unmarshal"}

// ObserveBatchCompressionRatio records one compressed/uncompressed
// size ratio for the wtp_batch_compression_ratio histogram. Unknown
// algos are dropped silently (no observation, no error counter) — the
// caller already validated `algo` against the encoder it constructed.
func (w *WTPMetrics) ObserveBatchCompressionRatio(algo string, ratio float64) {
	if w == nil || w.c == nil {
		return
	}
	var h *compressionRatioBuckets
	switch algo {
	case "zstd":
		h = &w.c.wtpBatchCompressionRatioZstd
	case "gzip":
		h = &w.c.wtpBatchCompressionRatioGzip
	default:
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++
	h.sum += ratio
	for i, ub := range wtpCompressionRatioBucketsValues {
		if ratio <= ub {
			h.buckets[i]++
		}
	}
	h.buckets[len(wtpCompressionRatioBucketsValues)]++ // +Inf
}

// AddBatchUncompressedBytes adds n to wtp_batch_uncompressed_bytes_total
// {algo}. Negative n and unknown algos are dropped.
func (w *WTPMetrics) AddBatchUncompressedBytes(algo string, n int) {
	if w == nil || w.c == nil || n < 0 {
		return
	}
	if algo != "zstd" && algo != "gzip" {
		return
	}
	ptr, _ := w.c.wtpBatchUncompressedBytesByAlgo.LoadOrStore(algo, &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(uint64(n))
}

// AddBatchCompressedBytes adds n to wtp_batch_compressed_bytes_total
// {algo}. Negative n and unknown algos are dropped.
func (w *WTPMetrics) AddBatchCompressedBytes(algo string, n int) {
	if w == nil || w.c == nil || n < 0 {
		return
	}
	if algo != "zstd" && algo != "gzip" {
		return
	}
	ptr, _ := w.c.wtpBatchCompressedBytesByAlgo.LoadOrStore(algo, &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(uint64(n))
}

// IncCompressError increments wtp_compress_error_total{algo}. Used on
// sender-side fail-open fallback when the encoder returned an error
// and the batch was emitted as COMPRESSION_NONE. Unknown algos are
// dropped.
func (w *WTPMetrics) IncCompressError(algo string) {
	if w == nil || w.c == nil {
		return
	}
	if algo != "zstd" && algo != "gzip" {
		return
	}
	ptr, _ := w.c.wtpCompressErrorByAlgo.LoadOrStore(algo, &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// IncDecompressError increments wtp_decompress_error_total{algo,reason}.
// Used by the receiver to count decode failures. Unknown algos and
// reasons are dropped to bound label cardinality.
func (w *WTPMetrics) IncDecompressError(algo, reason string) {
	if w == nil || w.c == nil {
		return
	}
	if algo != "zstd" && algo != "gzip" {
		return
	}
	valid := false
	for _, r := range wtpDecompressReasons {
		if r == reason {
			valid = true
			break
		}
	}
	if !valid {
		return
	}
	key := algo + "|" + reason
	ptr, _ := w.c.wtpDecompressErrorByLabels.LoadOrStore(key, &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}
