package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
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

func (w *WTPMetrics) IncReconnects(reason string) {
	if w == nil || w.c == nil {
		return
	}
	if reason == "" {
		reason = "unknown"
	}
	ptr, _ := w.c.wtpReconnectsByReason.LoadOrStore(reason, &atomic.Uint64{})
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

	reasons := snapshotKeys(&c.wtpReconnectsByReason)
	if len(reasons) > 0 {
		fmt.Fprint(w, "# HELP wtp_reconnects_total WTP transport reconnects by reason.\n")
		fmt.Fprint(w, "# TYPE wtp_reconnects_total counter\n")
		for _, r := range reasons {
			ptr, _ := c.wtpReconnectsByReason.Load(r)
			n := uint64(0)
			if ptr != nil {
				n = ptr.(*atomic.Uint64).Load()
			}
			fmt.Fprintf(w, "wtp_reconnects_total{reason=%q} %d\n", escapeLabelValue(r), n)
		}
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

	c.wtpLatencyMu.Lock()
	defer c.wtpLatencyMu.Unlock()
	fmt.Fprint(w, "# HELP wtp_send_latency_seconds Latency of WTP batch sends.\n")
	fmt.Fprint(w, "# TYPE wtp_send_latency_seconds histogram\n")
	for i, ub := range wtpLatencyBucketsSeconds {
		fmt.Fprintf(w, "wtp_send_latency_seconds_bucket{le=\"%g\"} %d\n", ub, c.wtpLatencyBuckets[i])
	}
	fmt.Fprintf(w, "wtp_send_latency_seconds_bucket{le=\"+Inf\"} %d\n", c.wtpLatencyBuckets[len(wtpLatencyBucketsSeconds)])
	fmt.Fprintf(w, "wtp_send_latency_seconds_sum %g\n", c.wtpLatencySum)
	fmt.Fprintf(w, "wtp_send_latency_seconds_count %d\n", c.wtpLatencyCount)
}

// reuse-prevention: ensure sort.Strings stays imported even if the only
// caller above is removed during refactors.
var _ = sort.Strings

// sync import retention (used via sync.Map field on Collector and sync.Mutex).
var _ sync.Locker = (*sync.Mutex)(nil)
