package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// compressionRatioBuckets is the per-algo storage backing the
// wtp_batch_compression_ratio histogram. The buckets array carries one
// slot per upper bound in wtpCompressionRatioBucketsValues plus one for
// the implicit +Inf bucket. Held under mu to keep ObserveBatchCompressionRatio
// + emit consistent (the histogram is updated as a 3-tuple of count,
// sum, buckets).
type compressionRatioBuckets struct {
	mu      sync.Mutex
	buckets [8]uint64 // 7 bucket values aligned to wtpCompressionRatioBucketsValues + +Inf
	count   uint64
	sum     float64
}

// Collector provides a minimal Prometheus-compatible metrics exporter.
type Collector struct {
	startedAt time.Time

	eventsTotal atomic.Uint64
	byType      sync.Map // string -> *atomic.Uint64

	ebpfDropped     atomic.Uint64
	ebpfAttachFail  atomic.Uint64
	ebpfUnavailable atomic.Uint64

	// WTP series
	wtpEventsAppended      atomic.Uint64
	wtpEventsAcked         atomic.Uint64
	wtpBatchesSent         atomic.Uint64
	wtpBytesSent           atomic.Uint64
	wtpTransportLoss       atomic.Uint64
	wtpReconnectsByReason  sync.Map
	wtpSessionState        atomic.Int64
	wtpWALSegments         atomic.Int64
	wtpWALBytes            atomic.Int64
	wtpAckHighWatermark    atomic.Int64
	wtpWALCorruption       atomic.Uint64

	// Task 22a sink-failure additions. Populated by AppendEvent
	// (Task 23) for the unlabeled per-record drops, and by the
	// transport / receiver layers (Phases 8-10) for the labeled
	// peer-protocol families. wtpDroppedMissingChain (Task 3) was
	// removed in Task 22a Step 3.5 — the missing-chain class is
	// now propagated as a wrapped error from AppendEvent rather
	// than counted, since it indicates a composite-store
	// regression operators must surface loudly.
	wtpDroppedInvalidUTF8              atomic.Uint64
	wtpDroppedSequenceOverflow         atomic.Uint64
	wtpDroppedInvalidMapper            atomic.Uint64
	wtpDroppedInvalidTimestamp         atomic.Uint64
	wtpDroppedMapperFailure            atomic.Uint64
	wtpDroppedInvalidFrameByReason     sync.Map
	wtpSessionInitFailuresByReason     sync.Map
	wtpSessionRotationFailuresByReason sync.Map

	// Task 3: wtp_loss_unknown_reason_total. Incremented by the encoder
	// when a wal.LossRecord.Reason string has no wire enum mapping.
	wtpLossUnknownReason atomic.Uint64

	// Task 22 cursor-feedback metrics. The Transport's
	// applyServerAckTuple helper increments these on the three non-
	// Adopted dispatch outcomes; AppendEvent and the recv-multiplexer
	// share the same accessors.
	wtpAnomalousAckByReason  sync.Map // map[string]*atomic.Uint64
	wtpResendNeeded          atomic.Uint64
	wtpAckRegressionLoss     atomic.Uint64
	wtpWALQuarantineByReason sync.Map // Task 22a: WAL identity-mismatch quarantines

	wtpLatencyMu      sync.Mutex
	wtpLatencyBuckets [14]uint64 // 13 buckets + +Inf; index aligned with wtpLatencyBucketsSeconds
	wtpLatencyCount   uint64
	wtpLatencySum     float64

	// Compression metrics (Task 4 of 2026-04-27 batch-compression plan).
	// Per-algo storage using fixed fields rather than sync.Map keeps the
	// always-emit cross product trivial — the emit code references each
	// field directly. Add new algos by adding a field + an entry to the
	// emit fixed slice (wtpCompressionAlgos) and the per-algo switch in
	// ObserveBatchCompressionRatio + emitWTPMetrics.
	wtpBatchCompressionRatioZstd compressionRatioBuckets
	wtpBatchCompressionRatioGzip compressionRatioBuckets

	wtpBatchCompressedBytesByAlgo   sync.Map // algo -> *atomic.Uint64
	wtpBatchUncompressedBytesByAlgo sync.Map // algo -> *atomic.Uint64
	wtpCompressErrorByAlgo          sync.Map // algo -> *atomic.Uint64
	wtpDecompressErrorByLabels      sync.Map // "algo|reason" -> *atomic.Uint64
}

func New() *Collector {
	return &Collector{startedAt: time.Now().UTC()}
}

func (c *Collector) IncEvent(eventType string) {
	if c == nil {
		return
	}
	c.eventsTotal.Add(1)
	if eventType == "" {
		eventType = "unknown"
	}
	ptr, _ := c.byType.LoadOrStore(eventType, &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

func (c *Collector) IncEBPFDropped() {
	if c == nil {
		return
	}
	c.ebpfDropped.Add(1)
}

func (c *Collector) IncEBPFAttachFail() {
	if c == nil {
		return
	}
	c.ebpfAttachFail.Add(1)
}

func (c *Collector) IncEBPFUnavailable() {
	if c == nil {
		return
	}
	c.ebpfUnavailable.Add(1)
}

type HandlerOptions struct {
	SessionCount func() int
}

func (c *Collector) Handler(opts HandlerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, "# HELP agentsh_up Whether the agentsh server is running.\n")
		fmt.Fprint(w, "# TYPE agentsh_up gauge\n")
		fmt.Fprint(w, "agentsh_up 1\n")

		fmt.Fprint(w, "# HELP agentsh_events_total Total number of events appended.\n")
		fmt.Fprint(w, "# TYPE agentsh_events_total counter\n")
		fmt.Fprintf(w, "agentsh_events_total %d\n", c.eventsTotal.Load())

		fmt.Fprint(w, "# HELP agentsh_net_ebpf_dropped_events_total eBPF connect events dropped due to backpressure.\n")
		fmt.Fprint(w, "# TYPE agentsh_net_ebpf_dropped_events_total counter\n")
		fmt.Fprintf(w, "agentsh_net_ebpf_dropped_events_total %d\n", c.ebpfDropped.Load())

		fmt.Fprint(w, "# HELP agentsh_net_ebpf_attach_fail_total eBPF attach failures.\n")
		fmt.Fprint(w, "# TYPE agentsh_net_ebpf_attach_fail_total counter\n")
		fmt.Fprintf(w, "agentsh_net_ebpf_attach_fail_total %d\n", c.ebpfAttachFail.Load())

		fmt.Fprint(w, "# HELP agentsh_net_ebpf_unavailable_total Times eBPF was unavailable on host.\n")
		fmt.Fprint(w, "# TYPE agentsh_net_ebpf_unavailable_total counter\n")
		fmt.Fprintf(w, "agentsh_net_ebpf_unavailable_total %d\n", c.ebpfUnavailable.Load())

		types := snapshotKeys(&c.byType)
		if len(types) > 0 {
			fmt.Fprint(w, "# HELP agentsh_events_by_type_total Total events appended by type.\n")
			fmt.Fprint(w, "# TYPE agentsh_events_by_type_total counter\n")
			for _, t := range types {
				ptr, _ := c.byType.Load(t)
				n := uint64(0)
				if ptr != nil {
					n = ptr.(*atomic.Uint64).Load()
				}
				fmt.Fprintf(w, "agentsh_events_by_type_total{type=%q} %d\n", escapeLabelValue(t), n)
			}
		}

		c.emitWTPMetrics(w)

		if opts.SessionCount != nil {
			fmt.Fprint(w, "# HELP agentsh_sessions_active Active sessions.\n")
			fmt.Fprint(w, "# TYPE agentsh_sessions_active gauge\n")
			fmt.Fprintf(w, "agentsh_sessions_active %d\n", opts.SessionCount())
		}
	})
}

func snapshotKeys(m *sync.Map) []string {
	var out []string
	m.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			out = append(out, s)
		}
		return true
	})
	sort.Strings(out)
	return out
}

func escapeLabelValue(v string) string {
	// Prometheus text format label escaping for " and \ and newlines.
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\n", "\\n")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	return v
}
