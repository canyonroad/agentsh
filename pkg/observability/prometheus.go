// Package observability provides Prometheus metrics, OpenTelemetry tracing,
// and structured logging for agentsh.
package observability

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PrometheusCollector provides Prometheus-compatible metrics.
type PrometheusCollector struct {
	startedAt time.Time

	// Session metrics
	sessionsActive  atomic.Int64
	sessionsCreated sync.Map // key: "state:tenant_id" -> *atomic.Uint64
	sessionDurations []sessionDuration
	sessionDurMu     sync.Mutex

	// Operation metrics
	operationsTotal   sync.Map // key: "type:decision" -> *atomic.Uint64
	operationLatencies []operationLatency
	operationLatMu     sync.Mutex

	// Approval metrics
	approvalsPending   atomic.Int64
	approvalLatencies []time.Duration
	approvalLatMu     sync.Mutex

	// Policy metrics
	policyEvalLatencies []time.Duration
	policyEvalMu        sync.Mutex

	// Legacy event metrics (for compatibility)
	eventsTotal atomic.Uint64
	byType      sync.Map // string -> *atomic.Uint64

	// eBPF metrics
	ebpfDropped     atomic.Uint64
	ebpfAttachFail  atomic.Uint64
	ebpfUnavailable atomic.Uint64
}

type sessionDuration struct {
	tenantID  string
	exitState string
	duration  time.Duration
}

type operationLatency struct {
	opType  string
	latency time.Duration
}

// NewPrometheusCollector creates a new Prometheus metrics collector.
func NewPrometheusCollector() *PrometheusCollector {
	return &PrometheusCollector{
		startedAt: time.Now().UTC(),
	}
}

// Session metrics

// IncSessionActive increments the active session count.
func (c *PrometheusCollector) IncSessionActive() {
	if c == nil {
		return
	}
	c.sessionsActive.Add(1)
}

// DecSessionActive decrements the active session count.
func (c *PrometheusCollector) DecSessionActive() {
	if c == nil {
		return
	}
	c.sessionsActive.Add(-1)
}

// IncSessionCreated increments the session created counter by state and tenant.
func (c *PrometheusCollector) IncSessionCreated(state, tenantID string) {
	if c == nil {
		return
	}
	key := state + ":" + tenantID
	ptr, _ := c.sessionsCreated.LoadOrStore(key, &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// RecordSessionDuration records a session duration for histogram.
func (c *PrometheusCollector) RecordSessionDuration(tenantID, exitState string, duration time.Duration) {
	if c == nil {
		return
	}
	c.sessionDurMu.Lock()
	defer c.sessionDurMu.Unlock()
	c.sessionDurations = append(c.sessionDurations, sessionDuration{
		tenantID:  tenantID,
		exitState: exitState,
		duration:  duration,
	})
}

// Operation metrics

// IncOperation increments the operation counter by type and decision.
func (c *PrometheusCollector) IncOperation(opType, decision string) {
	if c == nil {
		return
	}
	key := opType + ":" + decision
	ptr, _ := c.operationsTotal.LoadOrStore(key, &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// RecordOperationLatency records an operation latency for histogram.
func (c *PrometheusCollector) RecordOperationLatency(opType string, latency time.Duration) {
	if c == nil {
		return
	}
	c.operationLatMu.Lock()
	defer c.operationLatMu.Unlock()
	c.operationLatencies = append(c.operationLatencies, operationLatency{
		opType:  opType,
		latency: latency,
	})
}

// Approval metrics

// IncApprovalPending increments pending approvals.
func (c *PrometheusCollector) IncApprovalPending() {
	if c == nil {
		return
	}
	c.approvalsPending.Add(1)
}

// DecApprovalPending decrements pending approvals.
func (c *PrometheusCollector) DecApprovalPending() {
	if c == nil {
		return
	}
	c.approvalsPending.Add(-1)
}

// RecordApprovalLatency records approval latency for histogram.
func (c *PrometheusCollector) RecordApprovalLatency(latency time.Duration) {
	if c == nil {
		return
	}
	c.approvalLatMu.Lock()
	defer c.approvalLatMu.Unlock()
	c.approvalLatencies = append(c.approvalLatencies, latency)
}

// Policy metrics

// RecordPolicyEvalLatency records policy evaluation latency.
func (c *PrometheusCollector) RecordPolicyEvalLatency(latency time.Duration) {
	if c == nil {
		return
	}
	c.policyEvalMu.Lock()
	defer c.policyEvalMu.Unlock()
	c.policyEvalLatencies = append(c.policyEvalLatencies, latency)
}

// Legacy event metrics

// IncEvent increments event counter by type.
func (c *PrometheusCollector) IncEvent(eventType string) {
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

// eBPF metrics

// IncEBPFDropped increments dropped eBPF events counter.
func (c *PrometheusCollector) IncEBPFDropped() {
	if c == nil {
		return
	}
	c.ebpfDropped.Add(1)
}

// IncEBPFAttachFail increments eBPF attach failure counter.
func (c *PrometheusCollector) IncEBPFAttachFail() {
	if c == nil {
		return
	}
	c.ebpfAttachFail.Add(1)
}

// IncEBPFUnavailable increments eBPF unavailable counter.
func (c *PrometheusCollector) IncEBPFUnavailable() {
	if c == nil {
		return
	}
	c.ebpfUnavailable.Add(1)
}

// HandlerOptions configures the metrics HTTP handler.
type HandlerOptions struct {
	SessionCount func() int
}

// Handler returns an HTTP handler for Prometheus metrics.
func (c *PrometheusCollector) Handler(opts HandlerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		// Server up
		fmt.Fprint(w, "# HELP agentsh_up Whether the agentsh server is running.\n")
		fmt.Fprint(w, "# TYPE agentsh_up gauge\n")
		fmt.Fprint(w, "agentsh_up 1\n\n")

		// Session metrics
		fmt.Fprint(w, "# HELP agentsh_sessions_active Number of currently active sessions.\n")
		fmt.Fprint(w, "# TYPE agentsh_sessions_active gauge\n")
		fmt.Fprintf(w, "agentsh_sessions_active %d\n\n", c.sessionsActive.Load())

		c.writeSessionsTotal(w)
		c.writeSessionDurations(w)

		// Operation metrics
		c.writeOperationsTotal(w)
		c.writeOperationLatencies(w)

		// Approval metrics
		fmt.Fprint(w, "# HELP agentsh_approvals_pending Number of pending approvals.\n")
		fmt.Fprint(w, "# TYPE agentsh_approvals_pending gauge\n")
		fmt.Fprintf(w, "agentsh_approvals_pending %d\n\n", c.approvalsPending.Load())

		c.writeApprovalLatencies(w)

		// Policy metrics
		c.writePolicyEvalLatencies(w)

		// Legacy event metrics
		fmt.Fprint(w, "# HELP agentsh_events_total Total number of events appended.\n")
		fmt.Fprint(w, "# TYPE agentsh_events_total counter\n")
		fmt.Fprintf(w, "agentsh_events_total %d\n\n", c.eventsTotal.Load())

		c.writeEventsByType(w)

		// eBPF metrics
		fmt.Fprint(w, "# HELP agentsh_net_ebpf_dropped_events_total eBPF connect events dropped due to backpressure.\n")
		fmt.Fprint(w, "# TYPE agentsh_net_ebpf_dropped_events_total counter\n")
		fmt.Fprintf(w, "agentsh_net_ebpf_dropped_events_total %d\n\n", c.ebpfDropped.Load())

		fmt.Fprint(w, "# HELP agentsh_net_ebpf_attach_fail_total eBPF attach failures.\n")
		fmt.Fprint(w, "# TYPE agentsh_net_ebpf_attach_fail_total counter\n")
		fmt.Fprintf(w, "agentsh_net_ebpf_attach_fail_total %d\n\n", c.ebpfAttachFail.Load())

		fmt.Fprint(w, "# HELP agentsh_net_ebpf_unavailable_total Times eBPF was unavailable on host.\n")
		fmt.Fprint(w, "# TYPE agentsh_net_ebpf_unavailable_total counter\n")
		fmt.Fprintf(w, "agentsh_net_ebpf_unavailable_total %d\n", c.ebpfUnavailable.Load())
	})
}

func (c *PrometheusCollector) writeSessionsTotal(w http.ResponseWriter) {
	keys := snapshotMapKeys(&c.sessionsCreated)
	if len(keys) == 0 {
		return
	}
	fmt.Fprint(w, "# HELP agentsh_sessions_total Total sessions by state and tenant.\n")
	fmt.Fprint(w, "# TYPE agentsh_sessions_total counter\n")
	for _, key := range keys {
		parts := strings.SplitN(key, ":", 2)
		state, tenantID := parts[0], ""
		if len(parts) > 1 {
			tenantID = parts[1]
		}
		ptr, _ := c.sessionsCreated.Load(key)
		n := ptr.(*atomic.Uint64).Load()
		fmt.Fprintf(w, "agentsh_sessions_total{state=%q,tenant_id=%q} %d\n",
			escapeLabelValue(state), escapeLabelValue(tenantID), n)
	}
	fmt.Fprint(w, "\n")
}

func (c *PrometheusCollector) writeSessionDurations(w http.ResponseWriter) {
	c.sessionDurMu.Lock()
	durations := make([]sessionDuration, len(c.sessionDurations))
	copy(durations, c.sessionDurations)
	c.sessionDurMu.Unlock()

	if len(durations) == 0 {
		return
	}

	// Histogram buckets in seconds
	buckets := []float64{1, 10, 60, 300, 900, 3600}

	fmt.Fprint(w, "# HELP agentsh_session_duration_seconds Session duration in seconds.\n")
	fmt.Fprint(w, "# TYPE agentsh_session_duration_seconds histogram\n")

	// Group by tenant_id and exit_state
	groups := make(map[string][]time.Duration)
	for _, d := range durations {
		key := d.tenantID + ":" + d.exitState
		groups[key] = append(groups[key], d.duration)
	}

	for key, durs := range groups {
		parts := strings.SplitN(key, ":", 2)
		tenantID, exitState := parts[0], ""
		if len(parts) > 1 {
			exitState = parts[1]
		}
		labels := fmt.Sprintf("tenant_id=%q,exit_state=%q", escapeLabelValue(tenantID), escapeLabelValue(exitState))

		var sum float64
		for _, bucket := range buckets {
			count := 0
			for _, d := range durs {
				if d.Seconds() <= bucket {
					count++
				}
			}
			fmt.Fprintf(w, "agentsh_session_duration_seconds_bucket{%s,le=\"%.0f\"} %d\n", labels, bucket, count)
		}
		fmt.Fprintf(w, "agentsh_session_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, len(durs))
		for _, d := range durs {
			sum += d.Seconds()
		}
		fmt.Fprintf(w, "agentsh_session_duration_seconds_sum{%s} %.3f\n", labels, sum)
		fmt.Fprintf(w, "agentsh_session_duration_seconds_count{%s} %d\n", labels, len(durs))
	}
	fmt.Fprint(w, "\n")
}

func (c *PrometheusCollector) writeOperationsTotal(w http.ResponseWriter) {
	keys := snapshotMapKeys(&c.operationsTotal)
	if len(keys) == 0 {
		return
	}
	fmt.Fprint(w, "# HELP agentsh_operations_total Total operations by type and decision.\n")
	fmt.Fprint(w, "# TYPE agentsh_operations_total counter\n")
	for _, key := range keys {
		parts := strings.SplitN(key, ":", 2)
		opType, decision := parts[0], ""
		if len(parts) > 1 {
			decision = parts[1]
		}
		ptr, _ := c.operationsTotal.Load(key)
		n := ptr.(*atomic.Uint64).Load()
		fmt.Fprintf(w, "agentsh_operations_total{type=%q,decision=%q} %d\n",
			escapeLabelValue(opType), escapeLabelValue(decision), n)
	}
	fmt.Fprint(w, "\n")
}

func (c *PrometheusCollector) writeOperationLatencies(w http.ResponseWriter) {
	c.operationLatMu.Lock()
	latencies := make([]operationLatency, len(c.operationLatencies))
	copy(latencies, c.operationLatencies)
	c.operationLatMu.Unlock()

	if len(latencies) == 0 {
		return
	}

	// Histogram buckets in seconds
	buckets := []float64{0.0001, 0.001, 0.01, 0.1, 1, 10}

	fmt.Fprint(w, "# HELP agentsh_operation_latency_seconds Operation interception latency.\n")
	fmt.Fprint(w, "# TYPE agentsh_operation_latency_seconds histogram\n")

	// Group by type
	groups := make(map[string][]time.Duration)
	for _, l := range latencies {
		groups[l.opType] = append(groups[l.opType], l.latency)
	}

	for opType, lats := range groups {
		labels := fmt.Sprintf("type=%q", escapeLabelValue(opType))
		var sum float64
		for _, bucket := range buckets {
			count := 0
			for _, l := range lats {
				if l.Seconds() <= bucket {
					count++
				}
			}
			fmt.Fprintf(w, "agentsh_operation_latency_seconds_bucket{%s,le=\"%g\"} %d\n", labels, bucket, count)
		}
		fmt.Fprintf(w, "agentsh_operation_latency_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, len(lats))
		for _, l := range lats {
			sum += l.Seconds()
		}
		fmt.Fprintf(w, "agentsh_operation_latency_seconds_sum{%s} %.6f\n", labels, sum)
		fmt.Fprintf(w, "agentsh_operation_latency_seconds_count{%s} %d\n", labels, len(lats))
	}
	fmt.Fprint(w, "\n")
}

func (c *PrometheusCollector) writeApprovalLatencies(w http.ResponseWriter) {
	c.approvalLatMu.Lock()
	latencies := make([]time.Duration, len(c.approvalLatencies))
	copy(latencies, c.approvalLatencies)
	c.approvalLatMu.Unlock()

	if len(latencies) == 0 {
		return
	}

	// Histogram buckets in seconds
	buckets := []float64{1, 5, 10, 30, 60, 300}

	fmt.Fprint(w, "# HELP agentsh_approval_latency_seconds Time to receive approval decision.\n")
	fmt.Fprint(w, "# TYPE agentsh_approval_latency_seconds histogram\n")

	var sum float64
	for _, bucket := range buckets {
		count := 0
		for _, l := range latencies {
			if l.Seconds() <= bucket {
				count++
			}
		}
		fmt.Fprintf(w, "agentsh_approval_latency_seconds_bucket{le=\"%.0f\"} %d\n", bucket, count)
	}
	fmt.Fprintf(w, "agentsh_approval_latency_seconds_bucket{le=\"+Inf\"} %d\n", len(latencies))
	for _, l := range latencies {
		sum += l.Seconds()
	}
	fmt.Fprintf(w, "agentsh_approval_latency_seconds_sum %.3f\n", sum)
	fmt.Fprintf(w, "agentsh_approval_latency_seconds_count %d\n\n", len(latencies))
}

func (c *PrometheusCollector) writePolicyEvalLatencies(w http.ResponseWriter) {
	c.policyEvalMu.Lock()
	latencies := make([]time.Duration, len(c.policyEvalLatencies))
	copy(latencies, c.policyEvalLatencies)
	c.policyEvalMu.Unlock()

	if len(latencies) == 0 {
		return
	}

	// Histogram buckets in seconds (microsecond-level)
	buckets := []float64{0.00001, 0.0001, 0.001, 0.01}

	fmt.Fprint(w, "# HELP agentsh_policy_eval_latency_seconds Policy evaluation latency.\n")
	fmt.Fprint(w, "# TYPE agentsh_policy_eval_latency_seconds histogram\n")

	var sum float64
	for _, bucket := range buckets {
		count := 0
		for _, l := range latencies {
			if l.Seconds() <= bucket {
				count++
			}
		}
		fmt.Fprintf(w, "agentsh_policy_eval_latency_seconds_bucket{le=\"%g\"} %d\n", bucket, count)
	}
	fmt.Fprintf(w, "agentsh_policy_eval_latency_seconds_bucket{le=\"+Inf\"} %d\n", len(latencies))
	for _, l := range latencies {
		sum += l.Seconds()
	}
	fmt.Fprintf(w, "agentsh_policy_eval_latency_seconds_sum %.9f\n", sum)
	fmt.Fprintf(w, "agentsh_policy_eval_latency_seconds_count %d\n\n", len(latencies))
}

func (c *PrometheusCollector) writeEventsByType(w http.ResponseWriter) {
	types := snapshotMapKeys(&c.byType)
	if len(types) == 0 {
		return
	}
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
	fmt.Fprint(w, "\n")
}

func snapshotMapKeys(m *sync.Map) []string {
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
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\n", "\\n")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	return v
}
