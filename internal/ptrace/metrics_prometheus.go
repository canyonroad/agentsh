//go:build linux

package ptrace

// PtraceMetricsCollector is the interface that PrometheusCollector satisfies.
// Defined here to avoid a dependency from ptrace -> observability.
type PtraceMetricsCollector interface {
	SetPtraceTraceeCount(n int)
	IncPtraceAttachFailure(reason string)
	IncPtraceTimeout()
}

// prometheusMetrics adapts a PtraceMetricsCollector to the ptrace.Metrics interface.
type prometheusMetrics struct {
	c PtraceMetricsCollector
}

// NewPrometheusMetrics creates a Metrics implementation backed by a PtraceMetricsCollector.
// Returns nopMetrics if c is nil.
func NewPrometheusMetrics(c PtraceMetricsCollector) Metrics {
	if c == nil {
		return nopMetrics{}
	}
	return &prometheusMetrics{c: c}
}

func (m *prometheusMetrics) SetTraceeCount(n int)          { m.c.SetPtraceTraceeCount(n) }
func (m *prometheusMetrics) IncAttachFailure(reason string) { m.c.IncPtraceAttachFailure(reason) }
func (m *prometheusMetrics) IncTimeout()                    { m.c.IncPtraceTimeout() }
