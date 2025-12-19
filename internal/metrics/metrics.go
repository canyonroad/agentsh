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

// Collector provides a minimal Prometheus-compatible metrics exporter.
type Collector struct {
	startedAt time.Time

	eventsTotal atomic.Uint64
	byType      sync.Map // string -> *atomic.Uint64

	ebpfDropped     atomic.Uint64
	ebpfAttachFail  atomic.Uint64
	ebpfUnavailable atomic.Uint64
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
