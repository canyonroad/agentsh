//go:build linux

package ptrace

// Metrics collects ptrace-specific operational metrics.
// Implementations must be safe for concurrent use.
type Metrics interface {
	SetTraceeCount(n int)
	IncAttachFailure(reason string)
	IncTimeout()
	IncExitStopSkipped()
}

// nopMetrics is a no-op implementation used when no metrics collector is configured.
type nopMetrics struct{}

func (nopMetrics) SetTraceeCount(int)     {}
func (nopMetrics) IncAttachFailure(string) {}
func (nopMetrics) IncTimeout()            {}
func (nopMetrics) IncExitStopSkipped()    {}
