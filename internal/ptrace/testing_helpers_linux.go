//go:build linux

package ptrace

// NewTracerForTest creates a Tracer pre-seeded with a sessionless TraceeState
// for pid. Used by integration tests in other packages (e.g. internal/api) to
// exercise code paths that expect an already-traced, sessionless process — the
// attach_mode=pid shape that #416 fixes. Production code must not call this.
func NewTracerForTest(pid int) *Tracer {
	tr := &Tracer{
		tracees:       make(map[int]*TraceeState),
		parkedTracees: make(map[int]struct{}),
		tgidScratch:   make(map[int]*scratchPage),
		attachQueue:   make(chan attachRequest, 64),
		resumeQueue:   make(chan resumeRequest, 64),
		stopped:       make(chan struct{}),
		processTree:   NewProcessTree(),
		metrics:       nopMetrics{},
	}
	tr.tracees[pid] = &TraceeState{TID: pid, TGID: pid, SessionlessPIDAttach: true}
	return tr
}
