//go:build linux

package ptrace

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// #369 #2 diagnostic instrumentation.
//
// The FUSE-on hang on kernel 6.12.90 leaves the tracer goroutine idle in the
// Run-loop select (tracer.go) while a child sits stopped-but-reapable: a stop was
// consumed by handleStop, but no resume (PtraceCont/PtraceSyscall) or park
// (PTRACE_LISTEN) was issued for it, so Wait4 never returns that tid again. The
// branch responsible cannot be found by local inspection — it does not reproduce
// off exe.dev. This trace lets a single repro name the un-resumed stop: it logs
// every stop the Run loop dispatches and every resume/park issued, and an
// idle-tick scan flags any tracee whose stop was consumed but never resumed.
//
// Enabled only via the AGENTSH_PTRACE_TRACE env var. When off, the cost is one
// relaxed atomic load per stop/resume and nothing is written to TraceeState.

var (
	ptraceTraceEnabled atomic.Bool
	ptraceTraceSeq     atomic.Uint64
)

// wedgeThreshold is how long a tracee may sit with a consumed-but-unresumed stop
// before the idle-tick reporter flags it. Generous enough never to flag a tracee
// merely between a stop and its imminent resume on the same loop turn.
const wedgeThreshold = 2 * time.Second

// initPtraceTrace enables the stop/resume diagnostic when AGENTSH_PTRACE_TRACE is
// set to a truthy value. Called once at the top of Run.
func initPtraceTrace() {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AGENTSH_PTRACE_TRACE"))) {
	case "1", "true", "yes", "on":
		ptraceTraceEnabled.Store(true)
		slog.Info("ptrace-trace: stop/resume diagnostic enabled (#369)")
	}
}

// ptraceTraceOn reports whether the diagnostic is active.
func ptraceTraceOn() bool { return ptraceTraceEnabled.Load() }

// traceStop records and logs a stop dispatched from the Run loop, arming the
// wedge detector so the idle-tick scan can flag it if no resume or park follows.
// Terminal stops (exit/signaled) need no resume and do not arm. Call with t.mu
// NOT held.
func (t *Tracer) traceStop(tid int, st unix.WaitStatus) {
	if !ptraceTraceOn() {
		return
	}
	desc := describeWaitStatus(st)
	seq := ptraceTraceSeq.Add(1)
	slog.Info("ptrace-trace stop", "seq", seq, "tid", tid, "status", desc)

	terminal := st.Exited() || st.Signaled()
	t.mu.Lock()
	if s := t.tracees[tid]; s != nil {
		if terminal {
			s.awaitingResume = false
		} else {
			s.awaitingResume = true
			s.lastStopDesc = desc
			s.lastStopSeq = seq
			s.lastStopAt = time.Now()
			s.wedgeLogged = false
		}
	}
	t.mu.Unlock()
}

// traceResume records and logs a resume or intentional park for a tracee and
// clears the wedge-detector arm. `via` names the resume site (e.g.
// "allowSyscall-cont", "resumeTracee-syscall", "listen", "detach"). Call with
// t.mu NOT held.
func (t *Tracer) traceResume(tid int, via string, sig int) {
	if !ptraceTraceOn() {
		return
	}
	seq := ptraceTraceSeq.Add(1)
	slog.Info("ptrace-trace resume", "seq", seq, "tid", tid, "via", via, "sig", sig)
	t.mu.Lock()
	if s := t.tracees[tid]; s != nil {
		s.awaitingResume = false
	}
	t.mu.Unlock()
}

// scanWedged reports, at most once each, any tracee whose stop was consumed but
// never resumed for longer than wedgeThreshold. Called from the Run-loop idle
// branch. This is the diagnostic's headline output: it names the wedged tid and
// the stop type that went un-resumed, pinning the handleStop branch at fault.
func (t *Tracer) scanWedged() {
	if !ptraceTraceOn() {
		return
	}
	now := time.Now()
	type victim struct {
		tid  int
		desc string
		seq  uint64
		age  time.Duration
	}
	var victims []victim
	t.mu.Lock()
	for tid, s := range t.tracees {
		if s == nil || !s.awaitingResume || s.wedgeLogged {
			continue
		}
		age := now.Sub(s.lastStopAt)
		if age < wedgeThreshold {
			continue
		}
		s.wedgeLogged = true
		victims = append(victims, victim{tid: tid, desc: s.lastStopDesc, seq: s.lastStopSeq, age: age})
	}
	t.mu.Unlock()
	for _, v := range victims {
		slog.Warn("ptrace-trace WEDGE: stop consumed but never resumed (#369)",
			"tid", v.tid, "last_stop", v.desc, "stop_seq", v.seq, "age_ms", v.age.Milliseconds())
	}
}

// describeWaitStatus decodes a wait status into the same classification handleStop
// dispatches on, so each "stop" trace line names the branch that will run.
func describeWaitStatus(st unix.WaitStatus) string {
	switch {
	case st.Exited():
		return fmt.Sprintf("exited(code=%d)", st.ExitStatus())
	case st.Signaled():
		return fmt.Sprintf("signaled(sig=%s)", st.Signal())
	case st.Continued():
		return "continued"
	case st.Stopped():
		sig := st.StopSignal()
		switch {
		case sig == unix.SIGTRAP|0x80:
			return "syscall-stop"
		case sig == unix.SIGTRAP:
			switch st.TrapCause() {
			case unix.PTRACE_EVENT_FORK:
				return "event:FORK"
			case unix.PTRACE_EVENT_VFORK:
				return "event:VFORK"
			case unix.PTRACE_EVENT_CLONE:
				return "event:CLONE"
			case unix.PTRACE_EVENT_EXEC:
				return "event:EXEC"
			case unix.PTRACE_EVENT_VFORK_DONE:
				return "event:VFORK_DONE"
			case unix.PTRACE_EVENT_SECCOMP:
				return "event:SECCOMP"
			case unix.PTRACE_EVENT_EXIT:
				return "event:EXIT"
			case unix.PTRACE_EVENT_STOP:
				return "event:STOP"
			default:
				return "sigtrap(plain)"
			}
		default:
			if st.TrapCause() == unix.PTRACE_EVENT_STOP {
				return fmt.Sprintf("group-stop(sig=%s)", sig)
			}
			return fmt.Sprintf("signal-stop(sig=%s)", sig)
		}
	default:
		return fmt.Sprintf("unknown(0x%x)", uint32(st))
	}
}
