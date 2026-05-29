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

// #369 #2 diagnostic instrumentation (v2 — wait-layer + /proc ground truth).
//
// The FUSE-on hang on kernel 6.12.90 leaves a child kernel-stopped-and-reapable
// while the tracer goroutine idles in the Run-loop select, with NO server thread
// in wait4. The rc10 trace (v1) proved the stop is lost UPSTREAM of handleStop:
// its WEDGE alarm (consumed-but-not-resumed) never fired, because the stop is
// never consumed by the Run loop in the first place. v1 also masked the hang —
// per-event slog added enough latency to suppress the timing race (Heisenbug).
//
// v2 fixes both:
//   - A lock-free in-memory RING BUFFER replaces per-event slog. All trace events
//     (wait4 call/return at every layer, stop dispatch, resume/park) are appended
//     by the single Run goroutine, so no locking is needed and the per-event cost
//     is a struct copy — low enough not to perturb the race. The ring is dumped
//     to slog only when an alarm fires (rare).
//   - A /proc RECONCILIATION alarm: on the idle tick (throttled), any tracee the
//     Run loop believes is running but that /proc reports kernel-stopped (State
//     t/T) with TracerPid==us is flagged and the ring dumped. This is ground
//     truth, independent of where the stop was lost — it fires even though the
//     stop never reached handleStop.
//
// Enabled only via AGENTSH_PTRACE_TRACE. When off, every hook is one relaxed
// atomic load and returns.

var (
	ptraceTraceEnabled atomic.Bool
	ptraceTraceSeq     atomic.Uint64
)

// wedgeThreshold is how long a tracee may sit with a consumed-but-unresumed stop
// before the (v1) idle-tick reporter flags it. Retained as a secondary signal.
const wedgeThreshold = 2 * time.Second

// procStuckThreshold is how long a tracee must remain kernel-stopped (per /proc)
// while we think it is running before the v2 reconciliation alarm fires.
const procStuckThreshold = 1500 * time.Millisecond

// procScanInterval throttles the /proc reconciliation scan so it adds negligible
// overhead and does not itself perturb the race (it runs only on idle ticks).
const procScanInterval = 500 * time.Millisecond

// traceEventKind names a ring entry's category.
type traceEventKind uint8

const (
	evWaitCall traceEventKind = iota // about to call wait4(arg)
	evWaitRet                        // wait4 returned
	evStop                           // a stop was dispatched to handleStop
	evResume                         // a resume/park was issued
	evNote                           // a milestone note (attach handshake, exit-notify, park)
)

func (k traceEventKind) String() string {
	switch k {
	case evWaitCall:
		return "wait_call"
	case evWaitRet:
		return "wait_ret"
	case evStop:
		return "stop"
	case evResume:
		return "resume"
	case evNote:
		return "note"
	default:
		return "?"
	}
}

// traceEvent is one ring entry. Fields are raw; formatting happens only on dump.
// String fields hold interned literals (the wait layer / resume site), so an
// append allocates nothing.
type traceEvent struct {
	seq    uint64
	mono   int64 // time.Now().UnixNano()
	kind   traceEventKind
	tid    int   // returned/affected tid (or wait pid arg for evWaitCall)
	arg    int64 // wait pid arg (evWaitCall), signal (evResume), or returned tid (evWaitRet)
	status uint32
	errno  int32
	layer  string // "run" | "inject" | "attach" — for wait events
	via    string // resume site
}

// traceRingSize holds enough events to retain well over a minute of trace under
// sustained load. erans's rc15 capture showed the previous 8192 retained only
// ~9s and WRAPPED before the ~35s FUSE-on cliff completed, losing the
// terminating sequence. ~64k entries (~5MB at ~80B/event) retains ~70s, so a
// cliff dump captures the full stall + the unblock (#369 #2).
const traceRingSize = 65536

// traceRing and traceRingIdx are written ONLY by the Run goroutine. Every append
// site runs there: the Run-loop Wait4, handleStop and its dispatch handlers, the
// resume primitives, and waitForSyscallStop (which is only ever called inline
// from the Run goroutine — by handleStop's inject paths and by the #399 startup
// self-probe, which runs during Run() startup, also on the Run goroutine). So no
// synchronization is needed. dumpTraceRing reads them, also from the Run goroutine
// (idle tick). The atomic on the index is solely so a future off-goroutine reader
// could snapshot it safely.
var (
	traceRing    [traceRingSize]traceEvent
	traceRingIdx atomic.Uint64
)

// initPtraceTrace enables the diagnostic when AGENTSH_PTRACE_TRACE is truthy.
func initPtraceTrace() {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AGENTSH_PTRACE_TRACE"))) {
	case "1", "true", "yes", "on":
		ptraceTraceEnabled.Store(true)
		slog.Info("ptrace-trace: wait-layer + /proc diagnostic enabled (#369 #2)")
	}
}

func ptraceTraceOn() bool { return ptraceTraceEnabled.Load() }

// ringAppend writes one event to the ring (Run goroutine only).
func ringAppend(ev traceEvent) {
	ev.seq = ptraceTraceSeq.Add(1)
	ev.mono = time.Now().UnixNano()
	i := traceRingIdx.Load()
	traceRing[i%traceRingSize] = ev
	traceRingIdx.Store(i + 1)
}

// traceWaitCall records that wait4(arg) is about to be called at layer.
func traceWaitCall(layer string, arg int) {
	if !ptraceTraceOn() {
		return
	}
	ringAppend(traceEvent{kind: evWaitCall, tid: arg, arg: int64(arg), layer: layer})
}

// traceWaitRet records a wait4 return: which tid (0 = none), status, errno.
func traceWaitRet(layer string, ret int, status unix.WaitStatus, err error) {
	if !ptraceTraceOn() {
		return
	}
	var errno int32
	if err != nil {
		if e, ok := err.(unix.Errno); ok {
			errno = int32(e)
		} else {
			errno = -1
		}
	}
	ringAppend(traceEvent{kind: evWaitRet, tid: ret, arg: int64(ret), status: uint32(status), errno: errno, layer: layer})
}

// traceStop records a stop dispatched from the Run loop and arms the (v1)
// wedge detector. Call with t.mu NOT held.
func (t *Tracer) traceStop(tid int, st unix.WaitStatus) {
	if !ptraceTraceOn() {
		return
	}
	ringAppend(traceEvent{kind: evStop, tid: tid, status: uint32(st)})

	desc := describeWaitStatus(st)
	terminal := st.Exited() || st.Signaled()
	t.mu.Lock()
	if s := t.tracees[tid]; s != nil {
		if terminal {
			s.awaitingResume = false
		} else {
			s.awaitingResume = true
			s.lastStopDesc = desc
			s.lastStopSeq = ptraceTraceSeq.Load()
			s.lastStopAt = time.Now()
			s.wedgeLogged = false
		}
	}
	t.mu.Unlock()
}

// traceResume records a resume/park and clears the (v1) wedge arm. Call with
// t.mu NOT held.
func (t *Tracer) traceResume(tid int, via string, sig int) {
	if !ptraceTraceOn() {
		return
	}
	ringAppend(traceEvent{kind: evResume, tid: tid, arg: int64(sig), via: via})
	t.mu.Lock()
	if s := t.tracees[tid]; s != nil {
		s.awaitingResume = false
	}
	t.mu.Unlock()
}

// traceNote records a milestone (attach handshake step, exit-notify event, idle
// park) to the ring. `layer` is the category ("attach"/"exit"/"idle"), `msg` a
// short literal, `id` the relevant pid/tid. Call from the Run goroutine.
func traceNote(layer, msg string, id int) {
	if !ptraceTraceOn() {
		return
	}
	ringAppend(traceEvent{kind: evNote, tid: id, layer: layer, via: msg})
}

// scanWedged is the v1 (consumed-but-not-resumed) alarm, retained as a secondary
// signal. rc10 showed it does not fire for #2, but if it ever does we want the
// ring. Call from the Run-loop idle branch.
func (t *Tracer) scanWedged() {
	if !ptraceTraceOn() {
		return
	}
	now := time.Now()
	var victims []int
	t.mu.Lock()
	for tid, s := range t.tracees {
		if s == nil || !s.awaitingResume || s.wedgeLogged {
			continue
		}
		if now.Sub(s.lastStopAt) < wedgeThreshold {
			continue
		}
		s.wedgeLogged = true
		victims = append(victims, tid)
	}
	t.mu.Unlock()
	if len(victims) > 0 {
		for _, tid := range victims {
			slog.Warn("ptrace-trace WEDGE(v1): stop consumed but never resumed (#369)", "tid", tid)
		}
		t.dumpTraceRing("wedge-v1")
	}
}

// reconcileProc is the v2 ground-truth alarm. On the idle tick (throttled to
// procScanInterval) it reads /proc for every tracee the Run loop believes is
// running; any that is kernel-stopped (State t/T) with TracerPid==us for longer
// than procStuckThreshold is flagged and the trace ring dumped. This catches the
// hang regardless of where the stop was lost, because /proc is ground truth.
func (t *Tracer) reconcileProc() {
	if !ptraceTraceOn() {
		return
	}
	now := time.Now()
	if now.Sub(t.lastProcScan) < procScanInterval {
		return
	}
	t.lastProcScan = now

	myPid := os.Getpid()

	// Snapshot tids (and skip intentionally parked tracees) under the lock.
	type cand struct{ tid int }
	var cands []cand
	t.mu.Lock()
	for tid := range t.tracees {
		if _, parked := t.parkedTracees[tid]; parked {
			continue
		}
		cands = append(cands, cand{tid})
	}
	t.mu.Unlock()

	var flagged []int
	for _, c := range cands {
		state, tracerPid, ok := readProcStopState(c.tid)
		stuck := ok && (state == 't' || state == 'T') && tracerPid == myPid

		t.mu.Lock()
		s := t.tracees[c.tid]
		if s == nil {
			t.mu.Unlock()
			continue
		}
		if !stuck {
			s.procStuckSince = time.Time{}
			t.mu.Unlock()
			continue
		}
		if s.procStuckSince.IsZero() {
			s.procStuckSince = now
		}
		fire := !s.procWedgeLogged && now.Sub(s.procStuckSince) >= procStuckThreshold
		if fire {
			s.procWedgeLogged = true
		}
		stuckMs := now.Sub(s.procStuckSince).Milliseconds()
		t.mu.Unlock()

		if fire {
			slog.Warn("ptrace-trace WEDGE(v2): tracee kernel-stopped but Run loop not progressing it (#369 #2)",
				"tid", c.tid, "proc_state", string(rune(state)), "tracer_pid", tracerPid, "stuck_ms", stuckMs)
			flagged = append(flagged, c.tid)
		}
	}
	if len(flagged) > 0 {
		t.dumpTraceRing(fmt.Sprintf("wedge-v2 tids=%v", flagged))
	}
}

// dumpTraceRing emits the whole ring oldest→newest to slog. Called only when an
// alarm fires, so the slog cost is acceptable. BEGIN/END markers bracket the dump
// for easy extraction; t0 is the first event's timestamp so offsets are relative.
func (t *Tracer) dumpTraceRing(reason string) {
	total := traceRingIdx.Load()
	if total == 0 {
		slog.Warn("ptrace-trace ring DUMP: empty", "reason", reason)
		return
	}
	n := uint64(traceRingSize)
	if total < n {
		n = total
	}
	start := total - n
	first := traceRing[start%traceRingSize]
	t0 := first.mono

	slog.Warn("ptrace-trace ring DUMP BEGIN", "reason", reason, "events", n)
	for i := start; i < total; i++ {
		ev := traceRing[i%traceRingSize]
		offUs := (ev.mono - t0) / 1000
		switch ev.kind {
		case evWaitCall:
			slog.Warn("ptrace-trace", "seq", ev.seq, "us", offUs, "ev", "wait_call", "layer", ev.layer, "pid_arg", ev.arg)
		case evWaitRet:
			slog.Warn("ptrace-trace", "seq", ev.seq, "us", offUs, "ev", "wait_ret", "layer", ev.layer,
				"ret_tid", ev.arg, "status", describeWaitStatus(unix.WaitStatus(ev.status)), "errno", ev.errno)
		case evStop:
			slog.Warn("ptrace-trace", "seq", ev.seq, "us", offUs, "ev", "stop", "tid", ev.tid,
				"status", describeWaitStatus(unix.WaitStatus(ev.status)))
		case evResume:
			slog.Warn("ptrace-trace", "seq", ev.seq, "us", offUs, "ev", "resume", "tid", ev.tid, "via", ev.via, "sig", ev.arg)
		case evNote:
			slog.Warn("ptrace-trace", "seq", ev.seq, "us", offUs, "ev", "note", "layer", ev.layer, "msg", ev.via, "id", ev.tid)
		}
	}
	slog.Warn("ptrace-trace ring DUMP END", "reason", reason)
}

// readProcStopState reports whether tracee tid is currently kernel-stopped from
// the OS's point of view, and who its tracer is. It reuses procStateChar (reads
// /proc/<tid>/stat State char) and readProcStatusField (TracerPid). ok is false
// if /proc could not be read (tracee vanished). State 't' = tracing stop,
// 'T' = stopped (job control).
func readProcStopState(tid int) (state byte, tracerPid int, ok bool) {
	sc := procStateChar(tid)
	if sc == "" {
		return 0, 0, false
	}
	tp, err := readProcStatusField(tid, "TracerPid:")
	if err != nil {
		return sc[0], 0, false
	}
	return sc[0], tp, true
}

// describeWaitStatus decodes a wait status into the same classification handleStop
// dispatches on, so each stop/wait line names the branch that will run.
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
