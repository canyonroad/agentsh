//go:build linux

package ptrace

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// #369 #2: external wedge watchdog.
//
// Every prior diagnostic/fix (rc10–rc13) observed and acted from INSIDE the Run
// loop — which is exactly the goroutine that parks when the wedge occurs, so it
// was structurally blind: WEDGE alarms never fired, ring dumps never triggered,
// and the ECHILD recovery was never reached. This watchdog runs on its OWN
// goroutine and detects the wedge by /proc GROUND TRUTH, independent of where
// the Run loop is parked.
//
// Mechanism: a tracee we still track that the kernel reports ptrace-stopped
// (State 't'/'T') with TracerPid == our process, for longer than a threshold,
// means the Run loop is failing to advance it (a stop was consumed but never
// resumed, or never re-reported by wait4). Normal ptrace stops are serviced in
// microseconds; seconds in 't' is always a wedge (parked/keep-stopped tracees,
// which legitimately sit stopped awaiting approval/resume, are excluded).
//
// On detection the watchdog (1) logs it and, when AGENTSH_PTRACE_TRACE is set,
// dumps the trace ring to pin the mechanism, and (2) self-heals after a longer
// grace period: SIGKILL the wedged tracee (releasing the leaked ptrace-stop so
// the Run loop reaps it and runs proper cleanup on its own thread) and fire the
// blocked exec's exit-notify directly, so the exec returns instead of hanging.

const (
	watchdogTick      = 1 * time.Second
	watchdogDiagAfter = 3 * time.Second  // log + ring dump (observe)
	watchdogHealAfter = 15 * time.Second // SIGKILL + unblock the waiting exec (recover)
	// watchdogLoopStale gates healing on the Run loop genuinely not progressing.
	// A busy-but-progressing loop refreshes lastProgressNanos on every stop, so a
	// slow-but-alive loop never trips the killer (only a wedged one does).
	watchdogLoopStale = 3 * time.Second
	// watchdogExecStallDump is how long an exec's exit-notify may stay pending
	// before the watchdog dumps the trace ring (capture-only, #369 #2). A normal
	// exec resolves in ms; seconds means it is cliffing. The dump fires once
	// during the stall and again when it resolves, so erans captures both the
	// steady-state spin and the terminating sequence the ~35s cliff ends with.
	watchdogExecStallDump = 10 * time.Second
)

// runStuckTraceeWatchdog is the watchdog goroutine. It must NOT LockOSThread:
// it has to stay schedulable on any OS thread, independent of the (possibly
// wedged) Run-loop thread. Started from Run.
func (t *Tracer) runStuckTraceeWatchdog(ctx context.Context) {
	ticker := time.NewTicker(watchdogTick)
	defer ticker.Stop()
	stuckSince := make(map[int]time.Time)    // tid -> first observed ptrace-stuck
	diagged := make(map[int]bool)            // tid -> diagnostic already emitted
	execFirstSeen := make(map[int]time.Time) // pid -> first observed pending exit-notify
	execDumped := make(map[int]bool)         // pid -> stall dump already emitted
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopped:
			return
		case <-ticker.C:
		}
		t.scanStuckTracees(stuckSince, diagged)
		t.scanStalledExecs(execFirstSeen, execDumped)
	}
}

// scanStalledExecs is a capture-only diagnostic (#369 #2): it watches pending
// exit-notify registrations (one per in-flight exec) and dumps the trace ring
// when one stays pending past watchdogExecStallDump — i.e. an exec is cliffing.
// It dumps once during the stall (steady-state spin) and again when the exec
// finally resolves (the terminating sequence). No-op when tracing is off (the
// ring is empty). Runs on the watchdog goroutine; the maps carry state across
// ticks. Changes nothing about enforcement or recovery.
func (t *Tracer) scanStalledExecs(firstSeen map[int]time.Time, dumped map[int]bool) {
	if !ptraceTraceOn() {
		return
	}
	now := time.Now()
	live := make(map[int]bool)
	t.exitNotify.Range(func(k, _ any) bool {
		pid, ok := k.(int)
		if !ok {
			return true
		}
		live[pid] = true
		if firstSeen[pid].IsZero() {
			firstSeen[pid] = now
		}
		if !dumped[pid] && now.Sub(firstSeen[pid]) >= watchdogExecStallDump {
			dumped[pid] = true
			slog.Warn("ptrace WATCHDOG: exec stalled — exit-notify pending past threshold, dumping trace ring (#369 #2)",
				"pid", pid, "stalled_ms", now.Sub(firstSeen[pid]).Milliseconds(),
				"run_thread_tid", t.runThreadTID)
			t.dumpTraceRing(fmt.Sprintf("exec-stall pid=%d", pid))
		}
		return true
	})
	for pid := range firstSeen {
		if live[pid] {
			continue
		}
		// The exec resolved. If it had stalled, capture the terminating sequence
		// (what finally unblocked it — the ~35s cliff's end).
		if dumped[pid] {
			slog.Warn("ptrace WATCHDOG: stalled exec resolved, dumping terminating trace ring (#369 #2)", "pid", pid)
			t.dumpTraceRing(fmt.Sprintf("exec-stall-resolved pid=%d", pid))
		}
		delete(firstSeen, pid)
		delete(dumped, pid)
	}
}

// scanStuckTracees does one /proc sweep of tracked (non-parked) tracees, logging
// and healing any that have been ptrace-stopped past the thresholds. The
// stuckSince/diagged maps carry state across ticks (watchdog goroutine only).
func (t *Tracer) scanStuckTracees(stuckSince map[int]time.Time, diagged map[int]bool) {
	myPid := os.Getpid()
	now := time.Now()

	// Snapshot tracked tids, skipping intentionally-parked tracees (keepStopped
	// for the cgroup hook, or parked awaiting approval) and tracees held in
	// PTRACE_LISTEN (job-control group-stops) — all of those are stopped on
	// purpose and must not be reaped by the watchdog.
	t.mu.Lock()
	tids := make([]int, 0, len(t.tracees))
	for tid, s := range t.tracees {
		if _, parked := t.parkedTracees[tid]; parked {
			continue
		}
		if s != nil && s.listening {
			continue
		}
		tids = append(tids, tid)
	}
	t.mu.Unlock()

	live := make(map[int]bool, len(tids))
	for _, tid := range tids {
		live[tid] = true
		state, tracerPid, ok := readProcStopState(tid)
		stuck := ok && (state == 't' || state == 'T') && tracerPid == myPid
		if !stuck {
			delete(stuckSince, tid)
			delete(diagged, tid)
			continue
		}
		if stuckSince[tid].IsZero() {
			stuckSince[tid] = now
		}
		dur := now.Sub(stuckSince[tid])

		if dur >= watchdogDiagAfter && !diagged[tid] {
			diagged[tid] = true
			slog.Warn("ptrace WATCHDOG: tracee ptrace-stopped but Run loop not advancing it (#369 #2)",
				"tid", tid, "proc_state", string(rune(state)),
				"syscall", procSyscallSummary(tid), "stuck_ms", dur.Milliseconds(),
				"run_thread_tid", t.runThreadTID, "watchdog_tid", unix.Gettid(),
				"loop_progress_ms_ago", t.loopIdleFor(now).Milliseconds())
			if ptraceTraceOn() {
				t.dumpTraceRing(fmt.Sprintf("watchdog tid=%d stuck=%dms", tid, dur.Milliseconds()))
			}
		}

		// Heal only when (a) the tracee has been stuck long enough, (b) the Run
		// loop is itself not progressing (so a slow-but-alive loop is never the
		// trigger), and (c) the loop is not actively handling THIS tid right now.
		if dur >= watchdogHealAfter &&
			t.loopIdleFor(now) >= watchdogLoopStale &&
			t.currentHandlingTID.Load() != int64(tid) {
			t.healStuckTracee(tid)
			delete(stuckSince, tid)
			delete(diagged, tid)
		}
	}

	// Drop bookkeeping for tids no longer tracked.
	for tid := range stuckSince {
		if !live[tid] {
			delete(stuckSince, tid)
			delete(diagged, tid)
		}
	}
}

// healStuckTracee force-recovers a wedged tracee from OFF the Run thread. It does
// only goroutine-safe operations: Tgkill (no ptrace ownership required) and a
// sync.Map LoadAndDelete + non-blocking channel send. It deliberately does NOT
// call handleExit (which mutates Run-goroutine-only state like t.fds and the
// scratch maps); instead the SIGKILL makes the tracee exit, and the Run loop's
// wait4 reaps it and runs handleExit properly on its own thread. The direct
// exit-notify fire unblocks the waiting exec immediately, and LoadAndDelete
// makes the later handleExit a no-op so there is no double-send.
func (t *Tracer) healStuckTracee(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	tgid := tid
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	slog.Warn("ptrace WATCHDOG: force-recovering wedged tracee — SIGKILL + unblock exec (#369 #2)",
		"tid", tid, "tgid", tgid)

	// Release the leaked ptrace-stop. SIGKILL is fatal even under ptrace; the
	// Run loop's wait4 then sees the exit and cleans up on its own thread.
	if err := unix.Tgkill(tgid, tid, unix.SIGKILL); err != nil {
		slog.Warn("ptrace WATCHDOG: SIGKILL failed", "tid", tid, "tgid", tgid, "error", err)
	}

	// Unblock the blocked exec immediately rather than waiting for the reap.
	if v, ok := t.exitNotify.LoadAndDelete(tgid); ok {
		select {
		case v.(chan ExitStatus) <- ExitStatus{PID: tgid, Reason: ExitVanished}:
		default:
		}
	}
}

// procSyscallSummary reads /proc/<tid>/syscall for the watchdog diagnostic: the
// current syscall number + args while in-kernel, or "running"/"-1 ..." between
// syscalls. Best-effort; returns "?" on error.
func procSyscallSummary(tid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(tid) + "/syscall")
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}

// loopIdleFor reports how long since the Run loop last dispatched a stop. The
// watchdog uses it to heal only when the loop is genuinely not progressing — a
// busy-but-progressing loop refreshes the heartbeat on every stop. Initialized
// at Run start, so it is non-zero whenever the watchdog runs.
func (t *Tracer) loopIdleFor(now time.Time) time.Duration {
	last := t.lastProgressNanos.Load()
	if last == 0 {
		return 0 // not yet initialized; treat as just-progressed (do not heal)
	}
	return now.Sub(time.Unix(0, last))
}
