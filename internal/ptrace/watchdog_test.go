//go:build linux

package ptrace

import (
	"os"
	"testing"
	"time"
)

func TestProcSyscallSummary(t *testing.T) {
	if s := procSyscallSummary(os.Getpid()); s == "?" || s == "" {
		t.Errorf("procSyscallSummary(self) = %q, want a real /proc/self/syscall line", s)
	}
	if s := procSyscallSummary(1 << 30); s != "?" {
		t.Errorf("procSyscallSummary(huge pid) = %q, want %q", s, "?")
	}
}

// TestHealStuckTracee verifies the watchdog's off-Run-thread recovery: it fires
// the blocked exec's exit-notify with ExitVanished (so the exec returns) without
// calling handleExit. The Tgkill targets a nonexistent tgid (ESRCH, harmless).
func TestHealStuckTracee(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	const tid = 1 << 30 // nonexistent → Tgkill ESRCH, readProc* miss
	tr.tracees[tid] = &TraceeState{TID: tid, TGID: tid, MemFD: -1}
	exitCh, err := tr.RegisterExitNotify(tid)
	if err != nil {
		t.Fatalf("RegisterExitNotify: %v", err)
	}

	tr.healStuckTracee(tid)

	select {
	case es := <-exitCh:
		if es.Reason != ExitVanished {
			t.Errorf("heal exit Reason = %v, want ExitVanished", es.Reason)
		}
	default:
		t.Error("healStuckTracee must fire the exit-notify so the exec unblocks")
	}
	// The exit-notify registration must be consumed (LoadAndDelete), so a later
	// handleExit reap does not double-send.
	if _, ok := tr.exitNotify.Load(tid); ok {
		t.Error("healStuckTracee must LoadAndDelete the exit-notify registration")
	}
}

// TestScanStuckTracees_RunningAndParkedNotFlagged confirms the watchdog never
// flags or heals a tracee that is not ptrace-stopped, nor a parked one, nor one
// held in PTRACE_LISTEN (job-control group-stop).
func TestScanStuckTracees_RunningAndParkedNotFlagged(t *testing.T) {
	tr := NewTracer(TracerConfig{})

	// A "running" tracee: our own pid (State R/S, TracerPid 0 != us) → never stuck.
	self := os.Getpid()
	tr.tracees[self] = &TraceeState{TID: self, TGID: self, MemFD: -1}
	selfCh, _ := tr.RegisterExitNotify(self)

	// A parked tracee (keepStopped) must be skipped entirely.
	const parked = 1 << 30
	tr.tracees[parked] = &TraceeState{TID: parked, TGID: parked, MemFD: -1}
	tr.parkedTracees[parked] = struct{}{}
	parkedCh, _ := tr.RegisterExitNotify(parked)

	// A LISTEN'd (group-stopped) tracee must be skipped — never SIGKILL'd.
	const listening = (1 << 30) + 1
	tr.tracees[listening] = &TraceeState{TID: listening, TGID: listening, MemFD: -1, listening: true}
	listeningCh, _ := tr.RegisterExitNotify(listening)

	stuckSince := map[int]time.Time{}
	diagged := map[int]bool{}
	for i := 0; i < 3; i++ {
		tr.scanStuckTracees(stuckSince, diagged)
	}

	select {
	case <-selfCh:
		t.Error("a running tracee must not be healed")
	case <-parkedCh:
		t.Error("a parked tracee must not be healed")
	case <-listeningCh:
		t.Error("a PTRACE_LISTEN'd (group-stopped) tracee must not be healed")
	default:
	}
	if _, ok := stuckSince[parked]; ok {
		t.Error("parked tracee must be skipped (never recorded as stuck)")
	}
	if _, ok := stuckSince[listening]; ok {
		t.Error("listening tracee must be skipped (never recorded as stuck)")
	}
}

// TestLoopIdleFor confirms the heartbeat gate: a fresh heartbeat reads ~0, a
// stale one reads the elapsed time, and an uninitialized one reads 0 (don't heal).
func TestLoopIdleFor(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	now := time.Now()

	if d := tr.loopIdleFor(now); d != 0 {
		t.Errorf("uninitialized loopIdleFor = %v, want 0", d)
	}
	tr.lastProgressNanos.Store(now.UnixNano())
	if d := tr.loopIdleFor(now); d > 5*time.Millisecond {
		t.Errorf("fresh loopIdleFor = %v, want ~0", d)
	}
	tr.lastProgressNanos.Store(now.Add(-10 * time.Second).UnixNano())
	if d := tr.loopIdleFor(now); d < 9*time.Second {
		t.Errorf("stale loopIdleFor = %v, want ~10s", d)
	}
}
