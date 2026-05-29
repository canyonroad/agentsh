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
// flags or heals a tracee that is not ptrace-stopped, nor a parked one.
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

	stuckSince := map[int]time.Time{}
	diagged := map[int]bool{}
	// Several sweeps; even far past the heal threshold nothing should fire.
	for i := 0; i < 3; i++ {
		tr.scanStuckTracees(stuckSince, diagged)
	}

	select {
	case <-selfCh:
		t.Error("a running tracee must not be healed")
	case <-parkedCh:
		t.Error("a parked tracee must not be healed")
	default:
	}
	if _, ok := stuckSince[parked]; ok {
		t.Error("parked tracee must be skipped (never recorded as stuck)")
	}
}
