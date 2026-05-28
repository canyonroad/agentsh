//go:build linux

package ptrace

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// withTrace runs fn with the diagnostic forced on/off and slog captured to a
// buffer, restoring both afterwards. Returns the captured log text.
func withTrace(t *testing.T, on bool, fn func()) string {
	t.Helper()
	prevEnabled := ptraceTraceEnabled.Load()
	prevDefault := slog.Default()
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	ptraceTraceEnabled.Store(on)
	t.Cleanup(func() {
		ptraceTraceEnabled.Store(prevEnabled)
		slog.SetDefault(prevDefault)
	})
	fn()
	return buf.String()
}

func TestDescribeWaitStatus(t *testing.T) {
	cases := []struct {
		name   string
		status unix.WaitStatus
		want   string
	}{
		{"syscall-stop", unix.WaitStatus(uint32(unix.SIGTRAP|0x80)<<8 | 0x7f), "syscall-stop"},
		{"plain-sigtrap", unix.WaitStatus(uint32(unix.SIGTRAP)<<8 | 0x7f), "sigtrap(plain)"},
		{"event-exec", unix.WaitStatus(uint32(unix.PTRACE_EVENT_EXEC)<<16 | uint32(unix.SIGTRAP)<<8 | 0x7f), "event:EXEC"},
		{"event-seccomp", unix.WaitStatus(uint32(unix.PTRACE_EVENT_SECCOMP)<<16 | uint32(unix.SIGTRAP)<<8 | 0x7f), "event:SECCOMP"},
		{"event-clone", unix.WaitStatus(uint32(unix.PTRACE_EVENT_CLONE)<<16 | uint32(unix.SIGTRAP)<<8 | 0x7f), "event:CLONE"},
		{"exited", unix.WaitStatus(42 << 8), "exited(code=42)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeWaitStatus(tc.status); got != tc.want {
				t.Errorf("describeWaitStatus(0x%x) = %q, want %q", uint32(tc.status), got, tc.want)
			}
		})
	}
	group := describeWaitStatus(unix.WaitStatus(uint32(unix.SIGSTOP)<<8 | 0x7f))
	if !strings.HasPrefix(group, "signal-stop(") && !strings.HasPrefix(group, "group-stop(") {
		t.Errorf("SIGSTOP stop decoded as %q, want signal-stop/group-stop", group)
	}
	if killed := describeWaitStatus(unix.WaitStatus(uint32(unix.SIGKILL))); !strings.HasPrefix(killed, "signaled(") {
		t.Errorf("SIGKILL decoded as %q, want signaled(...)", killed)
	}
}

func TestReadProcStopState_SelfAndMissing(t *testing.T) {
	// Reading our own process: it's running, not traced by us.
	state, tracerPid, ok := readProcStopState(os.Getpid())
	if !ok {
		t.Fatal("readProcStopState(self) ok=false, want true")
	}
	// State should be a plausible scheduler state letter, never a stop ('t'/'T'),
	// since we're actively running this test.
	if state == 't' || state == 'T' {
		t.Errorf("self proc_state = %q, did not expect a stop state", state)
	}
	_ = tracerPid // 0 normally; nonzero only under an external debugger.

	// A pid that cannot exist must report ok=false.
	if _, _, ok := readProcStopState(1 << 30); ok {
		t.Error("readProcStopState(huge pid) ok=true, want false")
	}
}

func TestTrace_DisabledIsSilentAndInert(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	tr.tracees[100] = &TraceeState{TID: 100}
	beforeIdx := traceRingIdx.Load()

	out := withTrace(t, false, func() {
		traceWaitCall("run", -1)
		traceWaitRet("run", 0, 0, nil)
		tr.traceStop(100, unix.WaitStatus(uint32(unix.SIGTRAP|0x80)<<8|0x7f))
		tr.traceResume(100, "allowSyscall-cont", 0)
		tr.scanWedged()
		tr.reconcileProc()
	})

	if out != "" {
		t.Errorf("disabled trace must emit nothing, got:\n%s", out)
	}
	if traceRingIdx.Load() != beforeIdx {
		t.Error("disabled trace must not append to the ring")
	}
	if tr.tracees[100].awaitingResume {
		t.Error("disabled traceStop must not arm awaitingResume")
	}
}

func TestRing_AppendsAndDumps(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	tr.tracees[7] = &TraceeState{TID: 7}

	out := withTrace(t, true, func() {
		traceWaitCall("run", -1)
		traceWaitRet("run", 7, unix.WaitStatus(uint32(unix.PTRACE_EVENT_SECCOMP)<<16|uint32(unix.SIGTRAP)<<8|0x7f), nil)
		tr.traceStop(7, unix.WaitStatus(uint32(unix.PTRACE_EVENT_SECCOMP)<<16|uint32(unix.SIGTRAP)<<8|0x7f))
		tr.traceResume(7, "denySyscall", 0)
		tr.dumpTraceRing("unit-test")
	})

	for _, want := range []string{"DUMP BEGIN", "DUMP END", "wait_call", "wait_ret", "ev=stop", "ev=resume", "event:SECCOMP", "via=denySyscall"} {
		if !strings.Contains(out, want) {
			t.Errorf("ring dump missing %q; got:\n%s", want, out)
		}
	}
}

func TestScanWedged_v1_FlagsConsumedButUnresumedStop(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	tr.tracees[10] = &TraceeState{TID: 10, awaitingResume: true, lastStopDesc: "event:EXEC",
		lastStopAt: time.Now().Add(-3 * wedgeThreshold)}
	tr.tracees[11] = &TraceeState{TID: 11, awaitingResume: true, lastStopAt: time.Now()}
	tr.tracees[12] = &TraceeState{TID: 12, awaitingResume: false, lastStopAt: time.Now().Add(-3 * wedgeThreshold)}

	out := withTrace(t, true, func() { tr.scanWedged() })

	if !strings.Contains(out, "WEDGE(v1)") || !strings.Contains(out, "tid=10") {
		t.Errorf("scanWedged must flag the aged-armed tid 10; got:\n%s", out)
	}
	if strings.Contains(out, "tid=11") || strings.Contains(out, "tid=12") {
		t.Errorf("scanWedged must not flag recently-armed (11) or resumed (12); got:\n%s", out)
	}
	if !tr.tracees[10].wedgeLogged {
		t.Error("scanWedged must mark the flagged tracee wedgeLogged")
	}
}

func TestReconcileProc_RunningTraceeNotFlagged(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	// Use our own (running) pid as a stand-in tracee: /proc says state R and
	// TracerPid != us, so it must never be flagged as wedged.
	tr.tracees[os.Getpid()] = &TraceeState{TID: os.Getpid()}

	out := withTrace(t, true, func() {
		tr.reconcileProc()                              // first scan records lastProcScan
		tr.lastProcScan = time.Now().Add(-time.Second)  // bypass throttle
		tr.reconcileProc()
	})
	if strings.Contains(out, "WEDGE(v2)") {
		t.Errorf("a running tracee must not be flagged by reconcileProc; got:\n%s", out)
	}
}

func TestReconcileProc_Throttled(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	withTrace(t, true, func() {
		tr.lastProcScan = time.Time{}
		tr.reconcileProc()
		first := tr.lastProcScan
		if first.IsZero() {
			t.Fatal("reconcileProc must record lastProcScan on first run")
		}
		tr.reconcileProc() // within procScanInterval — must be a no-op
		if !tr.lastProcScan.Equal(first) {
			t.Error("reconcileProc must be throttled within procScanInterval")
		}
	})
}

func TestProcExists(t *testing.T) {
	if !procExists(os.Getpid()) {
		t.Error("procExists(self) = false, want true")
	}
	if procExists(1 << 30) {
		t.Error("procExists(huge pid) = true, want false")
	}
}

// TestRecoverVanishedTracees is the core #2 fix: a tracee that has vanished from
// /proc (its exit was reaped out from under the tracer) is reaped via handleExit,
// which unblocks the exec waiting on its exit-notify channel.
func TestRecoverVanishedTracees(t *testing.T) {
	tr := NewTracer(TracerConfig{})

	const goneTID = 1 << 30 // no such pid → procExists==false
	tr.tracees[goneTID] = &TraceeState{TID: goneTID, TGID: goneTID, MemFD: -1}
	exitCh, err := tr.RegisterExitNotify(goneTID)
	if err != nil {
		t.Fatalf("RegisterExitNotify: %v", err)
	}

	// A live tracee (our own pid) must NOT be reaped.
	livePID := os.Getpid()
	tr.tracees[livePID] = &TraceeState{TID: livePID, TGID: livePID, MemFD: -1}

	got := tr.recoverVanishedTracees()
	if got != 1 {
		t.Fatalf("recoverVanishedTracees() = %d, want 1 (only the vanished tracee)", got)
	}

	tr.mu.Lock()
	_, goneStillTracked := tr.tracees[goneTID]
	_, liveStillTracked := tr.tracees[livePID]
	tr.mu.Unlock()
	if goneStillTracked {
		t.Error("vanished tracee must be removed from t.tracees")
	}
	if !liveStillTracked {
		t.Error("live tracee must NOT be reaped")
	}

	// The waiter must be unblocked with ExitVanished so the exec doesn't hang.
	select {
	case es := <-exitCh:
		if es.Reason != ExitVanished {
			t.Errorf("exit notify Reason = %v, want ExitVanished", es.Reason)
		}
	default:
		t.Error("recovery must signal the exit-notify channel (exec would otherwise hang)")
	}
}

func TestRecoverVanishedTracees_NoneVanished(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	tr.tracees[os.Getpid()] = &TraceeState{TID: os.Getpid(), TGID: os.Getpid(), MemFD: -1}
	if got := tr.recoverVanishedTracees(); got != 0 {
		t.Errorf("recoverVanishedTracees() = %d, want 0 when all tracees are live", got)
	}
}

