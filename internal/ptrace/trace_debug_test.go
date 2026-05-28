//go:build linux

package ptrace

import (
	"bytes"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// withTrace runs fn with the stop/resume diagnostic forced on and slog captured
// to a buffer, restoring both afterwards. Returns the captured log text.
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
		// stopped: low byte 0x7f, stop signal in bits 8-15.
		{"syscall-stop", unix.WaitStatus(uint32(unix.SIGTRAP|0x80)<<8 | 0x7f), "syscall-stop"},
		{"plain-sigtrap", unix.WaitStatus(uint32(unix.SIGTRAP)<<8 | 0x7f), "sigtrap(plain)"},
		// SIGTRAP + PTRACE event in bits 16-23.
		{"event-exec", unix.WaitStatus(uint32(unix.PTRACE_EVENT_EXEC)<<16 | uint32(unix.SIGTRAP)<<8 | 0x7f), "event:EXEC"},
		{"event-seccomp", unix.WaitStatus(uint32(unix.PTRACE_EVENT_SECCOMP)<<16 | uint32(unix.SIGTRAP)<<8 | 0x7f), "event:SECCOMP"},
		{"event-clone", unix.WaitStatus(uint32(unix.PTRACE_EVENT_CLONE)<<16 | uint32(unix.SIGTRAP)<<8 | 0x7f), "event:CLONE"},
		// exited: low 7 bits zero, code in bits 8-15.
		{"exited", unix.WaitStatus(42 << 8), "exited(code=42)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeWaitStatus(tc.status); got != tc.want {
				t.Errorf("describeWaitStatus(0x%x) = %q, want %q", uint32(tc.status), got, tc.want)
			}
		})
	}

	// A group-stop (non-SIGTRAP stop signal) and a kill signal decode to their
	// own categories without panicking — assert the prefix only (signal-name
	// strings are platform-dependent).
	group := describeWaitStatus(unix.WaitStatus(uint32(unix.SIGSTOP)<<8 | 0x7f))
	if !strings.HasPrefix(group, "signal-stop(") && !strings.HasPrefix(group, "group-stop(") {
		t.Errorf("SIGSTOP stop decoded as %q, want signal-stop/group-stop", group)
	}
	if killed := describeWaitStatus(unix.WaitStatus(uint32(unix.SIGKILL))); !strings.HasPrefix(killed, "signaled(") {
		t.Errorf("SIGKILL decoded as %q, want signaled(...)", killed)
	}
}

func TestTrace_DisabledIsSilentAndInert(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	tr.tracees[100] = &TraceeState{TID: 100}

	out := withTrace(t, false, func() {
		tr.traceStop(100, unix.WaitStatus(uint32(unix.SIGTRAP|0x80)<<8|0x7f))
		tr.traceResume(100, "allowSyscall-cont", 0)
		tr.scanWedged()
	})

	if out != "" {
		t.Errorf("disabled trace must emit nothing, got:\n%s", out)
	}
	// And it must not have armed the wedge detector.
	if tr.tracees[100].awaitingResume {
		t.Error("disabled traceStop must not arm awaitingResume")
	}
}

func TestTrace_StopArmsResumeClears(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	tr.tracees[200] = &TraceeState{TID: 200}

	withTrace(t, true, func() {
		tr.traceStop(200, unix.WaitStatus(uint32(unix.PTRACE_EVENT_SECCOMP)<<16|uint32(unix.SIGTRAP)<<8|0x7f))
		if !tr.tracees[200].awaitingResume {
			t.Fatal("traceStop must arm awaitingResume")
		}
		if tr.tracees[200].lastStopDesc != "event:SECCOMP" {
			t.Errorf("lastStopDesc = %q, want event:SECCOMP", tr.tracees[200].lastStopDesc)
		}
		tr.traceResume(200, "denySyscall", 0)
		if tr.tracees[200].awaitingResume {
			t.Error("traceResume must clear awaitingResume")
		}
	})
}

func TestTrace_TerminalStopDoesNotArm(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	tr.tracees[300] = &TraceeState{TID: 300}
	withTrace(t, true, func() {
		tr.traceStop(300, unix.WaitStatus(7<<8)) // exited(code=7)
		if tr.tracees[300].awaitingResume {
			t.Error("a terminal (exited) stop must not arm the wedge detector")
		}
	})
}

func TestScanWedged_FlagsConsumedButUnresumedStop(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	// Wedged: armed, aged past threshold.
	tr.tracees[10] = &TraceeState{TID: 10, awaitingResume: true, lastStopDesc: "event:EXEC",
		lastStopSeq: 99, lastStopAt: time.Now().Add(-3 * wedgeThreshold)}
	// Recently armed: must NOT flag yet.
	tr.tracees[11] = &TraceeState{TID: 11, awaitingResume: true, lastStopDesc: "syscall-stop",
		lastStopAt: time.Now()}
	// Resumed (parked/continued): must NOT flag.
	tr.tracees[12] = &TraceeState{TID: 12, awaitingResume: false, lastStopAt: time.Now().Add(-3 * wedgeThreshold)}

	out := withTrace(t, true, func() { tr.scanWedged() })

	if !strings.Contains(out, "WEDGE") || !strings.Contains(out, "tid=10") || !strings.Contains(out, "event:EXEC") {
		t.Errorf("scanWedged must flag the wedged tid 10 with its last stop; got:\n%s", out)
	}
	if strings.Contains(out, "tid=11") || strings.Contains(out, "tid=12") {
		t.Errorf("scanWedged must not flag recently-armed (11) or resumed (12) tracees; got:\n%s", out)
	}
	if !tr.tracees[10].wedgeLogged {
		t.Error("scanWedged must mark the flagged tracee wedgeLogged")
	}

	// Second scan must not re-flag the same wedge (wedgeLogged set).
	out2 := withTrace(t, true, func() { tr.scanWedged() })
	if strings.Contains(out2, "tid=10") {
		t.Errorf("scanWedged must not re-flag an already-reported wedge; got:\n%s", out2)
	}
}

func TestTrace_SeqMonotonic(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	tr.tracees[400] = &TraceeState{TID: 400}
	before := ptraceTraceSeq.Load()
	withTrace(t, true, func() {
		tr.traceStop(400, unix.WaitStatus(uint32(unix.SIGTRAP|0x80)<<8|0x7f))
		tr.traceResume(400, "allowSyscall-cont", 0)
	})
	if got := ptraceTraceSeq.Load(); got < before+2 {
		t.Errorf("trace seq did not advance by >=2: before=%d after=%d", before, got)
	}
	// Sanity: the counter is a real atomic (compile-time guard against accidental
	// type change away from atomic.Uint64).
	var _ *atomic.Uint64 = &ptraceTraceSeq
}
