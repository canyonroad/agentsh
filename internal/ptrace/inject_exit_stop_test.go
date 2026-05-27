//go:build integration && linux

package ptrace

import (
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// assertSyscallStop fails the test unless ws is a TRACESYSGOOD syscall-trap
// stop (SIGTRAP|0x80). Without this, a stray group/signal stop would make
// syscallStopOp read a non-syscall stop (op=NONE → fallback), and the test
// would assert against a meaningless classification instead of failing loudly.
func assertSyscallStop(t *testing.T, ws unix.WaitStatus, where string) {
	t.Helper()
	if !ws.Stopped() {
		t.Fatalf("%s: expected a stop, status=%v", where, ws)
	}
	if ws.StopSignal() != unix.SIGTRAP|0x80 {
		t.Fatalf("%s: expected syscall-trap stop (SIGTRAP|0x80), got signal %v", where, ws.StopSignal())
	}
}

// driveToEntryStop starts a ptraced child, reaps its initial trace stop, sets
// TRACESYSGOOD|EXITKILL, and advances it to its first syscall-ENTRY stop. It
// returns the child pid and a cleanup func that kills+reaps it. The OS thread
// must already be locked by the caller (ptrace requires same-thread calls), and
// the caller must `defer cleanup()` AFTER its `defer runtime.UnlockOSThread()`
// so the reaping wait4 runs on the still-locked tracer thread (LIFO order);
// EXITKILL additionally bounds the child's lifetime to this process.
func driveToEntryStop(t *testing.T) (pid int, cleanup func()) {
	t.Helper()
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid = cmd.Process.Pid
	cleanup = func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }

	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		cleanup()
		t.Fatalf("initial wait4: %v", err)
	}
	if err := unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_EXITKILL); err != nil {
		cleanup()
		t.Fatalf("PTRACE_SETOPTIONS: %v", err)
	}
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		cleanup()
		t.Fatalf("ptracesyscall to entry: %v", err)
	}
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		cleanup()
		t.Fatalf("wait4 entry: %v", err)
	}
	assertSyscallStop(t, ws, "syscall-entry")
	return pid, cleanup
}

// TestAtSyscallExitStop_LiveTracee exercises the authoritative #369 trigger
// predicate against a real tracee: it must report not-exit at a syscall-ENTRY
// stop and exit at the matching EXIT stop, independent of the inSyscall
// fallback argument (which it should ignore when PTRACE_GET_SYSCALL_INFO works).
func TestAtSyscallExitStop_LiveTracee(t *testing.T) {
	requirePtrace(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tr := &Tracer{hasSyscallInfo: probePtraceSyscallInfo()}
	if !tr.hasSyscallInfo {
		t.Skip("PTRACE_GET_SYSCALL_INFO unsupported on this kernel")
	}

	pid, cleanup := driveToEntryStop(t)
	defer cleanup()

	// At the entry stop, atSyscallExitStop must return false even when the
	// (deliberately wrong) fallback bool says true — proving it uses the op.
	if tr.atSyscallExitStop(pid, true) {
		t.Fatal("atSyscallExitStop reported EXIT at a syscall-ENTRY stop")
	}

	// Advance to the matching exit stop.
	var ws unix.WaitStatus
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		t.Fatalf("ptracesyscall to exit: %v", err)
	}
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("wait4 exit: %v", err)
	}
	assertSyscallStop(t, ws, "syscall-exit")
	// At the exit stop, it must return true even when the fallback bool says
	// false.
	if !tr.atSyscallExitStop(pid, false) {
		t.Fatal("atSyscallExitStop reported not-EXIT at a syscall-EXIT stop")
	}
}

// TestInjectFromExit_BenignSyscallThroughGuards proves the #369 Task 2 guards
// (gadget-is-a-syscall-insn + injected-syscall-executed) do NOT reject a valid
// inject on a healthy kernel: a getpid() injected from a between-syscalls EXIT
// stop returns the tracee's own pid. This mirrors the production
// ensureScratchPage path (advancePastEntry -> injectFromExit gadget protocol).
func TestInjectFromExit_BenignSyscallThroughGuards(t *testing.T) {
	requirePtrace(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tr := NewTracer(TracerConfig{})
	tr.hasSyscallInfo = probePtraceSyscallInfo()
	if !tr.hasSyscallInfo {
		t.Skip("PTRACE_GET_SYSCALL_INFO unsupported on this kernel")
	}

	pid, cleanup := driveToEntryStop(t)
	defer cleanup()
	tr.mu.Lock()
	tr.tracees[pid] = &TraceeState{TID: pid, TGID: pid, InSyscall: false, MemFD: -1}
	tr.mu.Unlock()

	// Capture entry regs and advance to a between-syscalls EXIT stop so the
	// injectFromExit gadget protocol applies (RIP-2 is the real `syscall` insn).
	entryRegs, err := tr.getRegs(pid)
	if err != nil {
		t.Fatalf("getRegs at entry: %v", err)
	}
	if err := tr.advancePastEntry(pid, entryRegs); err != nil {
		t.Fatalf("advancePastEntry: %v", err)
	}
	savedRegs, err := tr.getRegs(pid)
	if err != nil {
		t.Fatalf("getRegs after advancePastEntry: %v", err)
	}

	// Inject getpid() through the gadget + syscall_nr guards.
	ret, err := tr.injectFromExit(pid, savedRegs, unix.SYS_GETPID)
	if err != nil {
		t.Fatalf("injectFromExit(getpid) rejected a valid inject: %v", err)
	}
	if ret != int64(pid) {
		t.Fatalf("injected getpid returned %d, want tracee pid %d", ret, pid)
	}
}
