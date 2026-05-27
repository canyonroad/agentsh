//go:build integration && linux

package ptrace

import (
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// driveToEntryStop starts a ptraced child, reaps its initial trace stop, sets
// TRACESYSGOOD, and advances it to its first syscall-ENTRY stop. It returns the
// child pid; the caller is responsible for killing/reaping it. The OS thread
// must already be locked by the caller (ptrace requires same-thread calls).
func driveToEntryStop(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("initial wait4: %v", err)
	}
	if err := unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESYSGOOD); err != nil {
		t.Fatalf("PTRACE_SETOPTIONS TRACESYSGOOD: %v", err)
	}
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		t.Fatalf("ptracesyscall to entry: %v", err)
	}
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("wait4 entry: %v", err)
	}
	if !ws.Stopped() {
		t.Fatalf("expected stop at syscall-entry, status=%v", ws)
	}
	return pid
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

	pid := driveToEntryStop(t)

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
	if !ws.Stopped() {
		t.Fatalf("expected stop at syscall-exit, status=%v", ws)
	}
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

	pid := driveToEntryStop(t)
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

	// Inject getpid() through the gadget + orig_rax guards.
	ret, err := tr.injectFromExit(pid, savedRegs, unix.SYS_GETPID)
	if err != nil {
		t.Fatalf("injectFromExit(getpid) rejected a valid inject: %v", err)
	}
	if ret != int64(pid) {
		t.Fatalf("injected getpid returned %d, want tracee pid %d", ret, pid)
	}
}
