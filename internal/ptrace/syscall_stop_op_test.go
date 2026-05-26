//go:build integration && linux

package ptrace

import (
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSyscallStopOp_EntryThenExit verifies syscallStopOp classifies a
// syscall-entry stop as ENTRY(1) and the matching exit stop as EXIT(2).
// This is the load-bearing primitive for the inject EXIT-stop fix (#369).
func TestSyscallStopOp_EntryThenExit(t *testing.T) {
	requirePtrace(t)
	// ptrace requires all calls for one tracee to come from the same OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	// Initial stop is the exec/TRACEME stop; reap it.
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("initial wait4: %v", err)
	}

	tr := &Tracer{hasSyscallInfo: probePtraceSyscallInfo()}
	if !tr.hasSyscallInfo {
		t.Skip("PTRACE_GET_SYSCALL_INFO unsupported on this kernel")
	}

	// PTRACE_O_TRACESYSGOOD is required: without it, syscall stops appear as
	// plain SIGTRAP and PTRACE_GET_SYSCALL_INFO returns op=NONE (0) for all
	// stops. With it, syscall stops are SIGTRAP|0x80 and the kernel correctly
	// populates the op field.
	if err := unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESYSGOOD); err != nil {
		t.Fatalf("PTRACE_SETOPTIONS TRACESYSGOOD: %v", err)
	}

	// Advance to a syscall-entry stop.
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		t.Fatalf("ptracesyscall to entry: %v", err)
	}
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("wait4 entry: %v", err)
	}
	if !ws.Stopped() {
		t.Fatalf("expected stop at entry, status=%v", ws)
	}
	op, err := tr.syscallStopOp(pid)
	if err != nil {
		t.Fatalf("syscallStopOp entry: %v", err)
	}
	if op != ptraceSyscallInfoEntry {
		t.Fatalf("entry stop op = %d, want %d (ENTRY)", op, ptraceSyscallInfoEntry)
	}

	// Advance to the matching syscall-exit stop.
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		t.Fatalf("ptracesyscall to exit: %v", err)
	}
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("wait4 exit: %v", err)
	}
	if !ws.Stopped() {
		t.Fatalf("expected stop at exit, status=%v", ws)
	}
	op, err = tr.syscallStopOp(pid)
	if err != nil {
		t.Fatalf("syscallStopOp exit: %v", err)
	}
	if op != ptraceSyscallInfoExit {
		t.Fatalf("exit stop op = %d, want %d (EXIT)", op, ptraceSyscallInfoExit)
	}
}
