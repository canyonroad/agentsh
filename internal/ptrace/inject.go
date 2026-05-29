//go:build linux

package ptrace

import (
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sys/unix"
)

// injectSyscall executes an arbitrary syscall inside a stopped tracee.
//
// Works from two stop states:
//
//   - Syscall-enter (InSyscall=true): modifies ORIG_RAX in place so the kernel
//     dispatches the injected syscall instead of the original. One PtraceSyscall
//     cycle reaches the exit stop where the return value is available.
//
//   - Between syscalls / exit stop (InSyscall=false): sets the instruction
//     pointer to a syscall gadget (the `syscall` instruction from the original
//     stop site). Two PtraceSyscall cycles: first to reach the gadget's
//     syscall-enter, second to reach its exit.
//
// After reading the return value, the original registers are restored and
// InSyscall is set to false (the tracee is always left at a syscall-exit stop).
func (t *Tracer) injectSyscall(tid int, savedRegs Regs, nr int, args ...uint64) (int64, error) {
	// Determine whether we're at a syscall-enter or between syscalls.
	atEntry := false
	t.mu.Lock()
	if state := t.tracees[tid]; state != nil {
		atEntry = state.InSyscall
	}
	t.mu.Unlock()

	if atEntry {
		return t.injectFromEntry(tid, savedRegs, nr, args...)
	}
	return t.injectFromExit(tid, savedRegs, nr, args...)
}

// injectFromEntry handles injection when the tracee is at a syscall-enter stop.
// Modifying ORIG_RAX replaces the current syscall. One cycle to exit.
func (t *Tracer) injectFromEntry(tid int, savedRegs Regs, nr int, args ...uint64) (int64, error) {
	injRegs := savedRegs.Clone()
	injRegs.SetSyscallNr(nr)
	// On amd64, the CPU reads the syscall number from RAX, not ORIG_RAX.
	// SetSyscallNr sets ORIG_RAX; we must also set RAX.
	injRegs.SetReturnValue(int64(nr))
	for i, v := range args {
		if i > 5 {
			break
		}
		injRegs.SetArg(i, v)
	}
	// Don't change IP — we're hijacking the current syscall entry.

	if err := t.setRegs(tid, injRegs); err != nil {
		return 0, fmt.Errorf("inject setRegs: %w", err)
	}

	var injectErr error
	defer func() {
		if injectErr != nil {
			if restoreErr := t.setRegs(tid, savedRegs); restoreErr != nil {
				slog.Warn("inject: failed to restore registers after error",
					"tid", tid, "injectErr", injectErr, "restoreErr", restoreErr)
			}
		}
	}()

	// Resume → kernel dispatches our modified syscall → exit stop.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		injectErr = fmt.Errorf("inject resume: %w", err)
		return 0, injectErr
	}
	if err := t.waitForSyscallExitStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-exit: %w", err)
		return 0, injectErr
	}

	retRegs, err := t.getRegs(tid)
	if err != nil {
		injectErr = fmt.Errorf("inject getRegs: %w", err)
		return 0, injectErr
	}
	if got := retRegs.SyscallNr(); got != nr {
		injectErr = fmt.Errorf("injected syscall %d did not execute (syscall_nr=%d at exit); stop misclassified (#369)", nr, got)
		return 0, injectErr
	}
	ret := retRegs.ReturnValue()

	// Restore original registers.
	if err := t.setRegs(tid, savedRegs); err != nil {
		return 0, fmt.Errorf("inject restore: %w", err)
	}

	// We consumed the enter→exit transition. Mark as exit state so
	// subsequent injections use the two-phase gadget protocol.
	t.mu.Lock()
	if state := t.tracees[tid]; state != nil {
		state.InSyscall = false
	}
	t.mu.Unlock()

	return ret, nil
}

// injectFromExit handles injection when the tracee is at a syscall-exit
// (between-syscall) stop. Uses a gadget: sets IP to the `syscall` instruction,
// two cycles (enter + exit).
func (t *Tracer) injectFromExit(tid int, savedRegs Regs, nr int, args ...uint64) (int64, error) {
	gadget := syscallGadgetAddr(savedRegs)

	insn := make([]byte, syscallInsnSize)
	if err := t.readBytes(tid, gadget, insn); err != nil {
		return 0, fmt.Errorf("inject gadget read @0x%x: %w", gadget, err)
	}
	if !isSyscallInsn(insn) {
		return 0, fmt.Errorf("inject gadget @0x%x not a syscall instruction (% x); stop misclassified (#369)", gadget, insn)
	}

	injRegs := savedRegs.Clone()
	injRegs.SetSyscallNr(nr)
	injRegs.SetReturnValue(int64(nr))
	for i, v := range args {
		if i > 5 {
			break
		}
		injRegs.SetArg(i, v)
	}
	injRegs.SetInstructionPointer(gadget)

	if err := t.setRegs(tid, injRegs); err != nil {
		return 0, fmt.Errorf("inject setRegs: %w", err)
	}

	var injectErr error
	defer func() {
		if injectErr != nil {
			if restoreErr := t.setRegs(tid, savedRegs); restoreErr != nil {
				slog.Warn("inject: failed to restore registers after error",
					"tid", tid, "injectErr", injectErr, "restoreErr", restoreErr)
			}
		}
	}()

	// Phase 1: resume → tracee returns to gadget → executes syscall → enter stop.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		injectErr = fmt.Errorf("inject resume-enter: %w", err)
		return 0, injectErr
	}
	if err := t.waitForSyscallStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-enter: %w", err)
		return 0, injectErr
	}

	// Phase 2: resume → kernel dispatches injected syscall → exit stop.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		injectErr = fmt.Errorf("inject resume-exit: %w", err)
		return 0, injectErr
	}
	if err := t.waitForSyscallExitStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-exit: %w", err)
		return 0, injectErr
	}

	retRegs, err := t.getRegs(tid)
	if err != nil {
		injectErr = fmt.Errorf("inject getRegs: %w", err)
		return 0, injectErr
	}
	if got := retRegs.SyscallNr(); got != nr {
		injectErr = fmt.Errorf("injected syscall %d did not execute (syscall_nr=%d at exit); stop misclassified (#369)", nr, got)
		return 0, injectErr
	}
	ret := retRegs.ReturnValue()

	if err := t.setRegs(tid, savedRegs); err != nil {
		return 0, fmt.Errorf("inject restore: %w", err)
	}

	return ret, nil
}

// injectMaxStopEvents bounds how many non-progress stops the inject waits
// tolerate before giving up, guarding against an unexpected stop storm.
const injectMaxStopEvents = 100

// waitForSyscallStop waits for the specified tid to hit a syscall stop.
// It uses waitpid with the specific tid to avoid consuming other tracees' events.
// Returns an error if the tracee exits during the wait, after performing
// bookkeeping cleanup.
//
// Uses WNOHANG polling with a deadline to prevent indefinite blocking if the
// expected stop is lost. Injected syscalls complete in microseconds, so the
// polling overhead is negligible in practice.
//
// Handles both TRACESYSGOOD mode (syscall stops report SIGTRAP|0x80) and
// prefilter/seccomp mode (syscall stops report plain SIGTRAP with no event).
func (t *Tracer) waitForSyscallStop(tid int) error {
	const (
		timeout   = 5 * time.Second
		pollDelay = 200 * time.Microsecond
	)
	deadline := time.Now().Add(timeout)
	stopEvents := 0
	for {
		// Refresh the Run-loop heartbeat: an active inject poll is real progress,
		// so a multi-second inject must not make the watchdog think the loop is
		// wedged and heal an unrelated tracee (#369 #2). The idle-spin wedge never
		// runs this loop, so it still goes stale and is healed.
		t.lastProgressNanos.Store(time.Now().UnixNano())
		if time.Now().After(deadline) {
			return fmt.Errorf("waitForSyscallStop tid %d: timed out after %v", tid, timeout)
		}
		var status unix.WaitStatus
		traceWaitCall("inject", tid)
		wpid, err := unix.Wait4(tid, &status, unix.WNOHANG|unix.WALL, nil)
		traceWaitRet("inject", wpid, status, err)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("wait4 tid %d: %w", tid, err)
		}
		if wpid == 0 {
			// Tracee hasn't stopped yet.
			time.Sleep(pollDelay)
			continue
		}
		if !status.Stopped() {
			if status.Exited() || status.Signaled() {
				// Clean up tracee bookkeeping before returning.
				t.handleExit(tid, status, nil, ExitNormal)
				return fmt.Errorf("tracee %d exited during injection", tid)
			}
			continue
		}

		sig := status.StopSignal()

		// TRACESYSGOOD mode: syscall stops have SIGTRAP|0x80.
		if sig == unix.SIGTRAP|0x80 {
			return nil
		}

		// PTRACE_EVENT_SECCOMP is a syscall-entry-equivalent stop.
		// Treat it as a syscall stop to keep injection phases in sync.
		if sig == unix.SIGTRAP && status.TrapCause() == unix.PTRACE_EVENT_SECCOMP {
			return nil
		}

		// Other ptrace event stops (fork, clone, exec, etc.) report
		// SIGTRAP with a non-zero TrapCause. Resume with signal 0.
		if sig == unix.SIGTRAP && status.TrapCause() != 0 {
			stopEvents++
			if stopEvents >= injectMaxStopEvents {
				return fmt.Errorf("waitForSyscallStop tid %d: exceeded %d non-progress stop events", tid, injectMaxStopEvents)
			}
			if err := unix.PtraceSyscall(tid, 0); err != nil {
				return fmt.Errorf("inject re-resume tid %d: %w", tid, err)
			}
			continue
		}

		// Real signal delivery: reinject the signal.
		stopEvents++
		if stopEvents >= injectMaxStopEvents {
			return fmt.Errorf("waitForSyscallStop tid %d: exceeded %d non-progress stop events", tid, injectMaxStopEvents)
		}
		if err := unix.PtraceSyscall(tid, int(sig)); err != nil {
			return fmt.Errorf("inject re-resume tid %d: %w", tid, err)
		}
	}
}

// waitForSyscallExitStop drives the tracee to a genuine syscall-EXIT stop and
// returns once there. When PTRACE_GET_SYSCALL_INFO is unavailable it degrades
// to waitForSyscallStop (legacy cycle-counting; unchanged for pre-5.3 kernels).
//
// Background (#369): on kernels that interleave PTRACE_EVENT_SECCOMP / entry
// stops with the PTRACE_SYSCALL enter/exit pairs (e.g. exe.dev 6.12.90), the
// fixed-cycle accounting could land the return-value read on an entry/seccomp
// stop, where rax holds the -ENOSYS entry placeholder rather than the syscall
// result. Injected syscalls run in isolation (the tracer controls the
// registers, so no other syscall executes between resumes), so the first EXIT
// stop reached is the injected syscall's exit; intervening entry/seccomp stops
// are resumed past.
func (t *Tracer) waitForSyscallExitStop(tid int) error {
	if err := t.waitForSyscallStop(tid); err != nil {
		return err
	}
	if !t.hasSyscallInfo {
		return nil // pre-5.3: cannot distinguish entry vs exit; keep legacy behavior
	}
	for i := 0; i < injectMaxStopEvents; i++ {
		op, err := t.syscallStopOp(tid)
		if err != nil || op == ptraceSyscallInfoNone {
			// Can't classify this stop; trust the legacy stop (no worse than before).
			return nil
		}
		if op == ptraceSyscallInfoExit {
			return nil
		}
		// Entry/seccomp stop — advance to the injected syscall's exit.
		if err := unix.PtraceSyscall(tid, 0); err != nil {
			return fmt.Errorf("inject advance-to-exit tid %d: %w", tid, err)
		}
		if err := t.waitForSyscallStop(tid); err != nil {
			return err // includes "tracee N exited during injection"
		}
	}
	return fmt.Errorf("waitForSyscallExitStop tid %d: no exit stop within %d events", tid, injectMaxStopEvents)
}

// injectSyscallRet is a convenience that returns an error if the injected
// syscall returned a negative errno value.
func (t *Tracer) injectSyscallRet(tid int, savedRegs Regs, nr int, args ...uint64) (uint64, error) {
	ret, err := t.injectSyscall(tid, savedRegs, nr, args...)
	if err != nil {
		return 0, err
	}
	if ret < 0 {
		return 0, fmt.Errorf("injected syscall %d returned %d (%s)", nr, ret, unix.Errno(-ret))
	}
	return uint64(ret), nil
}

// advancePastEntry nullifies the current syscall entry and advances the tracee
// to the EXIT stop. This allows subsequent injections to use the two-phase
// gadget protocol. The original registers are restored afterward and InSyscall
// is set to false.
func (t *Tracer) advancePastEntry(tid int, savedRegs Regs) error {
	nullRegs := savedRegs.Clone()
	nullRegs.SetSyscallNr(-1)
	nullRegs.SetReturnValue(-1)
	if err := t.setRegs(tid, nullRegs); err != nil {
		return fmt.Errorf("advance setRegs: %w", err)
	}
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		return fmt.Errorf("advance resume: %w", err)
	}
	if err := t.waitForSyscallExitStop(tid); err != nil {
		return fmt.Errorf("advance wait: %w", err)
	}
	if err := t.setRegs(tid, savedRegs); err != nil {
		return fmt.Errorf("advance restore: %w", err)
	}
	t.mu.Lock()
	if state := t.tracees[tid]; state != nil {
		state.InSyscall = false
	}
	t.mu.Unlock()
	return nil
}
