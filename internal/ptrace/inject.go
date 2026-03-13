//go:build linux

package ptrace

import (
	"fmt"
	"log/slog"

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
	if err := t.waitForSyscallStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-exit: %w", err)
		return 0, injectErr
	}

	retRegs, err := t.getRegs(tid)
	if err != nil {
		injectErr = fmt.Errorf("inject getRegs: %w", err)
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
	if err := t.waitForSyscallStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-exit: %w", err)
		return 0, injectErr
	}

	retRegs, err := t.getRegs(tid)
	if err != nil {
		injectErr = fmt.Errorf("inject getRegs: %w", err)
		return 0, injectErr
	}
	ret := retRegs.ReturnValue()

	if err := t.setRegs(tid, savedRegs); err != nil {
		return 0, fmt.Errorf("inject restore: %w", err)
	}

	return ret, nil
}

// waitForSyscallStop waits for the specified tid to hit a syscall stop.
// It uses waitpid with the specific tid to avoid consuming other tracees' events.
// Returns an error if the tracee exits during the wait, after performing
// bookkeeping cleanup.
//
// Handles both TRACESYSGOOD mode (syscall stops report SIGTRAP|0x80) and
// prefilter/seccomp mode (syscall stops report plain SIGTRAP with no event).
func (t *Tracer) waitForSyscallStop(tid int) error {
	const maxAttempts = 100 // guard against infinite loop from unexpected stops
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var status unix.WaitStatus
		_, err := unix.Wait4(tid, &status, 0, nil)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("wait4 tid %d: %w", tid, err)
		}
		if !status.Stopped() {
			if status.Exited() || status.Signaled() {
				// Clean up tracee bookkeeping before returning.
				t.handleExit(tid)
				return fmt.Errorf("tracee %d exited during injection", tid)
			}
			continue
		}

		sig := status.StopSignal()

		// TRACESYSGOOD mode: syscall stops have SIGTRAP|0x80.
		if sig == unix.SIGTRAP|0x80 {
			return nil
		}

		// Non-TRACESYSGOOD mode: plain SIGTRAP with no ptrace event
		// is a syscall stop.
		if sig == unix.SIGTRAP && status.TrapCause() == 0 {
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
			if err := unix.PtraceSyscall(tid, 0); err != nil {
				return fmt.Errorf("inject re-resume tid %d: %w", tid, err)
			}
			continue
		}

		// Real signal delivery: reinject the signal.
		if err := unix.PtraceSyscall(tid, int(sig)); err != nil {
			return fmt.Errorf("inject re-resume tid %d: %w", tid, err)
		}
	}
	return fmt.Errorf("waitForSyscallStop tid %d: exceeded %d attempts", tid, maxAttempts)
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
	if err := t.waitForSyscallStop(tid); err != nil {
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
