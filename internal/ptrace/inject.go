//go:build linux

package ptrace

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

// injectSyscall executes an arbitrary syscall inside a stopped tracee.
//
// The tracee MUST be stopped at a syscall-enter or PTRACE_EVENT_SECCOMP stop
// so that the instruction pointer can be used to locate a syscall gadget.
//
// Sequence:
//  1. Save current registers (caller passes savedRegs)
//  2. Set up injected syscall (nr + up to 6 args)
//  3. Set IP to the syscall instruction gadget
//  4. Resume with PtraceSyscall -> wait for syscall-enter stop
//  5. Resume with PtraceSyscall -> wait for syscall-exit stop
//  6. Read return value
//  7. Restore original registers
//
// Returns the syscall return value, or an error if any ptrace operation fails.
func (t *Tracer) injectSyscall(tid int, savedRegs Regs, nr int, args ...uint64) (int64, error) {
	gadget := syscallGadgetAddr(savedRegs)

	// Build injection registers from a clone of saved state.
	injRegs := savedRegs.Clone()
	injRegs.SetSyscallNr(nr)
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

	// Best-effort register restore on any failure after setRegs succeeds.
	var injectErr error
	defer func() {
		if injectErr != nil {
			if restoreErr := t.setRegs(tid, savedRegs); restoreErr != nil {
				slog.Warn("inject: failed to restore registers after error",
					"tid", tid, "injectErr", injectErr, "restoreErr", restoreErr)
			}
		}
	}()

	// Phase 1: resume -> wait for syscall-enter stop.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		injectErr = fmt.Errorf("inject resume-enter: %w", err)
		return 0, injectErr
	}
	if err := t.waitForSyscallStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-enter: %w", err)
		return 0, injectErr
	}

	// Phase 2: resume -> wait for syscall-exit stop.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		injectErr = fmt.Errorf("inject resume-exit: %w", err)
		return 0, injectErr
	}
	if err := t.waitForSyscallStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-exit: %w", err)
		return 0, injectErr
	}

	// Read return value.
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

		// Ptrace event stops (fork, clone, exec, seccomp, etc.) report
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
