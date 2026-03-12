//go:build linux

package ptrace

import (
	"fmt"

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

	// Phase 1: resume -> wait for syscall-enter stop.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		return 0, fmt.Errorf("inject resume-enter: %w", err)
	}
	if err := t.waitForSyscallStop(tid); err != nil {
		return 0, fmt.Errorf("inject wait-enter: %w", err)
	}

	// Phase 2: resume -> wait for syscall-exit stop.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		return 0, fmt.Errorf("inject resume-exit: %w", err)
	}
	if err := t.waitForSyscallStop(tid); err != nil {
		return 0, fmt.Errorf("inject wait-exit: %w", err)
	}

	// Read return value.
	retRegs, err := t.getRegs(tid)
	if err != nil {
		return 0, fmt.Errorf("inject getRegs: %w", err)
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
func (t *Tracer) waitForSyscallStop(tid int) error {
	for {
		var status unix.WaitStatus
		_, err := unix.Wait4(tid, &status, 0, nil)
		if err != nil {
			return fmt.Errorf("wait4 tid %d: %w", tid, err)
		}
		if status.Stopped() && status.StopSignal() == unix.SIGTRAP|0x80 {
			return nil
		}
		// If the tracee received a signal during injection, suppress it
		// and continue waiting for the syscall stop.
		if status.Stopped() {
			if err := unix.PtraceSyscall(tid, 0); err != nil {
				return fmt.Errorf("inject re-resume tid %d: %w", tid, err)
			}
			continue
		}
		if status.Exited() || status.Signaled() {
			return fmt.Errorf("tracee %d exited during injection", tid)
		}
	}
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
