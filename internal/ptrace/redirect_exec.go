//go:build linux

package ptrace

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const stubFDNum = 100 // Well-known fd number for stub communication

// redirectExec redirects an execve syscall to a stub binary.
//
// Sequence:
//  1. Advance past the original execve entry (nullify it) so helper
//     injections use the two-phase gadget protocol from EXIT state.
//  2. Create socketpair in tracer for stub communication
//  3. Inject tracer's socketpair fd into tracee at fd 100 via pidfd_getfd
//  4. Write stub path into tracee memory
//  5. Re-inject execve via gadget, advance to its ENTRY stop, and resume —
//     the main tracer loop handles the exec event from there.
func (t *Tracer) redirectExec(ctx context.Context, tid int, regs Regs, result ExecResult) {
	if result.StubPath == "" {
		slog.Warn("redirectExec: no stub path, denying", "tid", tid)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	savedRegs := regs.Clone()
	nr := regs.SyscallNr()

	// Advance past the original execve entry to EXIT state. All helper
	// injections will use the two-phase gadget protocol, and the final
	// execve is re-injected explicitly via gadget at the end.
	if err := t.advancePastEntry(tid, savedRegs); err != nil {
		slog.Warn("redirectExec: advance past entry failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	// Step 1: Create socketpair in tracer process.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		slog.Warn("redirectExec: socketpair failed", "tid", tid, "error", err)
		t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
		return
	}
	tracerFD := fds[0]
	injectFD := fds[1]
	// TODO: tracerFD should be kept alive in tracer state until the stub
	// handshake/IPC is complete. Currently closed immediately because the
	// stub communication protocol is not yet implemented. Once implemented,
	// tracerFD must be stored in session/tracee state and closed during
	// explicit cleanup.
	defer syscall.Close(tracerFD)
	defer syscall.Close(injectFD)

	// Step 2: Inject fd into tracee via pidfd_getfd.
	if err := t.injectFDIntoTracee(tid, savedRegs, injectFD, stubFDNum); err != nil {
		slog.Warn("redirectExec: fd injection failed", "tid", tid, "error", err)
		t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
		return
	}

	// Step 3: Write stub path into tracee memory.
	var filenamePtr uint64
	if nr == unix.SYS_EXECVEAT {
		filenamePtr = regs.Arg(1)
	} else {
		filenamePtr = regs.Arg(0)
	}

	origFilename, err := t.readString(tid, filenamePtr, 4096)
	if err != nil {
		slog.Warn("redirectExec: read original filename failed", "tid", tid, "error", err)
		t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
		t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
		return
	}
	origLen := len(origFilename) + 1

	stubPath := result.StubPath
	if len(stubPath)+1 <= origLen {
		if err := t.writeString(tid, filenamePtr, stubPath); err != nil {
			slog.Warn("redirectExec: write stub path failed", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
			t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
			return
		}
	} else {
		t.mu.Lock()
		state := t.tracees[tid]
		tgid := tid
		if state != nil {
			tgid = state.TGID
		}
		t.mu.Unlock()

		sp, err := t.ensureScratchPage(tid, tgid, savedRegs)
		if err != nil {
			slog.Warn("redirectExec: scratch alloc failed", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
			t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
			return
		}

		scratchAddr, err := sp.allocate(len(stubPath) + 1)
		if err != nil {
			slog.Warn("redirectExec: scratch page full", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
			t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
			return
		}

		if err := t.writeString(tid, scratchAddr, stubPath); err != nil {
			slog.Warn("redirectExec: write to scratch failed", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
			t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
			return
		}

		if nr == unix.SYS_EXECVEAT {
			regs.SetArg(1, scratchAddr)
		} else {
			regs.SetArg(0, scratchAddr)
		}
	}

	// Step 4: Inject the execve via gadget and advance to its ENTRY stop.
	// Always normalize to SYS_EXECVE with the stub path as arg0, regardless
	// of whether the original call was execve or execveat. This avoids
	// edge cases like AT_EMPTY_PATH or non-AT_FDCWD dirfds that could
	// bypass the redirect.
	gadget := syscallGadgetAddr(savedRegs)
	injRegs := regs.Clone()
	injRegs.SetSyscallNr(unix.SYS_EXECVE)
	injRegs.SetReturnValue(int64(unix.SYS_EXECVE))
	injRegs.SetInstructionPointer(gadget)

	// For execveat, move filename to arg0 and argv to arg1 for SYS_EXECVE.
	if nr == unix.SYS_EXECVEAT {
		injRegs.SetArg(0, injRegs.Arg(1)) // filename (already rewritten above)
		injRegs.SetArg(1, regs.Arg(2))    // argv
		injRegs.SetArg(2, regs.Arg(3))    // envp
	}

	if err := t.setRegs(tid, injRegs); err != nil {
		slog.Warn("redirectExec: setRegs failed", "tid", tid, "error", err)
		t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
		t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
		return
	}

	// Resume → gadget's syscall instruction → execve ENTRY stop.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		slog.Warn("redirectExec: resume to entry failed", "tid", tid, "error", err)
		t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
		t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
		return
	}
	if err := t.waitForSyscallStop(tid); err != nil {
		// Check if tracee is still tracked (non-exit failure).
		t.mu.Lock()
		tracked := t.tracees[tid] != nil
		t.mu.Unlock()
		if tracked {
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
			t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
		}
		return
	}

	// Now at the injected execve ENTRY. Update tracking and let the
	// main tracer loop handle the exec event and exit stop.
	t.mu.Lock()
	if state := t.tracees[tid]; state != nil {
		state.InSyscall = true
		// Track the injected stub fd so it can be cleaned up if the
		// exec fails (no PTRACE_EVENT_EXEC, just an error return).
		state.PendingExecStubFD = stubFDNum
	}
	t.mu.Unlock()

	t.allowSyscall(tid)
}


// injectFDIntoTracee injects a file descriptor from the tracer into the tracee
// at the specified fd number, using pidfd_open + pidfd_getfd + dup3.
func (t *Tracer) injectFDIntoTracee(tid int, savedRegs Regs, srcFD int, dstFDNum int) error {
	tracerPID := os.Getpid()

	pidfd, err := t.injectSyscallRet(tid, savedRegs, unix.SYS_PIDFD_OPEN,
		uint64(tracerPID), 0)
	if err != nil {
		return fmt.Errorf("pidfd_open: %w", err)
	}

	gotFD, err := t.injectSyscallRet(tid, savedRegs, unix.SYS_PIDFD_GETFD,
		pidfd, uint64(srcFD), 0)
	if err != nil {
		t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, pidfd)
		return fmt.Errorf("pidfd_getfd: %w (if EPERM, check kernel.yama.ptrace_scope sysctl)", err)
	}

	if gotFD != uint64(dstFDNum) {
		_, err = t.injectSyscallRet(tid, savedRegs, unix.SYS_DUP3,
			gotFD, uint64(dstFDNum), 0)
		if err != nil {
			t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, gotFD)
			t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, pidfd)
			return fmt.Errorf("dup3: %w", err)
		}
		t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, gotFD)
	} else {
		// pidfd_getfd returns the fd with FD_CLOEXEC set. dup3 would clear
		// it (flags=0), but since we skipped dup3, explicitly clear it so
		// the fd survives execve.
		_, err = t.injectSyscallRet(tid, savedRegs, unix.SYS_FCNTL,
			gotFD, uint64(unix.F_SETFD), 0)
		if err != nil {
			t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, gotFD)
			t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, pidfd)
			return fmt.Errorf("fcntl F_SETFD: %w", err)
		}
	}

	t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, pidfd)

	return nil
}

// cleanupInjectedFD closes a previously injected fd in the tracee.
func (t *Tracer) cleanupInjectedFD(tid int, savedRegs Regs, fdNum int) {
	t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, uint64(fdNum))
}
