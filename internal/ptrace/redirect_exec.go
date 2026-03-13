//go:build linux

package ptrace

import (
	"context"
	"errors"
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
	savedFD, err := t.injectFDIntoTracee(tid, savedRegs, injectFD, stubFDNum)
	if err != nil {
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
		t.cleanupInjectedFD(tid, savedRegs, stubFDNum, savedFD)
		t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
		return
	}
	origLen := len(origFilename) + 1

	stubPath := result.StubPath
	useScratch := len(stubPath)+1 > origLen
	if !useScratch {
		// Try in-place overwrite first.
		if err := t.writeString(tid, filenamePtr, stubPath); err != nil {
			slog.Info("redirectExec: in-place write failed, falling back to scratch", "tid", tid, "error", err)
			useScratch = true
		}
	}
	if useScratch {
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
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum, savedFD)
			t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
			return
		}

		scratchAddr, err := sp.allocate(len(stubPath) + 1)
		if err != nil {
			slog.Warn("redirectExec: scratch page full", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum, savedFD)
			t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
			return
		}

		if err := t.writeString(tid, scratchAddr, stubPath); err != nil {
			slog.Warn("redirectExec: write to scratch failed", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum, savedFD)
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
	filenameArg := regs.Arg(0) // save before SetReturnValue (clobbers x0/arg0 on arm64)
	injRegs := regs.Clone()
	injRegs.SetSyscallNr(unix.SYS_EXECVE)
	injRegs.SetReturnValue(int64(unix.SYS_EXECVE))
	injRegs.SetInstructionPointer(gadget)

	// For execveat, move filename to arg0 and argv to arg1 for SYS_EXECVE.
	if nr == unix.SYS_EXECVEAT {
		injRegs.SetArg(0, injRegs.Arg(1)) // filename (already rewritten above)
		injRegs.SetArg(1, regs.Arg(2))    // argv
		injRegs.SetArg(2, regs.Arg(3))    // envp
	} else {
		// On arm64, SetReturnValue writes x0 which is also arg0. Restore the
		// filename pointer which was clobbered.
		injRegs.SetArg(0, filenameArg)
	}

	if err := t.setRegs(tid, injRegs); err != nil {
		slog.Warn("redirectExec: setRegs failed", "tid", tid, "error", err)
		t.cleanupInjectedFD(tid, savedRegs, stubFDNum, savedFD)
		t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
		return
	}

	// Resume → gadget's syscall instruction → execve ENTRY stop.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		slog.Warn("redirectExec: resume to entry failed", "tid", tid, "error", err)
		t.cleanupInjectedFD(tid, savedRegs, stubFDNum, savedFD)
		t.resumeWithErrno(tid, savedRegs, int(unix.EACCES))
		return
	}
	if err := t.waitForSyscallStop(tid); err != nil {
		// Check if tracee is still tracked (non-exit failure).
		t.mu.Lock()
		tracked := t.tracees[tid] != nil
		t.mu.Unlock()
		if tracked {
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum, savedFD)
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
		state.PendingExecSavedFD = savedFD
	}
	t.mu.Unlock()

	// Use PtraceSyscall (not allowSyscall) to ensure we catch the exec
	// exit stop even in prefilter/seccomp mode. This is needed so the
	// PendingExecStubFD cleanup runs on exec failure.
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			t.handleExit(tid)
		} else {
			slog.Warn("redirectExec: PtraceSyscall failed, cleaning up stub fd",
				"tid", tid, "error", err)
			// Clean up the injected stub fd and restore any displaced fd.
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum, savedFD)
			// Clear pending state to avoid stale references.
			t.mu.Lock()
			if state := t.tracees[tid]; state != nil {
				state.PendingExecStubFD = -1
				state.PendingExecSavedFD = -1
				state.InSyscall = false
			}
			t.mu.Unlock()
		}
	}
}


// injectFDIntoTracee injects a file descriptor from the tracer into the tracee
// at the specified fd number, using pidfd_open + pidfd_getfd + dup3.
// If dstFDNum was already in use, it is saved via dup and the saved fd number
// is returned so the caller can restore it on failure. Returns -1 if the
// destination was not previously open.
func (t *Tracer) injectFDIntoTracee(tid int, savedRegs Regs, srcFD int, dstFDNum int) (savedFD int, err error) {
	tracerPID := os.Getpid()

	pidfd, err := t.injectSyscallRet(tid, savedRegs, unix.SYS_PIDFD_OPEN,
		uint64(tracerPID), 0)
	if err != nil {
		return -1, fmt.Errorf("pidfd_open: %w", err)
	}

	gotFD, err := t.injectSyscallRet(tid, savedRegs, unix.SYS_PIDFD_GETFD,
		pidfd, uint64(srcFD), 0)
	if err != nil {
		t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, pidfd)
		return -1, fmt.Errorf("pidfd_getfd: %w (if EPERM, check kernel.yama.ptrace_scope sysctl)", err)
	}

	// Check if dstFDNum is already open in the tracee. If so, save it via
	// dup so we can restore it if the redirect fails.
	savedFD = -1
	if gotFD != uint64(dstFDNum) {
		// fcntl(dstFDNum, F_GETFD) returns 0 or flags on success, -EBADF if not open.
		ret, _ := t.injectSyscall(tid, savedRegs, unix.SYS_FCNTL,
			uint64(dstFDNum), uint64(unix.F_GETFD))
		if ret >= 0 {
			// dstFDNum is open; save it via fcntl(F_DUPFD_CLOEXEC) so the
			// saved copy is automatically closed on successful exec and does
			// not leak into the stub process.
			dupRet, dupErr := t.injectSyscallRet(tid, savedRegs, unix.SYS_FCNTL,
				uint64(dstFDNum), uint64(unix.F_DUPFD_CLOEXEC), 0)
			if dupErr == nil {
				savedFD = int(dupRet)
			}
		}

		_, err = t.injectSyscallRet(tid, savedRegs, unix.SYS_DUP3,
			gotFD, uint64(dstFDNum), 0)
		if err != nil {
			if savedFD >= 0 {
				t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, uint64(savedFD))
			}
			t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, gotFD)
			t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, pidfd)
			return -1, fmt.Errorf("dup3: %w", err)
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
			return -1, fmt.Errorf("fcntl F_SETFD: %w", err)
		}
	}

	t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, pidfd)

	return savedFD, nil
}

// cleanupInjectedFD closes a previously injected fd in the tracee and restores
// any saved fd that was displaced.
func (t *Tracer) cleanupInjectedFD(tid int, savedRegs Regs, fdNum int, savedFD int) {
	if savedFD >= 0 {
		// Restore the original fd by dup3-ing the saved copy back.
		t.injectSyscall(tid, savedRegs, unix.SYS_DUP3,
			uint64(savedFD), uint64(fdNum), 0)
		t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, uint64(savedFD))
	} else {
		t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, uint64(fdNum))
	}
}
