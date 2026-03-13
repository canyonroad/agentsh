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
//  1. Create socketpair in tracer for stub communication
//  2. Inject tracer's socketpair fd into tracee at fd 100 via pidfd_getfd
//  3. Write stub path into tracee memory
//  4. Update registers so kernel executes execve with stub path
//  5. Resume — stub runs and connects back to tracer via fd 100
func (t *Tracer) redirectExec(ctx context.Context, tid int, regs Regs, result ExecResult) {
	if result.StubPath == "" {
		slog.Warn("redirectExec: no stub path, denying", "tid", tid)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	savedRegs := regs.Clone()

	// Step 1: Create socketpair in tracer process.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		slog.Warn("redirectExec: socketpair failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	tracerFD := fds[0]
	injectFD := fds[1]
	defer syscall.Close(tracerFD)
	defer syscall.Close(injectFD)

	// Step 2: Inject fd into tracee via pidfd_getfd.
	if err := t.injectFDIntoTracee(tid, savedRegs, injectFD, stubFDNum); err != nil {
		slog.Warn("redirectExec: fd injection failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	// Step 3: Write stub path into tracee memory.
	nr := regs.SyscallNr()
	var filenamePtr uint64
	if nr == unix.SYS_EXECVEAT {
		filenamePtr = regs.Arg(1)
	} else {
		filenamePtr = regs.Arg(0)
	}

	origFilename, _ := t.readString(tid, filenamePtr, 4096)
	origLen := len(origFilename) + 1

	stubPath := result.StubPath
	if len(stubPath)+1 <= origLen {
		if err := t.writeString(tid, filenamePtr, stubPath); err != nil {
			slog.Warn("redirectExec: write stub path failed, denying", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
			t.denySyscall(tid, int(unix.EACCES))
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
			slog.Warn("redirectExec: scratch alloc failed, denying", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
			t.denySyscall(tid, int(unix.EACCES))
			return
		}

		scratchAddr, err := sp.allocate(len(stubPath) + 1)
		if err != nil {
			slog.Warn("redirectExec: scratch page full, denying", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
			t.denySyscall(tid, int(unix.EACCES))
			return
		}

		if err := t.writeString(tid, scratchAddr, stubPath); err != nil {
			slog.Warn("redirectExec: write to scratch failed, denying", "tid", tid, "error", err)
			t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
			t.denySyscall(tid, int(unix.EACCES))
			return
		}

		if nr == unix.SYS_EXECVEAT {
			regs.SetArg(1, scratchAddr)
		} else {
			regs.SetArg(0, scratchAddr)
		}
	}

	// Step 4: Set registers and resume.
	if err := t.setRegs(tid, regs); err != nil {
		slog.Warn("redirectExec: setRegs failed, denying", "tid", tid, "error", err)
		t.cleanupInjectedFD(tid, savedRegs, stubFDNum)
		t.setRegs(tid, savedRegs)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

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
		return fmt.Errorf("pidfd_getfd: %w", err)
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
	}

	t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, pidfd)

	return nil
}

// cleanupInjectedFD closes a previously injected fd in the tracee.
func (t *Tracer) cleanupInjectedFD(tid int, savedRegs Regs, fdNum int) {
	t.injectSyscall(tid, savedRegs, unix.SYS_CLOSE, uint64(fdNum))
}
