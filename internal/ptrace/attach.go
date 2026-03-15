//go:build linux

package ptrace

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func (t *Tracer) attachProcess(pid int, opts attachOpts) error {
	// Seed directly-attached processes as roots in the process tree so
	// depth-based policy rules work correctly (depth 0 for direct attaches).
	t.processTree.AddRoot(pid)

	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return t.attachThread(pid, opts)
	}

	var firstErr error
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if err := t.attachThread(tid, opts); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			slog.Warn("failed to attach thread", "tid", tid, "pid", pid, "error", err)
		}
	}
	return firstErr
}

func (t *Tracer) attachThread(tid int, opts attachOpts) error {
	err := unix.PtraceSeize(tid)
	if err != nil {
		reason := "other"
		if errors.Is(err, unix.ESRCH) {
			reason = "esrch"
		} else if errors.Is(err, unix.EPERM) {
			reason = "eperm"
		}
		t.metrics.IncAttachFailure(reason)
		return fmt.Errorf("PTRACE_SEIZE tid %d: %w", tid, err)
	}

	// PTRACE_SEIZE does not stop the tracee. We must interrupt it and wait
	// for the ptrace-stop before calling PTRACE_SETOPTIONS, which requires
	// the tracee to be stopped (otherwise it returns ESRCH).
	if err := unix.PtraceInterrupt(tid); err != nil {
		t.safeDetach(tid)
		t.metrics.IncAttachFailure("other")
		return fmt.Errorf("PTRACE_INTERRUPT tid %d: %w", tid, err)
	}

	// Wait for the interrupt stop with a timeout. Use WNOHANG to avoid
	// blocking forever if Go's runtime reaps the child first (e.g., when
	// cmd.Wait() races with our Wait4).
	var status unix.WaitStatus
	deadline := time.Now().Add(2 * time.Second)
	for {
		wpid, werr := unix.Wait4(tid, &status, unix.WNOHANG|unix.WALL, nil)
		if werr != nil {
			if werr == unix.EINTR {
				continue
			}
			t.safeDetach(tid)
			t.metrics.IncAttachFailure("other")
			return fmt.Errorf("wait4 after interrupt tid %d: %w", tid, werr)
		}
		if wpid == tid {
			break
		}
		if time.Now().After(deadline) {
			t.safeDetach(tid)
			t.metrics.IncAttachFailure("other")
			return fmt.Errorf("wait4 after interrupt tid %d: timed out", tid)
		}
		time.Sleep(time.Millisecond)
	}

	if !status.Stopped() {
		t.safeDetach(tid)
		t.metrics.IncAttachFailure("other")
		return fmt.Errorf("tid %d: expected ptrace-stop after interrupt, got status %v", tid, status)
	}

	if err := unix.PtraceSetOptions(tid, t.ptraceOptions()); err != nil {
		t.safeDetach(tid)
		t.metrics.IncAttachFailure("other")
		return fmt.Errorf("PTRACE_SETOPTIONS tid %d: %w", tid, err)
	}

	tgid, err := readTGID(tid)
	if err != nil {
		t.safeDetach(tid)
		t.metrics.IncAttachFailure("other")
		return fmt.Errorf("read TGID for tid %d: %w", tid, err)
	}

	if opts.keepStopped {
		// Leave tracee stopped for cgroup hook; register in parkedTracees
		// so ResumePID (via handleResumeRequest) can find and resume it.
	} else {
		// HasPrefilter is always false for freshly attached threads
		// (injection hasn't happened yet), so this takes the PtraceSyscall
		// path. When injection is wired in, HasPrefilter will be set to
		// true and this will use PtraceCont instead.
		err = unix.PtraceSyscall(tid, 0)
	}
	if err != nil {
		unix.PtraceDetach(tid)
		t.metrics.IncAttachFailure("other")
		return fmt.Errorf("restart tid %d: %w", tid, err)
	}

	memFD := -1
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDWR, 0)
	if err != nil {
		fd, _ = unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDONLY, 0)
	}
	memFD = fd

	t.mu.Lock()
	t.tracees[tid] = &TraceeState{
		TID:                tid,
		TGID:               tgid,
		SessionID:          opts.sessionID,
		CommandID:          opts.commandID,
		Attached:           time.Now(),
		LastNr:             -1,
		MemFD:              memFD,
		PendingExecStubFD:  -1,
		PendingExecSavedFD: -1,
	}
	if opts.keepStopped {
		t.parkedTracees[tid] = struct{}{}
	}
	t.metrics.SetTraceeCount(len(t.tracees))
	t.mu.Unlock()

	return nil
}

func (t *Tracer) safeDetach(tid int) {
	if err := unix.PtraceInterrupt(tid); err != nil {
		// If interrupt fails (e.g., ESRCH), the tracee may have already
		// exited. Try detach anyway in case it's still stopped.
		unix.PtraceDetach(tid)
		return
	}
	var status unix.WaitStatus
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		wpid, err := unix.Wait4(tid, &status, unix.WNOHANG|unix.WALL, nil)
		if err != nil {
			// Wait4 failed — try best-effort detach.
			unix.PtraceDetach(tid)
			return
		}
		if wpid == tid {
			break
		}
		if time.Now().After(deadline) {
			// Timed out waiting for stop. Try detach anyway to avoid
			// leaving the tracee permanently ptrace-attached.
			unix.PtraceDetach(tid)
			return
		}
		time.Sleep(time.Millisecond)
	}
	unix.PtraceDetach(tid)
}
