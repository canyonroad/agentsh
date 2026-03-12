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

func (t *Tracer) attachProcess(pid int) error {
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return t.attachThread(pid)
	}

	var firstErr error
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if err := t.attachThread(tid); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			slog.Warn("failed to attach thread", "tid", tid, "pid", pid, "error", err)
		}
	}
	return firstErr
}

func (t *Tracer) attachThread(tid int) error {
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

	if err := unix.PtraceSetOptions(tid, t.ptraceOptions()); err != nil {
		t.safeDetach(tid)
		return fmt.Errorf("PTRACE_SETOPTIONS tid %d: %w", tid, err)
	}

	tgid, err := readTGID(tid)
	if err != nil {
		t.safeDetach(tid)
		return fmt.Errorf("read TGID for tid %d: %w", tid, err)
	}

	if err := unix.PtraceInterrupt(tid); err != nil {
		t.safeDetach(tid)
		return fmt.Errorf("PTRACE_INTERRUPT tid %d: %w", tid, err)
	}

	var status unix.WaitStatus
	_, err = unix.Wait4(tid, &status, 0, nil)
	if err != nil {
		t.safeDetach(tid)
		return fmt.Errorf("wait4 after interrupt tid %d: %w", tid, err)
	}

	if !status.Stopped() {
		t.safeDetach(tid)
		return fmt.Errorf("tid %d: expected ptrace-stop after interrupt, got status %v", tid, status)
	}

	if t.prefilterActive {
		err = unix.PtraceCont(tid, 0)
	} else {
		err = unix.PtraceSyscall(tid, 0)
	}
	if err != nil {
		unix.PtraceDetach(tid)
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
		TID:      tid,
		TGID:     tgid,
		Attached: time.Now(),
		MemFD:    memFD,
	}
	t.metrics.SetTraceeCount(len(t.tracees))
	t.mu.Unlock()

	return nil
}

func (t *Tracer) safeDetach(tid int) {
	if err := unix.PtraceInterrupt(tid); err != nil {
		return
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(tid, &status, 0, nil); err != nil {
		return
	}
	if status.Stopped() {
		unix.PtraceDetach(tid)
	}
}
