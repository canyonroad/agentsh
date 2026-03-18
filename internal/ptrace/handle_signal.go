//go:build linux

package ptrace

import (
	"context"
	"log/slog"

	"golang.org/x/sys/unix"
)

// extractSignalArgs extracts target PID, signal number, and the register index
// of the signal argument from syscall arguments.
func extractSignalArgs(nr int, arg0, arg1, arg2 int) (int, int, int) {
	switch nr {
	case unix.SYS_KILL:
		return arg0, arg1, 1
	case unix.SYS_TKILL:
		return arg0, arg1, 1
	case unix.SYS_TGKILL:
		return arg0, arg2, 2
	case unix.SYS_RT_SIGQUEUEINFO:
		// rt_sigqueueinfo(pid, sig, info): arg0=pid, arg1=sig
		return arg0, arg1, 1
	case unix.SYS_RT_TGSIGQUEUEINFO:
		// rt_tgsigqueueinfo(tgid, tid, sig, info): arg0=tgid, arg2=sig
		return arg0, arg2, 2
	default:
		return arg0, arg1, 1
	}
}

// handleSignal intercepts signal delivery syscalls for policy evaluation.
func (t *Tracer) handleSignal(ctx context.Context, tid int, sc *SyscallContext) {
	if t.cfg.SignalHandler == nil || !t.cfg.TraceSignal {
		t.allowSyscall(tid)
		return
	}

	nr := sc.Info.Nr

	switch nr {
	case unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
		unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO:
		// handled below
	default:
		t.allowSyscall(tid)
		return
	}

	arg0 := int(int32(sc.Info.Args[0]))
	arg1 := int(int32(sc.Info.Args[1]))
	arg2 := int(int32(sc.Info.Args[2]))

	targetPID, signal, sigArgIndex := extractSignalArgs(nr, arg0, arg1, arg2)

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	result := t.cfg.SignalHandler.HandleSignal(ctx, SignalContext{
		PID:       tgid,
		SessionID: sessionID,
		TargetPID: targetPID,
		Signal:    signal,
	})

	switch {
	case !result.Allow:
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EPERM)
		}
		t.denySyscall(tid, int(errno))

	case result.RedirectSignal > 0 && result.RedirectSignal != signal:
		// Redirect is only safe for kill/tkill/tgkill where we can rewrite
		// the signal register. For rt_sigqueueinfo/rt_tgsigqueueinfo, the
		// signal is also embedded in siginfo_t.si_signo which we can't
		// reliably patch, so deny if redirect is requested for those.
		switch nr {
		case unix.SYS_KILL, unix.SYS_TKILL, unix.SYS_TGKILL:
			regs, err := sc.Regs()
			if err != nil {
				slog.Warn("handleSignal: cannot load regs for redirect, denying", "tid", tid, "error", err)
				t.denySyscall(tid, int(unix.EPERM))
				return
			}
			regs.SetArg(sigArgIndex, uint64(result.RedirectSignal))
			if err := t.setRegs(tid, regs); err != nil {
				slog.Warn("handleSignal: cannot rewrite signal register, denying", "tid", tid, "error", err)
				t.denySyscall(tid, int(unix.EPERM))
				return
			}
			t.allowSyscall(tid)
		default:
			slog.Warn("handleSignal: redirect not supported for this syscall, denying", "tid", tid, "nr", nr)
			t.denySyscall(tid, int(unix.EPERM))
		}

	default:
		t.allowSyscall(tid)
	}
}
