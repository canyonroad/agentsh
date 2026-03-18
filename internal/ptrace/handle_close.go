//go:build linux

package ptrace

import "context"

// handleClose intercepts SYS_CLOSE to clean up fd tracking state.
func (t *Tracer) handleClose(_ context.Context, tid int, sc *SyscallContext) {
	fd := int(int32(sc.Info.Args[0]))

	if t.fds != nil {
		t.mu.Lock()
		state := t.tracees[tid]
		var tgid int
		if state != nil {
			tgid = state.TGID
		}
		t.mu.Unlock()

		t.fds.closeFd(tgid, fd)
	}

	t.allowSyscall(tid)
}
