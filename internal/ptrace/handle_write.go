//go:build linux

package ptrace

import (
	"context"
	"log/slog"
)

// handleWrite intercepts write for SNI rewrite on TLS-watched fds.
func (t *Tracer) handleWrite(ctx context.Context, tid int, sc *SyscallContext) {
	if t.fds == nil {
		t.allowSyscall(tid)
		return
	}

	fd := int(int32(sc.Info.Args[0]))

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	// Reset scratch page so SNI rewrite operations start fresh.
	t.resetScratchIfPresent(tgid)

	domain, watched := t.fds.getTLSWatch(tgid, fd)
	if !watched {
		t.allowSyscall(tid)
		return
	}

	// Read the write buffer to check for ClientHello
	regs, err := sc.Regs()
	if err != nil {
		slog.Warn("handleWrite: cannot load registers", "tid", tid, "error", err)
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}
	bufPtr := regs.Arg(1)
	bufLen := regs.Arg(2)

	readLen := bufLen
	if readLen > 16384 {
		readLen = 16384
	}

	buf := make([]byte, readLen)
	if err := t.readBytes(tid, bufPtr, buf); err != nil {
		slog.Warn("handleWrite: cannot read write buffer", "tid", tid, "error", err)
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}

	if !isClientHello(buf) {
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}

	sni, _, _, err := parseSNI(buf)
	if err != nil {
		slog.Debug("handleWrite: no SNI in ClientHello", "tid", tid, "error", err)
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}

	if sni == domain {
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}

	rewritten, err := rewriteSNI(buf, domain)
	if err != nil {
		slog.Warn("handleWrite: SNI rewrite failed", "tid", tid, "oldSNI", sni, "newSNI", domain, "error", err)
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}

	if len(rewritten) <= int(bufLen) {
		if err := t.writeBytes(tid, bufPtr, rewritten); err != nil {
			slog.Warn("handleWrite: failed to write rewritten ClientHello", "tid", tid, "error", err)
			t.fds.unwatchTLS(tgid, fd)
			t.allowSyscall(tid)
			return
		}
		if len(rewritten) < int(bufLen) {
			regs.SetArg(2, uint64(len(rewritten)))
			if err := t.setRegs(tid, regs); err != nil {
				slog.Warn("handleWrite: failed to update length register", "tid", tid, "error", err)
			}
		}
	} else {
		// Longer rewritten buffer — use scratch page from Phase 4a injection engine.
		sp, err := t.ensureScratchPage(tid, tgid, regs)
		if err != nil {
			slog.Warn("handleWrite: scratch page alloc failed, allowing original", "tid", tid, "error", err)
			t.fds.unwatchTLS(tgid, fd)
			t.allowSyscall(tid)
			return
		}
		scratchAddr, err := sp.allocate(len(rewritten))
		if err != nil {
			slog.Warn("handleWrite: scratch allocate failed, allowing original", "tid", tid, "error", err)
			t.fds.unwatchTLS(tgid, fd)
			t.allowSyscall(tid)
			return
		}
		if err := t.writeBytes(tid, scratchAddr, rewritten); err != nil {
			slog.Warn("handleWrite: failed to write to scratch", "tid", tid, "error", err)
			t.fds.unwatchTLS(tgid, fd)
			t.allowSyscall(tid)
			return
		}
		regs.SetArg(1, scratchAddr)
		regs.SetArg(2, uint64(len(rewritten)))
		if err := t.setRegs(tid, regs); err != nil {
			slog.Warn("handleWrite: failed to update registers for scratch", "tid", tid, "error", err)
		}
	}

	slog.Info("handleWrite: rewrote SNI", "tid", tid, "oldSNI", sni, "newSNI", domain)
	t.fds.unwatchTLS(tgid, fd)
	t.allowSyscall(tid)
}
