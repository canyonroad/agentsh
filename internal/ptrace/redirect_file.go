//go:build linux

package ptrace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

// atFDCWD is AT_FDCWD (-100) as a uint64 for use in injected syscall args.
// Go's const -100 cannot be directly converted to uint64, so we compute the
// two's complement representation that the kernel expects for a 64-bit register.
const atFDCWD = ^uint64(99) // 0xFFFFFFFFFFFFFF9C

// filePathArgIndex returns the register index containing the path pointer
// for the given file syscall number.
func filePathArgIndex(nr int) int {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
		return 1
	case unix.SYS_UNLINKAT, unix.SYS_MKDIRAT:
		return 1
	case unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2:
		return 1
	case unix.SYS_FCHOWNAT:
		return 1
	case unix.SYS_RENAMEAT2:
		return 1
	case unix.SYS_LINKAT:
		return 1
	case unix.SYS_SYMLINKAT:
		return 0
	default:
		return -1
	}
}

// redirectFileImpl injects a replacement file syscall with the redirect path.
//
// The kernel copies the filename from userspace via getname_flags() BEFORE
// delivering the ptrace seccomp/syscall-enter stop, so modifying the path
// in-place at that point is too late. Instead, we:
//  1. Write the redirect path to a scratch page
//  2. Inject a replacement syscall with all original args except the path
//  3. Return the injected syscall's return value
//
// After injection, the caller sets the return value directly in the registers
// and clears InSyscall so the tracer's enter/exit tracking stays synchronized.
func (t *Tracer) redirectFileImpl(ctx context.Context, tid int, regs Regs, nr int, redirectPath string) (int64, error) {
	argIdx := filePathArgIndex(nr)
	if argIdx < 0 {
		return 0, fmt.Errorf("unsupported syscall %d for file redirect", nr)
	}

	savedRegs := regs.Clone()

	// Get TGID for scratch page.
	t.mu.Lock()
	state := t.tracees[tid]
	tgid := tid
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	sp, err := t.ensureScratchPage(tid, tgid, savedRegs)
	if err != nil {
		return 0, fmt.Errorf("scratch page: %w", err)
	}

	pathAddr, err := sp.allocate(len(redirectPath) + 1)
	if err != nil {
		return 0, fmt.Errorf("scratch allocate: %w", err)
	}

	if err := t.writeString(tid, pathAddr, redirectPath); err != nil {
		return 0, fmt.Errorf("write to scratch: %w", err)
	}

	// Copy all 6 args from the original syscall, replacing the path arg.
	var args [6]uint64
	for i := 0; i < 6; i++ {
		args[i] = regs.Arg(i)
	}
	args[argIdx] = pathAddr

	// Inject the replacement syscall.
	ret, err := t.injectSyscall(tid, savedRegs, nr,
		args[0], args[1], args[2], args[3], args[4], args[5])
	if err != nil {
		return 0, fmt.Errorf("inject syscall: %w", err)
	}

	return ret, nil
}

// redirectFile redirects a file syscall to a different path.
//
// After injectSyscall returns, the injected syscall has completed its full
// enter+exit cycle and the original registers are restored. The tracee is
// stopped between syscalls (not inside one). We set the return value register
// directly so the tracee sees the injected result, clear InSyscall to keep
// the tracer's enter/exit tracking synchronized, and resume normally.
func (t *Tracer) redirectFile(ctx context.Context, tid int, regs Regs, nr int, result FileResult) {
	if result.RedirectPath == "" {
		slog.Warn("redirectFile: no redirect path, denying", "tid", tid)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	ret, err := t.redirectFileImpl(ctx, tid, regs, nr, result.RedirectPath)
	if err != nil {
		slog.Warn("redirectFile: failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	// Set the return value directly in the registers. The tracee will see
	// this as the result of the original syscall when it resumes.
	regs.SetReturnValue(ret)
	if err := t.setRegs(tid, regs); err != nil {
		slog.Warn("redirectFile: setRegs failed", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	// Clear InSyscall: the injection consumed the original syscall's
	// enter+exit cycle via injectSyscall's internal Wait4 calls.
	// The tracee is now stopped between syscalls, so the next ptrace
	// stop will be a fresh syscall-enter.
	t.mu.Lock()
	if s, ok := t.tracees[tid]; ok {
		s.InSyscall = false
	}
	t.mu.Unlock()

	t.allowSyscall(tid)
}

// softDeleteFile performs a soft-delete: denies the unlinkat but moves the file
// to a trash directory instead of actually deleting it.
// The absPath parameter is the already-resolved absolute path from handleFile.
func (t *Tracer) softDeleteFile(ctx context.Context, tid int, regs Regs, absPath string, result FileResult) {
	if result.TrashDir == "" {
		slog.Warn("softDeleteFile: no trash dir, denying", "tid", tid)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	nr := regs.SyscallNr()
	if nr != unix.SYS_UNLINKAT {
		slog.Warn("softDeleteFile: only supported for unlinkat", "tid", tid, "nr", nr)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	// Generate unique trash filename.
	var rndBuf [8]byte
	if _, err := rand.Read(rndBuf[:]); err != nil {
		slog.Warn("softDeleteFile: rand.Read failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	trashName := hex.EncodeToString(rndBuf[:])
	trashPath := result.TrashDir + "/" + trashName

	savedRegs := regs.Clone()

	// Get TGID for scratch page.
	t.mu.Lock()
	state := t.tracees[tid]
	tgid := tid
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	sp, err := t.ensureScratchPage(tid, tgid, savedRegs)
	if err != nil {
		slog.Warn("softDeleteFile: scratch page failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	// Write trash dir path to scratch and inject mkdirat.
	trashDirAddr, err := sp.allocate(len(result.TrashDir) + 1)
	if err != nil {
		slog.Warn("softDeleteFile: scratch alloc trashDir failed", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	if err := t.writeString(tid, trashDirAddr, result.TrashDir); err != nil {
		slog.Warn("softDeleteFile: write trashDir failed", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	mkdirRet, err := t.injectSyscall(tid, savedRegs, unix.SYS_MKDIRAT,
		atFDCWD, trashDirAddr, 0700)
	if err != nil {
		slog.Warn("softDeleteFile: mkdirat injection failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	if mkdirRet < 0 && unix.Errno(-mkdirRet) != unix.EEXIST {
		slog.Warn("softDeleteFile: mkdirat failed, denying", "tid", tid, "errno", unix.Errno(-mkdirRet))
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	sp.reset()

	// Write old path (absolute) and trash path to scratch.
	oldPathAddr, err := sp.allocate(len(absPath) + 1)
	if err != nil {
		slog.Warn("softDeleteFile: scratch alloc oldPath failed", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	if err := t.writeString(tid, oldPathAddr, absPath); err != nil {
		slog.Warn("softDeleteFile: write oldPath failed", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	trashPathAddr, err := sp.allocate(len(trashPath) + 1)
	if err != nil {
		slog.Warn("softDeleteFile: scratch alloc trashPath failed", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	if err := t.writeString(tid, trashPathAddr, trashPath); err != nil {
		slog.Warn("softDeleteFile: write trashPath failed", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	// Inject renameat2.
	renameRet, err := t.injectSyscall(tid, savedRegs, unix.SYS_RENAMEAT2,
		atFDCWD, oldPathAddr,
		atFDCWD, trashPathAddr,
		0)
	if err != nil {
		slog.Warn("softDeleteFile: renameat2 injection failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	if renameRet < 0 {
		errno := unix.Errno(-renameRet)
		slog.Warn("softDeleteFile: renameat2 failed, denying", "tid", tid, "errno", errno)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	// Set the return value to 0 (success) so the tracee sees the
	// unlinkat as having succeeded.
	regs.SetReturnValue(0)
	if err := t.setRegs(tid, regs); err != nil {
		slog.Warn("softDeleteFile: setRegs failed after rename", "tid", tid, "error", err)
	}

	// Clear InSyscall: the injection consumed the original syscall's
	// enter+exit cycle via injectSyscall's internal Wait4 calls.
	// The tracee is now stopped between syscalls, so the next ptrace
	// stop will be a fresh syscall-enter.
	t.mu.Lock()
	if s, ok := t.tracees[tid]; ok {
		s.InSyscall = false
	}
	t.mu.Unlock()

	t.allowSyscall(tid)
}
