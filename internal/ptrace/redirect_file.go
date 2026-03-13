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

// redirectFileImpl redirects a file syscall to a different path.
func (t *Tracer) redirectFileImpl(ctx context.Context, tid int, regs Regs, nr int, redirectPath string) error {
	argIdx := filePathArgIndex(nr)
	if argIdx < 0 {
		return fmt.Errorf("unsupported syscall %d for file redirect", nr)
	}

	pathPtr := regs.Arg(argIdx)

	// Read original path to determine buffer length.
	origPath, err := t.readString(tid, pathPtr, 4096)
	if err != nil {
		return fmt.Errorf("read original path: %w", err)
	}
	origLen := len(origPath) + 1

	if len(redirectPath)+1 <= origLen {
		return t.writeString(tid, pathPtr, redirectPath)
	}

	// Need scratch page.
	t.mu.Lock()
	state := t.tracees[tid]
	tgid := tid
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	savedRegs := regs.Clone()
	sp, err := t.ensureScratchPage(tid, tgid, savedRegs)
	if err != nil {
		return fmt.Errorf("scratch page: %w", err)
	}

	scratchAddr, err := sp.allocate(len(redirectPath) + 1)
	if err != nil {
		return fmt.Errorf("scratch allocate: %w", err)
	}

	if err := t.writeString(tid, scratchAddr, redirectPath); err != nil {
		return fmt.Errorf("write to scratch: %w", err)
	}

	regs.SetArg(argIdx, scratchAddr)
	return t.setRegs(tid, regs)
}

// redirectFile redirects a file syscall to a different path.
func (t *Tracer) redirectFile(ctx context.Context, tid int, regs Regs, nr int, result FileResult) {
	if result.RedirectPath == "" {
		slog.Warn("redirectFile: no redirect path, denying", "tid", tid)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	if err := t.redirectFileImpl(ctx, tid, regs, nr, result.RedirectPath); err != nil {
		slog.Warn("redirectFile: failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	t.allowSyscall(tid)
}

// softDeleteFile performs a soft-delete: denies the unlinkat but moves the file
// to a trash directory instead of actually deleting it.
func (t *Tracer) softDeleteFile(ctx context.Context, tid int, regs Regs, result FileResult) {
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

	// Read the path being deleted.
	pathPtr := regs.Arg(1)
	origPath, err := t.readString(tid, pathPtr, 4096)
	if err != nil {
		slog.Warn("softDeleteFile: cannot read path, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	dirfd := int(int32(regs.Arg(0)))
	absPath, err := resolvePathNoFollow(tid, dirfd, origPath)
	if err != nil {
		slog.Warn("softDeleteFile: cannot resolve path, denying", "tid", tid, "error", err)
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

	slog.Info("softDeleteFile: file moved to trash", "original", absPath, "trash", trashPath)

	// Deny the original unlinkat with fake success (return 0).
	regs.SetSyscallNr(-1)
	if err := t.setRegs(tid, regs); err != nil {
		slog.Warn("softDeleteFile: setRegs failed after rename", "tid", tid, "error", err)
		// File is already moved; best effort to resume the tracee.
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	t.mu.Lock()
	if s, ok := t.tracees[tid]; ok {
		s.PendingFakeZero = true
		s.InSyscall = true
	}
	t.mu.Unlock()

	if err := unix.PtraceSyscall(tid, 0); err != nil {
		slog.Warn("softDeleteFile: PtraceSyscall failed", "tid", tid, "error", err)
	}
}
