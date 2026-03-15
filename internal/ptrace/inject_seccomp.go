//go:build linux

package ptrace

import (
	"encoding/binary"
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

// prSetNoNewPrivs is the prctl option that prevents privilege escalation.
// Required before installing a seccomp filter without CAP_SYS_ADMIN.
const prSetNoNewPrivs = 38

// seccompSetModeFilter is the seccomp operation for installing a BPF filter.
const seccompSetModeFilter = 1

// sockFprogSize is the size of struct sock_fprog on amd64/arm64 (16 bytes).
// Layout: { uint16 len; [6]byte pad; uint64 filter; }
const sockFprogSize = 16

// sockFilterSize is the size of a single BPF instruction (struct sock_filter).
// Layout: { uint16 Code; uint8 Jt; uint8 Jf; uint32 K; }
const sockFilterSize = 8

// injectSeccompFilter injects a seccomp-BPF prefilter into a stopped tracee.
// The tracee must be in a ptrace-stop (e.g., after PTRACE_INTERRUPT).
// Returns nil on success. Failure is non-fatal — caller falls back to TRACESYSGOOD.
func (t *Tracer) injectSeccompFilter(tid int) error {
	// Build the BPF program.
	filters, bpfErr := buildPrefilterBPF()
	if bpfErr != nil {
		return bpfErr
	}
	if len(filters) == 0 {
		return fmt.Errorf("empty BPF program")
	}

	// Get current registers for injection.
	savedRegs, err := t.getRegs(tid)
	if err != nil {
		return fmt.Errorf("getRegs: %w", err)
	}

	// Get TGID for scratch page.
	t.mu.Lock()
	state := t.tracees[tid]
	tgid := tid
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	// Get or allocate scratch page.
	sp, err := t.ensureScratchPage(tid, tgid, savedRegs)
	if err != nil {
		return fmt.Errorf("scratch page: %w", err)
	}

	// Calculate total size needed: sock_fprog (16 bytes) + filters.
	totalSize := sockFprogSize + len(filters)*sockFilterSize
	scratchAddr, err := sp.allocate(totalSize)
	if err != nil {
		return fmt.Errorf("scratch allocate: %w", err)
	}

	// Serialize the BPF filter array.
	filterBuf := make([]byte, len(filters)*sockFilterSize)
	for i, f := range filters {
		off := i * sockFilterSize
		binary.LittleEndian.PutUint16(filterBuf[off:], f.Code)
		filterBuf[off+2] = f.Jt
		filterBuf[off+3] = f.Jf
		binary.LittleEndian.PutUint32(filterBuf[off+4:], f.K)
	}

	// Build sock_fprog struct.
	// On amd64/arm64: { uint16 len, [6]byte pad, uint64 filter_ptr }
	filterArrayAddr := scratchAddr + sockFprogSize
	fprogBuf := make([]byte, sockFprogSize)
	binary.LittleEndian.PutUint16(fprogBuf[0:], uint16(len(filters)))
	// bytes 2..7 are padding (zero from make)
	binary.LittleEndian.PutUint64(fprogBuf[8:], filterArrayAddr)

	// Write sock_fprog + filter array to tracee memory.
	payload := make([]byte, 0, totalSize)
	payload = append(payload, fprogBuf...)
	payload = append(payload, filterBuf...)
	if err := t.writeBytes(tid, scratchAddr, payload); err != nil {
		return fmt.Errorf("write BPF to tracee: %w", err)
	}

	// Inject prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).
	ret, err := t.injectSyscall(tid, savedRegs, unix.SYS_PRCTL,
		prSetNoNewPrivs, 1, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("inject prctl: %w", err)
	}
	if ret != 0 && ret != -int64(unix.EINVAL) {
		// EINVAL is acceptable (already set). Other errors are real failures.
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS) returned %d (%s)", ret, unix.Errno(-ret))
	}

	// Inject seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog).
	ret, err = t.injectSyscall(tid, savedRegs, unix.SYS_SECCOMP,
		seccompSetModeFilter, 0, scratchAddr, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("inject seccomp: %w", err)
	}
	if ret != 0 {
		return fmt.Errorf("seccomp(SECCOMP_SET_MODE_FILTER) returned %d (%s)", ret, unix.Errno(-ret))
	}

	slog.Info("seccomp prefilter installed", "tid", tid, "filters", len(filters))
	return nil
}
