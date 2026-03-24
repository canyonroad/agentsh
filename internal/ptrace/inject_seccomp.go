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

// seccompFilterFlagTsync synchronizes the filter across all threads in the
// thread group. Without this, the filter is installed on a single thread,
// causing libseccomp's TSYNC to fail with ECANCELED when a multi-threaded
// process (like a Go binary) later installs its own filter.
const seccompFilterFlagTsync = 1

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
	denies := t.collectStaticDenies()
	allows := t.collectStaticAllows()
	narrowNums := narrowTracedSyscallNumbers(&t.cfg)

	// Remove statically allowed syscalls from traced set.
	// These fall through to the BPF default SECCOMP_RET_ALLOW path.
	if len(allows) > 0 {
		filtered := narrowNums[:0]
		for _, nr := range narrowNums {
			if !allows[nr] {
				filtered = append(filtered, nr)
			}
		}
		narrowNums = filtered
	}

	// Build the action list (used by all filter paths).
	denySet := make(map[int]uint32)
	for _, d := range denies {
		denySet[d.Nr] = seccompRetErrno(d.Errno)
	}
	var actions []bpfSyscallAction
	for _, nr := range narrowNums {
		if errnoAction, ok := denySet[nr]; ok {
			actions = append(actions, bpfSyscallAction{Nr: nr, Action: errnoAction})
			delete(denySet, nr)
		} else {
			actions = append(actions, bpfSyscallAction{Nr: nr, Action: seccompRetTrace})
		}
	}
	for nr, action := range denySet {
		actions = append(actions, bpfSyscallAction{Nr: nr, Action: action})
	}

	var argFilters []bpfArgFilter
	var nullFilters []bpfNullPtrFilter
	if t.cfg.ArgLevelFilter {
		// NOTE: openat read-only arg filter is NOT wired here yet.
		// Allowing read-only opens in-kernel would bypass path-based deny
		// rules for read operations. A future StaticReadAllowChecker interface
		// will let handlers declare that read-only opens are safe, at which
		// point the openat arg filter can be enabled here.
		// The buildBPFWithArgFilters function supports it — just add:
		//   argFilters = append(argFilters, bpfArgFilter{
		//       Nr: unix.SYS_OPENAT, ArgIndex: 2, Mask: openatWriteMask,
		//   })

		// Sendto with NULL dest_addr: connected-socket send, skip ptrace.
		nullFilters = append(nullFilters, bpfNullPtrFilter{
			Nr:       unix.SYS_SENDTO,
			ArgIndex: 4,
		})

		// Remove filters for syscalls not in the traced set.
		tracedSet := make(map[int]bool)
		for _, a := range actions {
			tracedSet[a.Nr] = true
		}
		var filteredArg []bpfArgFilter
		for _, af := range argFilters {
			if tracedSet[af.Nr] {
				filteredArg = append(filteredArg, af)
			}
		}
		argFilters = filteredArg
		var filteredNull []bpfNullPtrFilter
		for _, nf := range nullFilters {
			if tracedSet[nf.Nr] {
				filteredNull = append(filteredNull, nf)
			}
		}
		nullFilters = filteredNull
	}

	var filters []unix.SockFilter
	var bpfErr error
	if len(argFilters) > 0 || len(nullFilters) > 0 {
		filters, bpfErr = buildBPFWithArgFilters(actions, argFilters, nullFilters)
	} else if len(denies) > 0 || len(denySet) > 0 {
		filters, bpfErr = buildBPFForActions(actions)
	} else {
		filters, bpfErr = buildBPFForSyscalls(narrowNums)
	}

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

	// Reset scratch page so injection starts fresh.
	t.resetScratchIfPresent(tgid)

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
	// Note: PR_SET_NO_NEW_PRIVS is irreversible — it persists even if the
	// subsequent seccomp() call fails. This is acceptable for agentsh
	// workloads (sandboxed agent commands should not escalate privileges;
	// the non-ptrace seccomp wrapper path also sets this flag).
	ret, err := t.injectSyscall(tid, savedRegs, unix.SYS_PRCTL,
		prSetNoNewPrivs, 1, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("inject prctl: %w", err)
	}
	if ret != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS) returned %d (%s)", ret, unix.Errno(-ret))
	}

	// Inject seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog).
	// TSYNC ensures all threads in the thread group get the filter. Without it,
	// only the current thread gets the filter, and multi-threaded Go binaries
	// (like agentsh-unixwrap) fail when libseccomp later calls seccomp with TSYNC
	// and finds asymmetric filter chains between threads.
	ret, err = t.injectSyscall(tid, savedRegs, unix.SYS_SECCOMP,
		seccompSetModeFilter, seccompFilterFlagTsync, scratchAddr, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("inject seccomp: %w", err)
	}
	if ret != 0 {
		return fmt.Errorf("seccomp(SECCOMP_SET_MODE_FILTER) returned %d (%s)", ret, unix.Errno(-ret))
	}

	slog.Info("seccomp prefilter installed", "tid", tid, "filters", len(filters))
	for _, d := range denies {
		slog.Info("seccomp static deny active", "tid", tid, "nr", d.Nr, "errno", d.Errno)
	}
	for nr := range allows {
		slog.Info("seccomp static allow active", "tid", tid, "nr", nr)
	}
	if t.cfg.ArgLevelFilter {
		for _, af := range argFilters {
			slog.Info("seccomp arg filter active", "tid", tid, "nr", af.Nr, "argIndex", af.ArgIndex, "mask", fmt.Sprintf("0x%x", af.Mask))
		}
		for _, nf := range nullFilters {
			slog.Info("seccomp null filter active", "tid", tid, "nr", nf.Nr, "argIndex", nf.ArgIndex)
		}
	}
	return nil
}

// readEscalationSyscalls are the syscalls added when TracerPid masking is needed.
var readEscalationSyscalls = []int{unix.SYS_READ, unix.SYS_PREAD64}

// writeEscalationSyscalls are the syscalls added when TLS SNI rewrite is needed.
var writeEscalationSyscalls = []int{unix.SYS_WRITE}

// injectEscalationFilter installs an additional seccomp-BPF filter that traces
// the specified syscalls. Stacked on top of the narrow prefilter. Skips
// prctl(PR_SET_NO_NEW_PRIVS) since the initial filter injection already set it.
// The tracee must be at a syscall-exit stop.
func (t *Tracer) injectEscalationFilter(tid int, syscalls []int) error {
	filters, err := buildEscalationBPF(syscalls)
	if err != nil {
		return err
	}
	if len(filters) == 0 {
		return fmt.Errorf("empty escalation BPF")
	}

	savedRegs, err := t.getRegs(tid)
	if err != nil {
		return fmt.Errorf("escalation getRegs: %w", err)
	}

	t.mu.Lock()
	state := t.tracees[tid]
	tgid := tid
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	// Reset scratch page so escalation injection starts fresh.
	t.resetScratchIfPresent(tgid)

	sp, err := t.ensureScratchPage(tid, tgid, savedRegs)
	if err != nil {
		return fmt.Errorf("escalation scratch page: %w", err)
	}

	totalSize := sockFprogSize + len(filters)*sockFilterSize
	scratchAddr, err := sp.allocate(totalSize)
	if err != nil {
		return fmt.Errorf("escalation scratch allocate: %w", err)
	}

	filterBuf := make([]byte, len(filters)*sockFilterSize)
	for i, f := range filters {
		off := i * sockFilterSize
		binary.LittleEndian.PutUint16(filterBuf[off:], f.Code)
		filterBuf[off+2] = f.Jt
		filterBuf[off+3] = f.Jf
		binary.LittleEndian.PutUint32(filterBuf[off+4:], f.K)
	}

	filterArrayAddr := scratchAddr + sockFprogSize
	fprogBuf := make([]byte, sockFprogSize)
	binary.LittleEndian.PutUint16(fprogBuf[0:], uint16(len(filters)))
	binary.LittleEndian.PutUint64(fprogBuf[8:], filterArrayAddr)

	payload := make([]byte, 0, totalSize)
	payload = append(payload, fprogBuf...)
	payload = append(payload, filterBuf...)
	if err := t.writeBytes(tid, scratchAddr, payload); err != nil {
		return fmt.Errorf("escalation write BPF: %w", err)
	}

	// Skip prctl — PR_SET_NO_NEW_PRIVS already set by initial filter.
	ret, err := t.injectSyscall(tid, savedRegs, unix.SYS_SECCOMP,
		seccompSetModeFilter, 0, scratchAddr, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("escalation inject seccomp: %w", err)
	}
	if ret != 0 {
		return fmt.Errorf("escalation seccomp returned %d (%s)", ret, unix.Errno(-ret))
	}

	slog.Info("seccomp escalation filter installed", "tid", tid, "syscalls", syscalls)
	return nil
}
