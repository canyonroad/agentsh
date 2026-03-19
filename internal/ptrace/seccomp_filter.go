//go:build linux

package ptrace

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// BPF instruction classes and fields.
const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfK   = 0x00
	bpfRET = 0x06
	bpfJSET = 0x40

	seccompRetAllow = 0x7FFF0000
	seccompRetTrace = 0x7FF00000

	seccompRetErrnoBase = 0x00050000

	// seccomp_data offsets.
	offsetNr   = 0 // offsetof(struct seccomp_data, nr)
	offsetArch = 4 // offsetof(struct seccomp_data, arch)

	// seccomp_data argument offsets.
	// struct seccomp_data { int nr; __u32 arch; __u64 ip; __u64 args[6]; }
	// args[i] is at offset 16 + i*8. Classic BPF loads 32-bit words, so
	// the low 32 bits of args[i] are at offset 16+i*8, high at 16+i*8+4.
	offsetArgs0Lo = 16
	offsetArgs2Lo = 32 // openat flags
	offsetArgs4Lo = 48 // sendto dest_addr low
	offsetArgs4Hi = 52 // sendto dest_addr high

	auditArchX86_64  = 0xC000003E
	auditArchAarch64 = 0xC00000B7

	// openatWriteMask is the bitmask of openat flags that indicate a
	// non-read-only operation. O_WRONLY|O_RDWR|O_CREAT|__O_TMPFILE.
	// If (flags & openatWriteMask) == 0, the open is read-only.
	openatWriteMask = 0x400043
)

// buildBPFForSyscalls generates a seccomp-BPF filter that returns
// SECCOMP_RET_TRACE for the given syscalls and SECCOMP_RET_ALLOW for
// everything else.
func buildBPFForSyscalls(syscalls []int) ([]unix.SockFilter, error) {
	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = auditArchX86_64
	case "arm64":
		auditArch = auditArchAarch64
	default:
		return nil, fmt.Errorf("seccomp prefilter: unsupported architecture %s", runtime.GOARCH)
	}

	n := len(syscalls)
	prog := make([]unix.SockFilter, 0, 4+n+2)

	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetArch})
	prog = append(prog, unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: auditArch})
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetNr})

	for i, nr := range syscalls {
		remaining := n - i - 1
		jumpToTrace := uint8(remaining + 1)
		prog = append(prog, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jumpToTrace,
			Jf:   0,
			K:    uint32(nr),
		})
	}

	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})

	return prog, nil
}

// seccompRetErrno returns the SECCOMP_RET_ERRNO value for the given errno.
func seccompRetErrno(errno int) uint32 {
	return seccompRetErrnoBase | uint32(errno&0xFFFF)
}

// bpfSyscallAction pairs a syscall number with its BPF return action.
type bpfSyscallAction struct {
	Nr     int
	Action uint32 // seccompRetTrace or seccompRetErrno(errno)
}

// bpfArgFilter describes a bitmask check on a syscall argument.
// If (arg & Mask) != 0 → TRACE, else → ALLOW.
// Only applicable to arguments that are scalar values (flags, sizes),
// NOT pointers — classic BPF cannot dereference pointers.
type bpfArgFilter struct {
	Nr       int    // syscall number
	ArgIndex int    // 0-5
	Mask     uint32 // bitmask for JSET
}

// bpfNullPtrFilter describes a NULL-pointer check on a syscall argument.
// If arg == 0 (both 32-bit halves) → ALLOW, else → TRACE.
type bpfNullPtrFilter struct {
	Nr       int // syscall number
	ArgIndex int // 0-5
}

// buildBPFForActions generates a seccomp-BPF filter with per-syscall return
// actions. Different syscalls can have different return values (TRACE vs ERRNO).
func buildBPFForActions(actions []bpfSyscallAction) ([]unix.SockFilter, error) {
	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = auditArchX86_64
	case "arm64":
		auditArch = auditArchAarch64
	default:
		return nil, fmt.Errorf("seccomp prefilter: unsupported architecture %s", runtime.GOARCH)
	}

	// Collect unique return actions (deduplicate).
	retActionSet := make(map[uint32]int) // action → index in retActions slice
	var retActions []uint32
	for _, a := range actions {
		if _, ok := retActionSet[a.Action]; !ok {
			retActionSet[a.Action] = len(retActions)
			retActions = append(retActions, a.Action)
		}
	}

	n := len(actions)
	nRet := len(retActions)
	prog := make([]unix.SockFilter, 0, 4+n+1+nRet)

	// Header: load arch, check arch, load nr
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetArch})
	prog = append(prog, unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: auditArch})
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetNr})

	// Comparisons: each JEQ jumps to its action's return instruction.
	// Layout after comparisons: [ALLOW ret] [action0 ret] [action1 ret] ...
	for i, a := range actions {
		remaining := n - i - 1
		jumpTarget := uint8(remaining + 1 + retActionSet[a.Action])
		prog = append(prog, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jumpTarget,
			Jf:   0,
			K:    uint32(a.Nr),
		})
	}

	// Default: ALLOW
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})

	// Per-action return instructions
	for _, action := range retActions {
		prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: action})
	}

	return prog, nil
}

// checkBlock associates a syscall action entry index with its position in
// the check-blocks section and the type of check to perform.
type checkBlock struct {
	actionIdx int  // index into the actions slice
	offset    int  // instruction offset within the check-blocks section
	isNull    bool // true for bpfNullPtrFilter, false for bpfArgFilter
	argOffset uint32
	mask      uint32 // only for bpfArgFilter
}

// buildBPFWithArgFilters generates a seccomp-BPF filter with per-syscall
// actions AND optional argument-level checks. When no arg/null filters are
// provided it delegates to buildBPFForActions.
//
// Program layout:
//
//	[4 header: load arch, check arch, ret trace, load nr]
//	[n JEQ comparisons — with-filter syscalls jump to check blocks, others to action rets]
//	[1 default RET ALLOW]
//	[nRet action return instructions]
//	[check blocks: arg filter = 3 insns each, null filter = 5 insns each]
//	[1 trailing RET TRACE]
func buildBPFWithArgFilters(actions []bpfSyscallAction, argFilters []bpfArgFilter, nullFilters []bpfNullPtrFilter) ([]unix.SockFilter, error) {
	// Fall back when no filters are provided.
	if len(argFilters) == 0 && len(nullFilters) == 0 {
		return buildBPFForActions(actions)
	}

	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = auditArchX86_64
	case "arm64":
		auditArch = auditArchAarch64
	default:
		return nil, fmt.Errorf("seccomp prefilter: unsupported architecture %s", runtime.GOARCH)
	}

	// Build lookup maps for arg and null filters, keyed by syscall number.
	argByNr := make(map[int]bpfArgFilter, len(argFilters))
	for _, af := range argFilters {
		argByNr[af.Nr] = af
	}
	nullByNr := make(map[int]bpfNullPtrFilter, len(nullFilters))
	for _, nf := range nullFilters {
		nullByNr[nf.Nr] = nf
	}

	// Collect unique return actions (deduplicate), same as buildBPFForActions.
	retActionSet := make(map[uint32]int)
	var retActions []uint32
	for _, a := range actions {
		if _, ok := retActionSet[a.Action]; !ok {
			retActionSet[a.Action] = len(retActions)
			retActions = append(retActions, a.Action)
		}
	}

	// Assign check blocks. Arg filters are skipped for non-TRACE (ERRNO) syscalls.
	// Blocks are ordered in the same sequence as they appear in actions.
	var blocks []checkBlock
	blockByActionIdx := make(map[int]int) // actionIdx → blocks index
	checkOffset := 0
	for i, a := range actions {
		if a.Action != seccompRetTrace {
			// Deny priority: skip arg/null filters for this syscall.
			continue
		}
		if af, ok := argByNr[a.Nr]; ok {
			blockByActionIdx[i] = len(blocks)
			argOff := uint32(offsetArgs0Lo + af.ArgIndex*8)
			blocks = append(blocks, checkBlock{
				actionIdx: i,
				offset:    checkOffset,
				isNull:    false,
				argOffset: argOff,
				mask:      af.Mask,
			})
			checkOffset += 3 // LD + JSET + RET ALLOW
		} else if nf, ok := nullByNr[a.Nr]; ok {
			blockByActionIdx[i] = len(blocks)
			argOff := uint32(offsetArgs0Lo + nf.ArgIndex*8)
			blocks = append(blocks, checkBlock{
				actionIdx: i,
				offset:    checkOffset,
				isNull:    true,
				argOffset: argOff,
			})
			checkOffset += 5 // LD lo + JEQ + LD hi + JEQ + RET ALLOW
		}
	}

	// If after filtering there are no valid check blocks, delegate.
	if len(blocks) == 0 {
		return buildBPFForActions(actions)
	}

	totalCheckInsts := checkOffset // total instructions in all check blocks (before trailing RET)
	n := len(actions)
	nRet := len(retActions)
	// checksStart: number of instructions to skip from end of comparisons to reach check blocks.
	// After comparisons: [RET ALLOW] [nRet action rets] [check blocks...]
	checksStart := 1 + nRet

	prog := make([]unix.SockFilter, 0, 4+n+1+nRet+totalCheckInsts+1)

	// Header.
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetArch})
	prog = append(prog, unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: auditArch})
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetNr})

	// Comparisons.
	for i, a := range actions {
		remaining := n - i - 1
		var jumpTarget uint8
		if blkIdx, ok := blockByActionIdx[i]; ok {
			blk := blocks[blkIdx]
			jumpTarget = uint8(remaining + checksStart + blk.offset)
		} else {
			jumpTarget = uint8(remaining + 1 + retActionSet[a.Action])
		}
		prog = append(prog, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jumpTarget,
			Jf:   0,
			K:    uint32(a.Nr),
		})
	}

	// Default RET ALLOW.
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})

	// Per-action return instructions.
	for _, action := range retActions {
		prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: action})
	}

	// Check blocks.
	for _, blk := range blocks {
		if !blk.isNull {
			// Arg filter: LD + JSET + RET ALLOW (3 instructions).
			// JSET: Jt → trailing TRACE (write), Jf → fall through to RET ALLOW (read-only).
			jsetToTrace := uint8(totalCheckInsts - blk.offset - 2)
			prog = append(prog,
				unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: blk.argOffset},
				unix.SockFilter{Code: bpfJMP | bpfJSET | bpfK, Jt: jsetToTrace, Jf: 0, K: blk.mask},
				unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow},
			)
		} else {
			// Null pointer filter: LD lo + JEQ + LD hi + JEQ + RET ALLOW (5 instructions).
			// Both halves must be zero (NULL) to ALLOW; either non-zero → TRACE.
			jfToTrace1 := uint8(totalCheckInsts - blk.offset - 2)
			jfToTrace2 := uint8(totalCheckInsts - blk.offset - 4)
			loOffset := blk.argOffset
			hiOffset := blk.argOffset + 4
			prog = append(prog,
				unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: loOffset},
				unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 0, Jf: jfToTrace1, K: 0},
				unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: hiOffset},
				unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 0, Jf: jfToTrace2, K: 0},
				unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow},
			)
		}
	}

	// Trailing RET TRACE (target for all arg/null filter mismatches).
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})

	return prog, nil
}

// buildPrefilterBPF generates the full prefilter (all traced syscalls).
func buildPrefilterBPF(cfg *TracerConfig) ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(tracedSyscallNumbers(cfg))
}

// buildNarrowPrefilterBPF generates a BPF filter that excludes read/write
// syscalls from the traced set. Used as the initial filter; read/write are
// lazily escalated per-TGID when needed.
func buildNarrowPrefilterBPF(cfg *TracerConfig) ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(narrowTracedSyscallNumbers(cfg))
}

// buildEscalationBPF generates a minimal BPF filter that traces only the
// specified syscalls. Installed on top of the narrow filter via seccomp
// stacking to add read/write when needed.
func buildEscalationBPF(syscalls []int) ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(syscalls)
}
