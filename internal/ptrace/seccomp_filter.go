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
