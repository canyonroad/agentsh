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

	seccompRetAllow = 0x7FFF0000
	seccompRetTrace = 0x7FF00000

	// seccomp_data offsets.
	offsetNr   = 0 // offsetof(struct seccomp_data, nr)
	offsetArch = 4 // offsetof(struct seccomp_data, arch)

	auditArchX86_64  = 0xC000003E
	auditArchAarch64 = 0xC00000B7
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

// buildPrefilterBPF generates the full prefilter (all traced syscalls).
func buildPrefilterBPF() ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(tracedSyscallNumbers())
}

// buildNarrowPrefilterBPF generates a BPF filter that excludes read/write
// syscalls from the traced set. Used as the initial filter; read/write are
// lazily escalated per-TGID when needed.
func buildNarrowPrefilterBPF() ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(narrowTracedSyscallNumbers())
}

// buildEscalationBPF generates a minimal BPF filter that traces only the
// specified syscalls. Installed on top of the narrow filter via seccomp
// stacking to add read/write when needed.
func buildEscalationBPF(syscalls []int) ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(syscalls)
}
