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

// buildPrefilterBPF generates a seccomp-BPF filter that returns
// SECCOMP_RET_TRACE for syscalls the tracer handles and
// SECCOMP_RET_ALLOW for everything else.
func buildPrefilterBPF() ([]unix.SockFilter, error) {
	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = auditArchX86_64
	case "arm64":
		auditArch = auditArchAarch64
	default:
		return nil, fmt.Errorf("seccomp prefilter: unsupported architecture %s", runtime.GOARCH)
	}

	syscalls := tracedSyscallNumbers()

	// Program layout:
	//   [0] LD arch
	//   [1] JEQ auditArch -> skip ALLOW (jt=1), fall through (jf=0)
	//   [2] RET ALLOW  (wrong arch)
	//   [3] LD nr
	//   [4..4+len-1] JEQ for each syscall
	//   [4+len] RET ALLOW  (default, no match)
	//   [4+len+1] RET TRACE (matched)

	n := len(syscalls)
	prog := make([]unix.SockFilter, 0, 4+n+2)

	// Load architecture.
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetArch})

	// Check architecture: if match jump over the ALLOW, otherwise fall through to ALLOW.
	prog = append(prog, unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: auditArch})

	// Wrong architecture: allow.
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})

	// Load syscall number.
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetNr})

	// Compare each traced syscall. On match, jump to the RET TRACE
	// instruction at the end. On mismatch, fall through to the next compare.
	for i, nr := range syscalls {
		remaining := n - i - 1 // remaining compare instructions after this one
		jumpToTrace := uint8(remaining + 1) // +1 for the default RET ALLOW
		prog = append(prog, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jumpToTrace,
			Jf:   0,
			K:    uint32(nr),
		})
	}

	// Default: allow.
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})

	// Matched: trace.
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})

	return prog, nil
}
