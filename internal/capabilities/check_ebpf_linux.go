//go:build linux

package capabilities

import (
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/agentsh/agentsh/internal/netmonitor/ebpf"
)

// Canary program used by probeEBPF. Exposed as package-level identifiers so
// TestProbeEBPFCanary can lock in the structure — see check_test.go. The bug
// fixed in #196 was an under-specified canary:
//
//   - instruction stream: a lone BPF_EXIT with r0 (the return-value register)
//     uninitialized, which the verifier rejects with EACCES even on fully
//     functional systems. The errno string surfaces as "permission denied",
//     making the false-negative look like a missing capability.
//   - prog type: value 13 with a comment claiming BPF_PROG_TYPE_CGROUP_SKB,
//     but value 13 is actually BPF_PROG_TYPE_SOCK_OPS (CGROUP_SKB is 8).
//
// The canary is now the minimal verifier-accepted program (r0 = 0; exit;)
// loaded as BPF_PROG_TYPE_CGROUP_SKB (8) — the same program type used by
// internal/netmonitor/ebpf for cgroup-attached network tracing. For
// CGROUP_SKB, r0 is the packet verdict (0 = drop, 1 = allow); both are valid
// return values, so `r0 = 0; exit;` satisfies the verifier.
var probeEBPFCanaryInsns = [16]byte{
	0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
}

const (
	probeEBPFCanaryProgType uint32 = 8 // BPF_PROG_TYPE_CGROUP_SKB
	probeEBPFCanaryInsnCnt  uint32 = 2
)

// probeEBPF determines whether the process can use cgroup-attached eBPF
// network tracing. It first runs the same environment checks used by the
// actual netmonitor (ebpf.CheckSupport: cgroup v2, BTF, CAP_BPF/CAP_SYS_ADMIN,
// kernel >= 5.8), and only then attempts a minimal BPF_PROG_LOAD canary to
// confirm that BPF_PROG_LOAD itself is not blocked by seccomp, lockdown, or
// an LSM policy. Aligning with CheckSupport keeps capability reporting
// consistent with runtime behavior so strict-mode validation and policy
// warnings don't claim eBPF enforcement is available when the real attach
// path will still fail.
func probeEBPF() ProbeResult {
	if status := ebpf.CheckSupport(); !status.Supported {
		return ProbeResult{Available: false, Detail: status.Reason}
	}

	license := [4]byte{'G', 'P', 'L', 0}
	type bpfProgLoadAttr struct {
		progType    uint32
		insnCnt     uint32
		insns       uint64
		license     uint64
		logLevel    uint32
		logSize     uint32
		logBuf      uint64
		kernVersion uint32
	}
	attr := bpfProgLoadAttr{
		progType: probeEBPFCanaryProgType,
		insnCnt:  probeEBPFCanaryInsnCnt,
		insns:    uint64(uintptr(unsafe.Pointer(&probeEBPFCanaryInsns[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 5, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno == 0 {
		unix.Close(int(fd))
		return ProbeResult{Available: true, Detail: "cgroup_skb"}
	}
	switch errno {
	case unix.EPERM:
		return ProbeResult{Available: false, Detail: "EPERM (BPF_PROG_LOAD denied)"}
	case unix.EACCES:
		return ProbeResult{Available: false, Detail: "EACCES (BPF verifier rejected canary)"}
	case unix.ENOSYS:
		return ProbeResult{Available: false, Detail: "ENOSYS (kernel too old)"}
	default:
		return ProbeResult{Available: false, Detail: errno.Error()}
	}
}
