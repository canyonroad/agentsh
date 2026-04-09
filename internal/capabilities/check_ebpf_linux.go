//go:build linux

package capabilities

import (
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/agentsh/agentsh/internal/netmonitor/ebpf"
)

// Canary program used by probeEBPF. Exposed as package-level identifiers so
// TestProbeEBPFCanary can lock in the structure. The bug fixed in #196 was an
// under-specified canary:
//
//   - instruction stream: a lone BPF_EXIT with r0 (the return-value register)
//     uninitialized, which the verifier rejects with EACCES even on fully
//     functional systems. The errno string surfaces as "permission denied",
//     making the false-negative look like a missing capability.
//   - prog type: value 13 with a comment claiming BPF_PROG_TYPE_CGROUP_SKB,
//     but value 13 is actually BPF_PROG_TYPE_SOCK_OPS. Worse, the real
//     netmonitor does not load skb programs at all — it loads
//     `cgroup/connect*` and `cgroup/sendmsg*` hooks, which are
//     BPF_PROG_TYPE_CGROUP_SOCK_ADDR programs with `struct bpf_sock_addr`
//     contexts.
//
// The canary now matches the runtime program family:
//
//   - prog_type = BPF_PROG_TYPE_CGROUP_SOCK_ADDR (18)
//   - expected_attach_type = BPF_CGROUP_INET4_CONNECT (10) — one of the
//     attach types the kernel accepts for CGROUP_SOCK_ADDR; without a valid
//     expected_attach_type the kernel rejects the load with EINVAL.
//   - instructions = { r0 = 0; exit; } — 16 bytes. For CGROUP_SOCK_ADDR,
//     r0 is the verdict (0 = deny, 1 = allow); both are valid, so the
//     verifier accepts `r0 = 0`.
var probeEBPFCanaryInsns = [16]byte{
	0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
}

const (
	probeEBPFCanaryProgType           uint32 = 18 // BPF_PROG_TYPE_CGROUP_SOCK_ADDR
	probeEBPFCanaryInsnCnt            uint32 = 2
	probeEBPFCanaryExpectedAttachType uint32 = 10 // BPF_CGROUP_INET4_CONNECT
)

// bpfProgLoadAttr matches the prog_load variant of `union bpf_attr` through
// the expected_attach_type field. The kernel reads `attr_size` bytes from
// userspace and zero-pads the rest, so any fields beyond expected_attach_type
// are implicitly zero.
type bpfProgLoadAttr struct {
	progType           uint32
	insnCnt            uint32
	insns              uint64
	license            uint64
	logLevel           uint32
	logSize            uint32
	logBuf             uint64
	kernVersion        uint32
	progFlags          uint32
	progName           [16]byte
	progIfindex        uint32
	expectedAttachType uint32
}

// probeEBPF determines whether the process can use cgroup-attached eBPF
// network tracing. It first runs the same environment checks used by the
// actual netmonitor (ebpf.CheckSupport: cgroup v2, BTF, CAP_BPF/CAP_SYS_ADMIN,
// kernel >= 5.8), and only then attempts a minimal BPF_PROG_LOAD canary to
// confirm that BPF_PROG_LOAD for the netmonitor's program family is not
// blocked by seccomp, lockdown, or an LSM policy. Aligning with CheckSupport
// and the real program type keeps capability reporting consistent with
// runtime behavior so strict-mode validation and policy warnings don't claim
// eBPF enforcement is available when the real attach path will still fail.
func probeEBPF() ProbeResult {
	if status := ebpf.CheckSupport(); !status.Supported {
		return ProbeResult{Available: false, Detail: status.Reason}
	}

	license := [4]byte{'G', 'P', 'L', 0}
	attr := bpfProgLoadAttr{
		progType:           probeEBPFCanaryProgType,
		insnCnt:            probeEBPFCanaryInsnCnt,
		insns:              uint64(uintptr(unsafe.Pointer(&probeEBPFCanaryInsns[0]))),
		license:            uint64(uintptr(unsafe.Pointer(&license[0]))),
		expectedAttachType: probeEBPFCanaryExpectedAttachType,
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 5, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno == 0 {
		unix.Close(int(fd))
		return ProbeResult{Available: true, Detail: "cgroup_sock_addr"}
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
