//go:build linux

package capabilities

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Canary program used by probeEBPF. Exposed as package-level vars so a
// regression test can lock in the structure — see TestProbeEBPFCanary in
// check_test.go. The bug fixed in #196 was an under-specified canary
// (single BPF_EXIT with uninitialized r0), which the BPF verifier rejects
// with EACCES even on fully functional systems.
//
// The canary is the minimal verifier-accepted program:
//
//	r0 = 0   (BPF_ALU64 | BPF_MOV | BPF_K, dst=r0, imm=0)  -> 0xb7
//	exit     (BPF_JMP   | BPF_EXIT)                         -> 0x95
//
// Program type BPF_PROG_TYPE_SOCKET_FILTER (1) is chosen because it is the
// lowest-privilege type, runnable without CAP_BPF/CAP_SYS_ADMIN on kernels
// where unprivileged BPF is enabled.
var probeEBPFCanaryInsns = [16]byte{
	0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
}

const (
	probeEBPFCanaryProgType uint32 = 1 // BPF_PROG_TYPE_SOCKET_FILTER
	probeEBPFCanaryInsnCnt  uint32 = 2
)

// probeEBPF attempts to load a minimal BPF program to determine whether the
// current process can use eBPF.
func probeEBPF() ProbeResult {
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
		return ProbeResult{Available: true, Detail: "socket_filter"}
	}
	switch errno {
	case unix.EPERM:
		return ProbeResult{Available: false, Detail: "EPERM (missing CAP_BPF/CAP_SYS_ADMIN or unprivileged_bpf_disabled)"}
	case unix.EACCES:
		return ProbeResult{Available: false, Detail: "EACCES (BPF verifier rejected canary)"}
	case unix.ENOSYS:
		return ProbeResult{Available: false, Detail: "ENOSYS (kernel too old)"}
	default:
		return ProbeResult{Available: false, Detail: errno.Error()}
	}
}
