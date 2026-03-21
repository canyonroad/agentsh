//go:build linux

package capabilities

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func probeEBPF() ProbeResult {
	insn := [8]byte{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // BPF_EXIT
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
		progType: 13, // BPF_PROG_TYPE_CGROUP_SKB
		insnCnt:  1,
		insns:    uint64(uintptr(unsafe.Pointer(&insn[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 5, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno == 0 {
		unix.Close(int(fd))
		return ProbeResult{Available: true, Detail: "cgroup_skb"}
	}
	switch errno {
	case unix.EPERM:
		return ProbeResult{Available: false, Detail: "EPERM (missing CAP_BPF)"}
	case unix.ENOSYS:
		return ProbeResult{Available: false, Detail: "ENOSYS (kernel too old)"}
	default:
		return ProbeResult{Available: false, Detail: errno.Error()}
	}
}
