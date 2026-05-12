//go:build linux && cgo

package unix

import (
	"encoding/binary"
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// TestExportBPFViaPipe builds a minimal filter and asserts the exporter
// returns a non-empty BPF program whose first instruction is a valid
// libseccomp prologue: BPF_LD | BPF_W | BPF_ABS loading a seccomp_data
// field (arch at offset 4 on >=2.2, nr at offset 0 on older versions).
func TestExportBPFViaPipe(t *testing.T) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	if err := filt.AddRule(seccomp.ScmpSyscall(unix.SYS_GETPID), seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	prog, err := exportFilterBPF(filt)
	if err != nil {
		t.Fatalf("exportFilterBPF: %v", err)
	}
	if len(prog) == 0 {
		t.Fatalf("exportFilterBPF returned empty program")
	}
	if len(prog)%8 != 0 {
		t.Fatalf("BPF program length %d is not a multiple of 8 (sock_filter size)", len(prog))
	}
	// First sock_filter: code uint16, jt uint8, jf uint8, k uint32.
	// libseccomp prologue is BPF_LD|BPF_W|BPF_ABS (0x20) loading a seccomp_data
	// field: k=0 (nr) on older libseccomp or k=4 (arch) on >=2.2 which emits
	// an arch-check as the very first instruction.
	code := binary.LittleEndian.Uint16(prog[0:2])
	k := binary.LittleEndian.Uint32(prog[4:8])
	const bpfLdWAbs = 0x20
	if code != bpfLdWAbs {
		t.Fatalf("first BPF instruction code = 0x%x, want 0x%x (BPF_LD|BPF_W|BPF_ABS)", code, bpfLdWAbs)
	}
	// k must be a valid seccomp_data field offset: 0 (nr), 4 (arch), 8 (ip), or 16+ (args).
	if k != 0 && k != 4 {
		t.Fatalf("first BPF instruction k = %d, want 0 (seccomp_data.nr) or 4 (seccomp_data.arch)", k)
	}
}
