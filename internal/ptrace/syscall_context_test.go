//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSyscallContextLazyRegs(t *testing.T) {
	sc := &SyscallContext{
		Info: SyscallEntryInfo{
			Nr:   unix.SYS_OPENAT,
			Args: [6]uint64{0xFFFFFF9C, 0x7FFF1234, 0, 0, 0, 0},
		},
	}
	if sc.loaded {
		t.Error("regs should not be loaded initially")
	}
	if sc.Info.Nr != unix.SYS_OPENAT {
		t.Errorf("Nr = %d, want SYS_OPENAT", sc.Info.Nr)
	}
	if sc.Info.Args[0] != 0xFFFFFF9C {
		t.Errorf("Args[0] = 0x%x, want 0xFFFFFF9C", sc.Info.Args[0])
	}
}
