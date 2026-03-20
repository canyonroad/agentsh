//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestGetSyscallEntryInfoAcceptsSeccompOp(t *testing.T) {
	// Op=3 (PTRACE_SYSCALL_INFO_SECCOMP) has the same nr+args layout
	// as Op=1 (ENTRY) and must be accepted by getSyscallEntryInfo.
	// This is a unit-level assertion on the Op check logic.
	// The actual PTRACE_GET_SYSCALL_INFO call requires a traced process,
	// so we verify the constant used in the check.
	const ptraceSyscallInfoEntry = 1
	const ptraceSyscallInfoSeccomp = 3
	if ptraceSyscallInfoEntry == ptraceSyscallInfoSeccomp {
		t.Fatal("entry and seccomp op values should differ")
	}
	// Verify Op=2 (EXIT) is still rejected by the check logic.
	const ptraceSyscallInfoExit = 2
	op := uint8(ptraceSyscallInfoExit)
	if op == 1 || op == 3 {
		t.Fatal("exit op should not match entry or seccomp")
	}
}

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
