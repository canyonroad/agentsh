//go:build linux

package ptrace

import "testing"

func TestPrefilterBPFNonEmpty(t *testing.T) {
	prog, err := buildPrefilterBPF()
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) == 0 {
		t.Fatal("buildPrefilterBPF returned empty filter")
	}
}

func TestPrefilterBPFInstructionCount(t *testing.T) {
	syscalls := tracedSyscallNumbers()
	prog, err := buildPrefilterBPF()
	if err != nil {
		t.Fatal(err)
	}

	// 4 header instructions + len(syscalls) comparisons + 2 return instructions.
	want := 4 + len(syscalls) + 2
	if len(prog) != want {
		t.Errorf("instruction count = %d, want %d (4 header + %d comparisons + 2 returns)",
			len(prog), want, len(syscalls))
	}
}

func TestPrefilterBPFContainsAllSyscalls(t *testing.T) {
	syscalls := tracedSyscallNumbers()
	prog, err := buildPrefilterBPF()
	if err != nil {
		t.Fatal(err)
	}

	// Collect all K values from JEQ instructions.
	jeqValues := make(map[uint32]bool)
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJEQ|bpfK {
			// Skip the architecture check instruction.
			if inst.K == auditArchX86_64 || inst.K == auditArchAarch64 {
				continue
			}
			jeqValues[inst.K] = true
		}
	}

	for _, nr := range syscalls {
		if !jeqValues[uint32(nr)] {
			t.Errorf("syscall %d not found as JEQ instruction in filter", nr)
		}
	}
}

func TestPrefilterBPFArchCheck(t *testing.T) {
	prog, err := buildPrefilterBPF()
	if err != nil {
		t.Fatal(err)
	}

	// First instruction must load the architecture field.
	if prog[0].Code != bpfLD|bpfW|bpfABS || prog[0].K != offsetArch {
		t.Errorf("first instruction should load arch (offset %d), got Code=0x%x K=%d",
			offsetArch, prog[0].Code, prog[0].K)
	}

	// Second instruction must be a JEQ comparing the audit arch.
	if prog[1].Code != bpfJMP|bpfJEQ|bpfK {
		t.Errorf("second instruction should be JEQ, got Code=0x%x", prog[1].Code)
	}
	if prog[1].K != auditArchX86_64 && prog[1].K != auditArchAarch64 {
		t.Errorf("arch check compares unexpected value 0x%X", prog[1].K)
	}
}
