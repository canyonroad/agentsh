//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrefilterBPFNonEmpty(t *testing.T) {
	prog, err := buildPrefilterBPF(allFeaturesConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) == 0 {
		t.Fatal("buildPrefilterBPF returned empty filter")
	}
}

func TestPrefilterBPFInstructionCount(t *testing.T) {
	cfg := allFeaturesConfig()
	syscalls := tracedSyscallNumbers(cfg)
	prog, err := buildPrefilterBPF(cfg)
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
	cfg := allFeaturesConfig()
	syscalls := tracedSyscallNumbers(cfg)
	prog, err := buildPrefilterBPF(cfg)
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
	prog, err := buildPrefilterBPF(allFeaturesConfig())
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

func TestBuildBPFForActions(t *testing.T) {
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetTrace},
		{Nr: unix.SYS_CONNECT, Action: seccompRetErrno(int(unix.EACCES))},
	}
	prog, err := buildBPFForActions(actions)
	if err != nil {
		t.Fatal(err)
	}

	jeqValues := make(map[uint32]bool)
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJEQ|bpfK {
			if inst.K == auditArchX86_64 || inst.K == auditArchAarch64 {
				continue
			}
			jeqValues[inst.K] = true
		}
	}
	if !jeqValues[uint32(unix.SYS_OPENAT)] {
		t.Error("SYS_OPENAT missing from filter")
	}
	if !jeqValues[uint32(unix.SYS_CONNECT)] {
		t.Error("SYS_CONNECT missing from filter")
	}

	retInsts := 0
	for _, inst := range prog {
		if inst.Code == bpfRET|bpfK {
			retInsts++
		}
	}
	// Should have: unknown-arch TRACE, default ALLOW, TRACE, ERRNO = 4 ret instructions
	if retInsts < 3 {
		t.Errorf("expected at least 3 return instructions, got %d", retInsts)
	}
}

func TestBuildBPFForActionsErrnoValue(t *testing.T) {
	errno := int(unix.EPERM)
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_CONNECT, Action: seccompRetErrno(errno)},
	}
	prog, err := buildBPFForActions(actions)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, inst := range prog {
		if inst.Code == bpfRET|bpfK && inst.K != seccompRetAllow && inst.K != seccompRetTrace {
			want := uint32(0x00050000 | errno)
			if inst.K != want {
				t.Errorf("ERRNO return = 0x%x, want 0x%x", inst.K, want)
			}
			found = true
		}
	}
	if !found {
		t.Error("no ERRNO return instruction found")
	}
}

func TestSeccompRetErrnoEncoding(t *testing.T) {
	got := seccompRetErrno(int(unix.EACCES))
	want := uint32(0x00050000 | unix.EACCES)
	if got != want {
		t.Errorf("seccompRetErrno(EACCES) = 0x%x, want 0x%x", got, want)
	}
}

func TestStaticAllowsExcludedFromBPF(t *testing.T) {
	// Simulate the filtering logic from injectSeccompFilter:
	// narrowNums minus allows should not contain allowed syscalls.
	cfg := allFeaturesConfig()
	cfg.FileHandler = allowAllFileHandler{}
	narrowNums := narrowTracedSyscallNumbers(cfg)

	allows := make(map[int]bool)
	if checker, ok := cfg.FileHandler.(StaticAllowChecker); ok {
		for _, nr := range checker.StaticAllowSyscalls() {
			allows[nr] = true
		}
	}

	filtered := make([]int, 0, len(narrowNums))
	for _, nr := range narrowNums {
		if !allows[nr] {
			filtered = append(filtered, nr)
		}
	}

	// Build BPF from filtered set.
	prog, err := buildBPFForSyscalls(filtered)
	if err != nil {
		t.Fatal(err)
	}

	// Collect JEQ syscall numbers from BPF.
	jeqValues := make(map[uint32]bool)
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJEQ|bpfK {
			if inst.K == auditArchX86_64 || inst.K == auditArchAarch64 {
				continue
			}
			jeqValues[inst.K] = true
		}
	}

	// Allowed syscalls must NOT appear in BPF.
	for nr := range allows {
		if jeqValues[uint32(nr)] {
			t.Errorf("statically allowed syscall %d should not be in BPF filter", nr)
		}
	}

	// Non-allowed syscalls that were in narrowNums MUST appear.
	if !jeqValues[uint32(unix.SYS_CONNECT)] {
		t.Error("SYS_CONNECT should still be in BPF filter")
	}
	if !jeqValues[uint32(unix.SYS_EXECVE)] {
		t.Error("SYS_EXECVE should still be in BPF filter")
	}
}
