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

// --- buildBPFWithArgFilters tests ---

func TestBPFWithArgFilterOpenat(t *testing.T) {
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetTrace},
	}
	argFilters := []bpfArgFilter{
		{Nr: unix.SYS_OPENAT, ArgIndex: 2, Mask: openatWriteMask},
	}
	prog, err := buildBPFWithArgFilters(actions, argFilters, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify JSET instruction exists with mask openatWriteMask.
	foundJSET := false
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJSET|bpfK && inst.K == openatWriteMask {
			foundJSET = true
		}
	}
	if !foundJSET {
		t.Errorf("expected JSET instruction with mask 0x%x, not found", openatWriteMask)
	}

	// Verify LD instruction for args[2] at offset 32 (offsetArgs2Lo).
	foundLD := false
	for _, inst := range prog {
		if inst.Code == bpfLD|bpfW|bpfABS && inst.K == offsetArgs2Lo {
			foundLD = true
		}
	}
	if !foundLD {
		t.Errorf("expected LD instruction for args[2] at offset %d, not found", offsetArgs2Lo)
	}

	// Verify both ALLOW and TRACE return instructions exist.
	foundAllow, foundTrace := false, false
	for _, inst := range prog {
		if inst.Code == bpfRET|bpfK {
			if inst.K == seccompRetAllow {
				foundAllow = true
			}
			if inst.K == seccompRetTrace {
				foundTrace = true
			}
		}
	}
	if !foundAllow {
		t.Error("expected RET ALLOW instruction, not found")
	}
	if !foundTrace {
		t.Error("expected RET TRACE instruction, not found")
	}
}

func TestBPFWithArgFilterSendtoNull(t *testing.T) {
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_SENDTO, Action: seccompRetTrace},
	}
	nullFilters := []bpfNullPtrFilter{
		{Nr: unix.SYS_SENDTO, ArgIndex: 4},
	}
	prog, err := buildBPFWithArgFilters(actions, nil, nullFilters)
	if err != nil {
		t.Fatal(err)
	}

	// Verify two JEQ 0 instructions (for low and high halves of args[4]).
	jeqZeroCount := 0
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJEQ|bpfK && inst.K == 0 {
			jeqZeroCount++
		}
	}
	if jeqZeroCount < 2 {
		t.Errorf("expected at least 2 JEQ 0 instructions for null check, got %d", jeqZeroCount)
	}

	// Verify LD instructions for offsetArgs4Lo (48) and offsetArgs4Hi (52).
	foundLo, foundHi := false, false
	for _, inst := range prog {
		if inst.Code == bpfLD|bpfW|bpfABS {
			if inst.K == offsetArgs4Lo {
				foundLo = true
			}
			if inst.K == offsetArgs4Hi {
				foundHi = true
			}
		}
	}
	if !foundLo {
		t.Errorf("expected LD for offsetArgs4Lo (%d), not found", offsetArgs4Lo)
	}
	if !foundHi {
		t.Errorf("expected LD for offsetArgs4Hi (%d), not found", offsetArgs4Hi)
	}
}

func TestBPFWithArgFiltersNoFilters(t *testing.T) {
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetTrace},
		{Nr: unix.SYS_CONNECT, Action: seccompRetErrno(int(unix.EACCES))},
	}
	progWithFilters, err := buildBPFWithArgFilters(actions, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	progForActions, err := buildBPFForActions(actions)
	if err != nil {
		t.Fatal(err)
	}
	if len(progWithFilters) != len(progForActions) {
		t.Errorf("with no arg filters: instruction count = %d, want %d (same as buildBPFForActions)",
			len(progWithFilters), len(progForActions))
	}
}

func TestBPFWithArgFilterSkippedForDeny(t *testing.T) {
	// When a syscall has ERRNO action, arg filters for it should be skipped.
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetErrno(int(unix.EACCES))},
	}
	argFilters := []bpfArgFilter{
		{Nr: unix.SYS_OPENAT, ArgIndex: 2, Mask: openatWriteMask},
	}
	prog, err := buildBPFWithArgFilters(actions, argFilters, nil)
	if err != nil {
		t.Fatal(err)
	}

	// JSET should NOT appear — deny takes priority over arg filter.
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJSET|bpfK {
			t.Errorf("unexpected JSET instruction for syscall with ERRNO action")
		}
	}
}

func TestBPFWithArgFiltersOpenatAndSendto(t *testing.T) {
	// CRITICAL: combined test with both an arg filter (openat) and null filter (sendto).
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetTrace},
		{Nr: unix.SYS_SENDTO, Action: seccompRetTrace},
	}
	argFilters := []bpfArgFilter{
		{Nr: unix.SYS_OPENAT, ArgIndex: 2, Mask: openatWriteMask},
	}
	nullFilters := []bpfNullPtrFilter{
		{Nr: unix.SYS_SENDTO, ArgIndex: 4},
	}
	prog, err := buildBPFWithArgFilters(actions, argFilters, nullFilters)
	if err != nil {
		t.Fatal(err)
	}

	// Find the trailing RET TRACE (last instruction) and all RET instructions.
	lastIdx := len(prog) - 1
	if prog[lastIdx].Code != bpfRET|bpfK || prog[lastIdx].K != seccompRetTrace {
		t.Errorf("last instruction should be RET TRACE, got Code=0x%x K=0x%x",
			prog[lastIdx].Code, prog[lastIdx].K)
	}

	// Walk the program and verify that every JSET Jt target lands on a RET instruction.
	for i, inst := range prog {
		if inst.Code == bpfJMP|bpfJSET|bpfK {
			target := i + 1 + int(inst.Jt)
			if target >= len(prog) {
				t.Errorf("JSET at %d: Jt target %d out of bounds", i, target)
				continue
			}
			if prog[target].Code != bpfRET|bpfK {
				t.Errorf("JSET at %d: Jt target %d is not a RET (Code=0x%x)", i, target, prog[target].Code)
			}
		}
	}

	// Walk the program and verify every null-check JEQ 0 with Jf > 0 lands on a RET.
	for i, inst := range prog {
		if inst.Code == bpfJMP|bpfJEQ|bpfK && inst.K == 0 && inst.Jf > 0 {
			target := i + 1 + int(inst.Jf)
			if target >= len(prog) {
				t.Errorf("JEQ 0 at %d: Jf target %d out of bounds", i, target)
				continue
			}
			if prog[target].Code != bpfRET|bpfK {
				t.Errorf("JEQ 0 at %d: Jf target %d is not a RET (Code=0x%x)", i, target, prog[target].Code)
			}
		}
	}

	// Verify both check blocks exist: JSET with openatWriteMask and LD for args[4].
	foundJSET := false
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJSET|bpfK && inst.K == openatWriteMask {
			foundJSET = true
		}
	}
	if !foundJSET {
		t.Errorf("expected JSET with openatWriteMask (0x%x), not found", openatWriteMask)
	}

	foundArgs4 := false
	for _, inst := range prog {
		if inst.Code == bpfLD|bpfW|bpfABS && (inst.K == offsetArgs4Lo || inst.K == offsetArgs4Hi) {
			foundArgs4 = true
		}
	}
	if !foundArgs4 {
		t.Error("expected LD for args[4] (sendto null check), not found")
	}
}

func TestBPFWithArgFiltersInstructionLimit(t *testing.T) {
	cfg := allFeaturesConfig()
	narrowNums := narrowTracedSyscallNumbers(cfg)

	// Build actions from narrowTracedSyscallNumbers (all TRACE).
	actions := make([]bpfSyscallAction, len(narrowNums))
	for i, nr := range narrowNums {
		actions[i] = bpfSyscallAction{Nr: nr, Action: seccompRetTrace}
	}

	// Add arg filter for openat and null filter for sendto.
	argFilters := []bpfArgFilter{
		{Nr: unix.SYS_OPENAT, ArgIndex: 2, Mask: openatWriteMask},
	}
	nullFilters := []bpfNullPtrFilter{
		{Nr: unix.SYS_SENDTO, ArgIndex: 4},
	}

	prog, err := buildBPFWithArgFilters(actions, argFilters, nullFilters)
	if err != nil {
		t.Fatal(err)
	}

	const limit = 100
	if len(prog) >= limit {
		t.Errorf("instruction count = %d, want < %d", len(prog), limit)
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
