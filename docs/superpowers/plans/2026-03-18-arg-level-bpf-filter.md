# Argument-Level BPF Filter Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the seccomp BPF prefilter to check syscall arguments (openat flags, sendto dest_addr) so read-only opens and connected-socket sends skip ptrace entirely.

**Architecture:** Add new BPF instruction types (JSET for bitmask, JEQ for null-ptr) to the existing filter generator. A new `buildBPFWithArgFilters` function emits arg-check blocks after the syscall-number scan. Wired into `injectSeccompFilter` behind a config flag `ArgLevelFilter`.

**Tech Stack:** Go, classic BPF (cBPF), seccomp, unix syscalls

**Spec:** `docs/superpowers/specs/2026-03-18-arg-level-bpf-filtering-design.md`

---

### Task 1: Add ArgLevelFilter config field

**Files:**
- Modify: `internal/config/ptrace.go:25-31` (PtracePerformanceConfig struct)
- Modify: `internal/config/ptrace.go:33-51` (DefaultPtraceConfig)
- Modify: `internal/config/ptrace_test.go:11-38` (TestDefaultPtraceConfig)

- [ ] **Step 1: Write the failing test**

Add assertion in `TestDefaultPtraceConfig`:

```go
// In TestDefaultPtraceConfig, after the MaxHoldMs check (line 31):
if !cfg.Performance.ArgLevelFilter {
	t.Error("arg_level_filter should be enabled by default")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestDefaultPtraceConfig -v`
Expected: FAIL — `ArgLevelFilter` field doesn't exist yet.

- [ ] **Step 3: Add the field and default**

In `internal/config/ptrace.go`, add `ArgLevelFilter` to the struct:

```go
type PtracePerformanceConfig struct {
	SeccompPrefilter   bool `yaml:"seccomp_prefilter"`
	MaxTracees         int  `yaml:"max_tracees"`
	MaxHoldMs          int  `yaml:"max_hold_ms"`
	StaticAllowFile    bool `yaml:"static_allow_file"`
	StaticAllowNetwork bool `yaml:"static_allow_network"`
	ArgLevelFilter     bool `yaml:"arg_level_filter"`
}
```

In `DefaultPtraceConfig`, set the default to `true`:

```go
Performance: PtracePerformanceConfig{
	SeccompPrefilter: true,
	MaxTracees:       500,
	MaxHoldMs:        5000,
	ArgLevelFilter:   true,
},
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -run TestDefaultPtraceConfig -v`
Expected: PASS

- [ ] **Step 5: Add ArgLevelFilter to TracerConfig**

In `internal/ptrace/tracer.go`, add field after `SeccompPrefilter` (line 135):

```go
ArgLevelFilter   bool
```

- [ ] **Step 6: Wire config in app_ptrace_linux.go**

In `internal/api/app_ptrace_linux.go`, add to the TracerConfig literal (after line 34):

```go
ArgLevelFilter:   cfg.Performance.ArgLevelFilter,
```

- [ ] **Step 7: Verify build**

Run: `go build ./...`
Expected: Compiles with no errors.

- [ ] **Step 8: Commit**

```bash
git add internal/config/ptrace.go internal/config/ptrace_test.go \
       internal/ptrace/tracer.go internal/api/app_ptrace_linux.go
git commit -m "feat(ptrace): add ArgLevelFilter config field

Adds performance.arg_level_filter config option (default: true).
When enabled with seccomp_prefilter, BPF filters will check syscall
arguments to skip ptrace stops for safe patterns."
```

---

### Task 2: Add BPF constants and arg filter types

**Files:**
- Modify: `internal/ptrace/seccomp_filter.go:12-33` (constants block)

- [ ] **Step 1: Add new BPF constants and types**

In `internal/ptrace/seccomp_filter.go`, add to the constants block (after line 20, the `bpfRET` line):

```go
bpfJSET = 0x40
```

Add `seccomp_data` argument offsets (after line 29, the `offsetArch` line):

```go
// seccomp_data argument offsets.
// struct seccomp_data { int nr; __u32 arch; __u64 ip; __u64 args[6]; }
// args[i] is at offset 16 + i*8. Classic BPF loads 32-bit words, so
// the low 32 bits of args[i] are at offset 16+i*8, high at 16+i*8+4.
offsetArgs0Lo = 16
offsetArgs2Lo = 32 // openat flags
offsetArgs4Lo = 48 // sendto dest_addr low
offsetArgs4Hi = 52 // sendto dest_addr high
```

Add the openat flag mask constant:

```go
// openatWriteMask is the bitmask of openat flags that indicate a
// non-read-only operation. O_WRONLY|O_RDWR|O_CREAT|__O_TMPFILE.
// If (flags & openatWriteMask) == 0, the open is read-only.
openatWriteMask = 0x400043
```

Add the two arg filter types after the `bpfSyscallAction` type (after line 83):

```go
// bpfArgFilter describes a bitmask check on a syscall argument.
// If (arg & Mask) != 0 → TRACE, else → ALLOW.
// Only applicable to arguments that are scalar values (flags, sizes),
// NOT pointers — classic BPF cannot dereference pointers.
type bpfArgFilter struct {
	Nr       int    // syscall number
	ArgIndex int    // 0-5
	Mask     uint32 // bitmask for JSET
}

// bpfNullPtrFilter describes a NULL-pointer check on a syscall argument.
// If arg == 0 (both 32-bit halves) → ALLOW, else → TRACE.
type bpfNullPtrFilter struct {
	Nr       int // syscall number
	ArgIndex int // 0-5
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./internal/ptrace/...`
Expected: Compiles. Types are unused for now (that's OK, they'll be used in Task 3).

- [ ] **Step 3: Commit**

```bash
git add internal/ptrace/seccomp_filter.go
git commit -m "feat(ptrace): add BPF constants and arg filter types

Adds JSET opcode, seccomp_data argument offsets, openat write mask
constant, and bpfArgFilter/bpfNullPtrFilter types for argument-level
BPF filtering."
```

---

### Task 3: Implement buildBPFWithArgFilters

**Files:**
- Modify: `internal/ptrace/seccomp_filter.go` (add new function after `buildBPFForActions`)
- Modify: `internal/ptrace/seccomp_filter_test.go` (add tests)

- [ ] **Step 1: Write test for openat arg filter**

Add to `internal/ptrace/seccomp_filter_test.go`:

```go
func TestBPFWithArgFilterOpenat(t *testing.T) {
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetTrace},
		{Nr: unix.SYS_CONNECT, Action: seccompRetTrace},
	}
	argFilters := []bpfArgFilter{
		{Nr: unix.SYS_OPENAT, ArgIndex: 2, Mask: openatWriteMask},
	}
	prog, err := buildBPFWithArgFilters(actions, argFilters, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify JSET instruction exists with correct mask.
	foundJSET := false
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJSET|bpfK && inst.K == openatWriteMask {
			foundJSET = true
		}
	}
	if !foundJSET {
		t.Error("expected JSET instruction with openatWriteMask")
	}

	// Verify arg load instruction exists for args[2] (offset 32).
	foundArgLoad := false
	for _, inst := range prog {
		if inst.Code == bpfLD|bpfW|bpfABS && inst.K == offsetArgs2Lo {
			foundArgLoad = true
		}
	}
	if !foundArgLoad {
		t.Error("expected LD W ABS instruction for args[2] at offset 32")
	}

	// Verify both ALLOW and TRACE return instructions exist.
	retValues := make(map[uint32]bool)
	for _, inst := range prog {
		if inst.Code == bpfRET|bpfK {
			retValues[inst.K] = true
		}
	}
	if !retValues[seccompRetAllow] {
		t.Error("missing SECCOMP_RET_ALLOW return")
	}
	if !retValues[seccompRetTrace] {
		t.Error("missing SECCOMP_RET_TRACE return")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestBPFWithArgFilterOpenat -v`
Expected: FAIL — `buildBPFWithArgFilters` doesn't exist yet.

- [ ] **Step 3: Write test for sendto null-ptr filter**

```go
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

	// Verify load instructions for both halves of args[4].
	foundLo := false
	foundHi := false
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
		t.Error("expected LD instruction for args[4] low (offset 48)")
	}
	if !foundHi {
		t.Error("expected LD instruction for args[4] high (offset 52)")
	}

	// Two JEQ 0 instructions for the null check.
	jeqZeroCount := 0
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJEQ|bpfK && inst.K == 0 {
			jeqZeroCount++
		}
	}
	if jeqZeroCount < 2 {
		t.Errorf("expected at least 2 JEQ 0 instructions for null check, got %d", jeqZeroCount)
	}
}
```

- [ ] **Step 4: Write test for no-arg-filters passthrough**

```go
func TestBPFWithArgFiltersNoFilters(t *testing.T) {
	// With no arg/null filters, should behave like buildBPFForActions.
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetTrace},
		{Nr: unix.SYS_CONNECT, Action: seccompRetErrno(int(unix.EACCES))},
	}
	prog, err := buildBPFWithArgFilters(actions, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	progOld, err := buildBPFForActions(actions)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) != len(progOld) {
		t.Errorf("with no filters, instruction count %d != buildBPFForActions count %d",
			len(prog), len(progOld))
	}
}
```

- [ ] **Step 5: Write test for arg filter skipped on static deny**

```go
func TestBPFWithArgFilterSkippedForDeny(t *testing.T) {
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetErrno(int(unix.EPERM))},
	}
	argFilters := []bpfArgFilter{
		{Nr: unix.SYS_OPENAT, ArgIndex: 2, Mask: openatWriteMask},
	}
	prog, err := buildBPFWithArgFilters(actions, argFilters, nil)
	if err != nil {
		t.Fatal(err)
	}

	// JSET should NOT appear — deny action takes priority over arg filter.
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJSET|bpfK {
			t.Error("JSET should not appear when syscall has ERRNO action")
		}
	}
}
```

- [ ] **Step 6: Write test for combined arg + null filters with jump verification**

```go
func TestBPFWithArgFiltersOpenatAndSendto(t *testing.T) {
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetTrace},
		{Nr: unix.SYS_SENDTO, Action: seccompRetTrace},
		{Nr: unix.SYS_CONNECT, Action: seccompRetTrace},
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

	// Walk the program and verify that every JSET Jt and null-check JEQ Jf
	// land on a RET instruction, not a LD or other non-terminal.
	for i, inst := range prog {
		if inst.Code == bpfJMP|bpfJSET|bpfK {
			target := i + 1 + int(inst.Jt)
			if target >= len(prog) {
				t.Errorf("JSET at %d: Jt=%d jumps past end (len=%d)", i, inst.Jt, len(prog))
			} else if prog[target].Code != bpfRET|bpfK {
				t.Errorf("JSET at %d: Jt=%d lands on instruction 0x%x, expected RET", i, inst.Jt, prog[target].Code)
			}
		}
	}

	// Verify both arg check blocks exist (JSET + two LD for lo/hi).
	foundJSET := false
	foundNullLo := false
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJSET|bpfK && inst.K == openatWriteMask {
			foundJSET = true
		}
		if inst.Code == bpfLD|bpfW|bpfABS && inst.K == offsetArgs4Lo {
			foundNullLo = true
		}
	}
	if !foundJSET {
		t.Error("missing openat JSET instruction")
	}
	if !foundNullLo {
		t.Error("missing sendto null-check LD instruction")
	}
}
```

- [ ] **Step 6b: Write test for instruction limit**

```go
func TestBPFWithArgFiltersInstructionLimit(t *testing.T) {
	cfg := allFeaturesConfig()
	narrowNums := narrowTracedSyscallNumbers(cfg)
	var actions []bpfSyscallAction
	for _, nr := range narrowNums {
		actions = append(actions, bpfSyscallAction{Nr: nr, Action: seccompRetTrace})
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
	if len(prog) > 4096 {
		t.Errorf("BPF program exceeds 4096 instruction limit: %d", len(prog))
	}
	// Sanity: should be well under 100 instructions for our small traced set.
	if len(prog) > 100 {
		t.Errorf("BPF program unexpectedly large: %d instructions", len(prog))
	}
}
```

- [ ] **Step 7: Implement buildBPFWithArgFilters**

Add to `internal/ptrace/seccomp_filter.go` after `buildBPFForActions` (after line 140):

```go
// buildBPFWithArgFilters generates a seccomp-BPF filter with per-syscall
// return actions AND argument-level checks. Syscalls with arg filters jump
// to check blocks at the end of the program instead of directly to their
// return action. Arg filters are only applied to syscalls with TRACE action;
// syscalls with ERRNO actions are not filtered (deny takes priority).
func buildBPFWithArgFilters(
	actions []bpfSyscallAction,
	argFilters []bpfArgFilter,
	nullFilters []bpfNullPtrFilter,
) ([]unix.SockFilter, error) {
	// If no arg/null filters, delegate to existing builder.
	if len(argFilters) == 0 && len(nullFilters) == 0 {
		return buildBPFForActions(actions)
	}

	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = auditArchX86_64
	case "arm64":
		auditArch = auditArchAarch64
	default:
		return nil, fmt.Errorf("seccomp prefilter: unsupported architecture %s", runtime.GOARCH)
	}

	// Build lookup maps for arg filters. Only apply to TRACE actions.
	argFilterMap := make(map[int]*bpfArgFilter)
	for i := range argFilters {
		argFilterMap[argFilters[i].Nr] = &argFilters[i]
	}
	nullFilterMap := make(map[int]*bpfNullPtrFilter)
	for i := range nullFilters {
		nullFilterMap[nullFilters[i].Nr] = &nullFilters[i]
	}

	// Remove arg/null filters for non-TRACE actions (deny takes priority).
	for _, a := range actions {
		if a.Action != seccompRetTrace {
			delete(argFilterMap, a.Nr)
			delete(nullFilterMap, a.Nr)
		}
	}

	// Count check blocks to calculate jump offsets.
	// Each arg filter block: 3 instructions (load + JSET + RET ALLOW)
	// Each null filter block: 5 instructions (load lo + JEQ + RET TRACE + load hi + JEQ→ALLOW / RET TRACE)
	type checkBlock struct {
		nr        int
		argFilter *bpfArgFilter
		nullFilter *bpfNullPtrFilter
		offset    int // instruction offset within the check blocks section
	}
	var blocks []checkBlock
	blockOffset := 0
	for _, a := range actions {
		if af, ok := argFilterMap[a.Nr]; ok {
			blocks = append(blocks, checkBlock{nr: a.Nr, argFilter: af, offset: blockOffset})
			blockOffset += 3 // load + JSET + RET ALLOW
		} else if nf, ok := nullFilterMap[a.Nr]; ok {
			blocks = append(blocks, checkBlock{nr: a.Nr, nullFilter: nf, offset: blockOffset})
			blockOffset += 5 // load lo + JEQ 0 + RET TRACE + load hi + JEQ 0→ALLOW or TRACE
		}
	}

	// Build block lookup by syscall number.
	blockByNr := make(map[int]*checkBlock)
	for i := range blocks {
		blockByNr[blocks[i].nr] = &blocks[i]
	}

	// Collect unique return actions (deduplicate) — same as buildBPFForActions.
	retActionSet := make(map[uint32]int)
	var retActions []uint32
	for _, a := range actions {
		if _, ok := retActionSet[a.Action]; !ok {
			retActionSet[a.Action] = len(retActions)
			retActions = append(retActions, a.Action)
		}
	}

	n := len(actions)
	nRet := len(retActions)
	// Total: 4 header + n comparisons + 1 default ALLOW + nRet action returns + blockOffset check instructions + 1 ALLOW for checks
	totalCheckInsts := blockOffset
	prog := make([]unix.SockFilter, 0, 4+n+1+nRet+totalCheckInsts+1)

	// Header: load arch, check arch, load nr.
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetArch})
	prog = append(prog, unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: auditArch})
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetNr})

	// Comparisons section: each JEQ jumps to its target.
	// Layout after comparisons:
	//   [default ALLOW] [action0 ret] ... [actionN ret] [check blocks...] [check ALLOW]
	//
	// For syscalls WITH an arg check block, JEQ jumps to the check block.
	// For syscalls WITHOUT, JEQ jumps to the action return (same as buildBPFForActions).
	checksStart := 1 + nRet // offset from last comparison to start of check blocks
	for i, a := range actions {
		remaining := n - i - 1

		if blk, ok := blockByNr[a.Nr]; ok {
			// Jump to check block.
			jumpTarget := uint8(remaining + checksStart + blk.offset)
			prog = append(prog, unix.SockFilter{
				Code: bpfJMP | bpfJEQ | bpfK,
				Jt:   jumpTarget,
				Jf:   0,
				K:    uint32(a.Nr),
			})
		} else {
			// Jump to action return (same as buildBPFForActions).
			jumpTarget := uint8(remaining + 1 + retActionSet[a.Action])
			prog = append(prog, unix.SockFilter{
				Code: bpfJMP | bpfJEQ | bpfK,
				Jt:   jumpTarget,
				Jf:   0,
				K:    uint32(a.Nr),
			})
		}
	}

	// Default: ALLOW (unmatched syscalls).
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})

	// Per-action return instructions.
	for _, action := range retActions {
		prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: action})
	}

	// Check blocks section.
	// Each block ends with an inline RET ALLOW for the "safe" case.
	// The "unsafe" case must jump to the trailing RET TRACE at the end.
	// Jump offsets are calculated dynamically based on block position.
	// The trailing RET TRACE is at offset totalCheckInsts within the
	// check blocks section.
	for _, blk := range blocks {
		if blk.argFilter != nil {
			// Arg bitmask check: 3 instructions.
			// [blk.offset+0] LD W ABS <arg offset>
			// [blk.offset+1] JSET mask → TRACE (Jt), fall through to ALLOW (Jf)
			// [blk.offset+2] RET ALLOW (read-only / safe case)
			af := blk.argFilter
			argOffset := uint32(offsetArgs0Lo + af.ArgIndex*8)
			prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: argOffset})

			// JSET is at position blk.offset+1 within check blocks.
			// Trailing RET TRACE is at position totalCheckInsts.
			// BPF Jt skips forward from NEXT instruction, so:
			// distance = totalCheckInsts - (blk.offset+1) - 1 = totalCheckInsts - blk.offset - 2
			jsetToTrace := uint8(totalCheckInsts - blk.offset - 2)
			prog = append(prog, unix.SockFilter{
				Code: bpfJMP | bpfJSET | bpfK,
				Jt:   jsetToTrace, // bits set → jump to trailing RET TRACE
				Jf:   0,           // no bits → fall through to RET ALLOW
				K:    af.Mask,
			})
			// Fall-through: no write flags → ALLOW.
			prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})

		} else if blk.nullFilter != nil {
			// Null pointer check: 5 instructions.
			// [blk.offset+0] LD W ABS <arg_lo>       — load low 32 bits
			// [blk.offset+1] JEQ 0: Jt=0 (check hi), Jf→trailing TRACE
			// [blk.offset+2] LD W ABS <arg_hi>       — load high 32 bits
			// [blk.offset+3] JEQ 0: Jt=0 (ALLOW), Jf→trailing TRACE
			// [blk.offset+4] RET ALLOW               — null pointer → allow
			nf := blk.nullFilter
			argLoOffset := uint32(offsetArgs0Lo + nf.ArgIndex*8)
			argHiOffset := argLoOffset + 4

			// Load low 32 bits.
			prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: argLoOffset})

			// JEQ 0 at blk.offset+1: if low == 0, fall through (Jt=0).
			// If low != 0, jump to trailing RET TRACE.
			jfToTrace1 := uint8(totalCheckInsts - blk.offset - 2)
			prog = append(prog, unix.SockFilter{
				Code: bpfJMP | bpfJEQ | bpfK,
				Jt:   0,           // fall through to load high
				Jf:   jfToTrace1,  // not null → trailing RET TRACE
				K:    0,
			})

			// Load high 32 bits.
			prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: argHiOffset})

			// JEQ 0 at blk.offset+3: if high == 0, fall through to ALLOW (Jt=0).
			// If high != 0, jump to trailing RET TRACE.
			jfToTrace2 := uint8(totalCheckInsts - blk.offset - 4)
			prog = append(prog, unix.SockFilter{
				Code: bpfJMP | bpfJEQ | bpfK,
				Jt:   0,           // fall through to RET ALLOW
				Jf:   jfToTrace2,  // not null → trailing RET TRACE
				K:    0,
			})

			// NULL → ALLOW.
			prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})
		}
	}

	// Note: each check block includes its own inline RET ALLOW. The TRACE
	// return for failed checks falls through to the TRACE action already
	// emitted in the retActions section above. For arg filter blocks, JSET
	// Jt=1 skips the inline ALLOW and hits the next block or the end.
	// We need a trailing RET TRACE to catch the fall-through from JSET Jt
	// and null-check Jf paths.
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})

	return prog, nil
}
```

**Important implementation note:** The jump offsets in the JSET block are simple: `Jt: 1` skips the inline `RET ALLOW` to hit the trailing `RET TRACE`. `Jf: 0` falls through to `RET ALLOW`. For the null check, `Jf: 3` from the first JEQ skips `(load hi + JEQ + ALLOW)` to hit the trailing `RET TRACE`.

- [ ] **Step 8: Run all tests**

Run: `go test ./internal/ptrace/ -run 'TestBPFWithArgFilter' -v`
Expected: All 5 new tests pass.

- [ ] **Step 9: Run existing BPF tests to verify no regression**

Run: `go test ./internal/ptrace/ -run 'TestPrefilter|TestBuildBPF|TestSeccompRet|TestStaticAllow' -v`
Expected: All existing tests still pass.

- [ ] **Step 10: Commit**

```bash
git add internal/ptrace/seccomp_filter.go internal/ptrace/seccomp_filter_test.go
git commit -m "feat(ptrace): implement buildBPFWithArgFilters

New BPF filter generator that supports argument-level checks:
- bpfArgFilter: JSET bitmask check (for openat flags)
- bpfNullPtrFilter: 64-bit NULL pointer check (for sendto dest_addr)

Arg filters are skipped for syscalls with ERRNO (deny) actions.
Falls back to buildBPFForActions when no arg filters are provided."
```

---

### Task 4: Wire arg filters into injectSeccompFilter

**Files:**
- Modify: `internal/ptrace/inject_seccomp.go:31-73` (injectSeccompFilter)

- [ ] **Step 1: Write the arg filter construction and wiring**

In `internal/ptrace/inject_seccomp.go`, replace the filter building block (lines 48-73) with:

```go
	// Build the action list (used by all filter paths).
	denySet := make(map[int]uint32)
	for _, d := range denies {
		denySet[d.Nr] = seccompRetErrno(d.Errno)
	}
	var actions []bpfSyscallAction
	for _, nr := range narrowNums {
		if errnoAction, ok := denySet[nr]; ok {
			actions = append(actions, bpfSyscallAction{Nr: nr, Action: errnoAction})
			delete(denySet, nr)
		} else {
			actions = append(actions, bpfSyscallAction{Nr: nr, Action: seccompRetTrace})
		}
	}
	for nr, action := range denySet {
		actions = append(actions, bpfSyscallAction{Nr: nr, Action: action})
	}

	// Build arg-level filters if enabled.
	var argFilters []bpfArgFilter
	var nullFilters []bpfNullPtrFilter
	if t.cfg.ArgLevelFilter {
		// Openat read-only: skip ptrace for opens without write/create flags.
		// Disabled when MaskTracerPid is on (needs exit stops for all opens).
		if !t.cfg.MaskTracerPid {
			argFilters = append(argFilters, bpfArgFilter{
				Nr:       unix.SYS_OPENAT,
				ArgIndex: 2,
				Mask:     openatWriteMask,
			})
		}
		// Sendto with NULL dest_addr: connected-socket send, skip ptrace.
		nullFilters = append(nullFilters, bpfNullPtrFilter{
			Nr:       unix.SYS_SENDTO,
			ArgIndex: 4,
		})

		// Remove filters for syscalls not in the traced set.
		tracedSet := make(map[int]bool)
		for _, a := range actions {
			tracedSet[a.Nr] = true
		}
		var filteredArg []bpfArgFilter
		for _, af := range argFilters {
			if tracedSet[af.Nr] {
				filteredArg = append(filteredArg, af)
			}
		}
		argFilters = filteredArg
		var filteredNull []bpfNullPtrFilter
		for _, nf := range nullFilters {
			if tracedSet[nf.Nr] {
				filteredNull = append(filteredNull, nf)
			}
		}
		nullFilters = filteredNull
	}

	var filters []unix.SockFilter
	var bpfErr error
	if len(argFilters) > 0 || len(nullFilters) > 0 {
		filters, bpfErr = buildBPFWithArgFilters(actions, argFilters, nullFilters)
	} else if len(denies) > 0 || len(denySet) > 0 {
		filters, bpfErr = buildBPFForActions(actions)
	} else {
		filters, bpfErr = buildBPFForSyscalls(narrowNums)
	}
```

- [ ] **Step 2: Add logging for arg filters**

After the existing logging at line 163-169, add:

```go
	if t.cfg.ArgLevelFilter {
		for _, af := range argFilters {
			slog.Info("seccomp arg filter active", "tid", tid, "nr", af.Nr, "argIndex", af.ArgIndex, "mask", fmt.Sprintf("0x%x", af.Mask))
		}
		for _, nf := range nullFilters {
			slog.Info("seccomp null filter active", "tid", tid, "nr", nf.Nr, "argIndex", nf.ArgIndex)
		}
	}
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: Compiles with no errors.

- [ ] **Step 4: Run all ptrace tests**

Run: `go test ./internal/ptrace/ -v -count=1`
Expected: All tests pass (unit tests don't exercise the injection path directly).

- [ ] **Step 5: Commit**

```bash
git add internal/ptrace/inject_seccomp.go
git commit -m "feat(ptrace): wire arg-level BPF filters into injection

injectSeccompFilter now builds arg filters when ArgLevelFilter is enabled:
- openat read-only filter (skipped when MaskTracerPid is on)
- sendto NULL dest_addr filter
Filters are removed for syscalls not in the traced set or with deny actions."
```

---

### Task 5: Integration tests

**Files:**
- Modify: `internal/ptrace/integration_test.go` (add new test functions)

**Note:** Integration tests require ptrace capability. Check existing integration test patterns in the file for how they set up tracers and traced processes.

- [ ] **Step 1: Read integration test patterns**

Read: `internal/ptrace/integration_test.go` — find an existing test that traces a child process and checks for file syscall events. Use the same setup pattern.

- [ ] **Step 2: Write TestArgFilterOpenatReadOnly**

Write an integration test that:
1. Creates a tracer with `ArgLevelFilter: true`, `SeccompPrefilter: true`, `TraceFile: true`
2. Traces a child process that does:
   - `open("file", O_RDONLY)` — should NOT produce a ptrace stop
   - `open("file", O_WRONLY|O_CREAT)` — SHOULD produce a ptrace stop
3. Asserts that the file handler only receives the write/create open, not the read-only one

- [ ] **Step 3: Write TestArgFilterSendtoConnected**

Write an integration test that:
1. Creates a tracer with `ArgLevelFilter: true`, `SeccompPrefilter: true`, `TraceNetwork: true`
2. Traces a child process that does a connected UDP `sendto(fd, buf, len, 0, NULL, 0)`
3. Asserts no ptrace stop occurs for the NULL-dest sendto

- [ ] **Step 4: Run integration tests**

Run: `go test ./internal/ptrace/ -run 'TestArgFilter' -v -count=1`
Expected: PASS (may need to skip if ptrace capabilities unavailable in CI)

- [ ] **Step 5: Commit**

```bash
git add internal/ptrace/integration_test.go
git commit -m "test(ptrace): add integration tests for arg-level BPF filtering

Tests verify that read-only openat and connected-socket sendto
bypass ptrace when ArgLevelFilter is enabled."
```

---

### Task 6: Full build verification and cross-compile

**Files:** None (verification only)

- [ ] **Step 1: Run all tests**

Run: `go test ./...`
Expected: All tests pass.

- [ ] **Step 2: Cross-compile for Windows**

Run: `GOOS=windows go build ./...`
Expected: Compiles (ptrace code is behind `//go:build linux`).

- [ ] **Step 3: Build for Linux**

Run: `go build ./...`
Expected: Compiles.

- [ ] **Step 4: Final commit (if any fixups needed)**

Only if steps 1-3 revealed issues.
