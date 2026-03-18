# Ptrace Performance Optimizations Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce ptrace mode overhead (~621%) through four complementary optimizations: config-aware exit stop elimination, config-driven BPF filter, BPF-level static denies, and PTRACE_GET_SYSCALL_INFO.

**Architecture:** Each optimization reduces the number or cost of ptrace stops. Opt 1 skips unnecessary exit stops based on config. Opt 2 removes always-allowed syscalls from the BPF filter. Opt 3 encodes static deny decisions in BPF. Opt 4 uses a lighter ptrace call for entry info.

**Tech Stack:** Go, Linux ptrace, seccomp-BPF (cBPF), `golang.org/x/sys/unix`

**Spec:** `docs/superpowers/specs/2026-03-17-ptrace-performance-optimizations-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/ptrace/tracer.go` | Modify | `needsExitStop` → method; `SyscallContext` dispatch; capability detection |
| `internal/ptrace/syscalls.go` | Modify | Config-driven `narrowTracedSyscallNumbers`/`tracedSyscallNumbers` |
| `internal/ptrace/seccomp_filter.go` | Modify | `buildBPFForActions` with mixed TRACE/ERRNO; config-aware builders |
| `internal/ptrace/inject_seccomp.go` | Modify | Pass config to builders; `collectStaticDenies`; escalation overlap validation |
| `internal/ptrace/syscall_context.go` | Create | `SyscallEntryInfo`, `SyscallContext`, `getSyscallEntryInfo` |
| `internal/ptrace/static_deny.go` | Create | `StaticDenyChecker` interface, `StaticDeny` type, `collectStaticDenies` |
| `internal/ptrace/seccomp_filter_test.go` | Modify | Tests for config-driven filters, mixed actions BPF |
| `internal/ptrace/syscalls_test.go` | Modify | Tests for config-driven syscall lists |
| `internal/ptrace/static_deny_test.go` | Create | Tests for static deny collection and validation |
| `internal/ptrace/syscall_context_test.go` | Create | Tests for SyscallContext lazy loading |
| `internal/ptrace/handle_file.go` | Unchanged | Complex handler — gets Regs via dispatchSyscall (Opt 4) |
| `internal/ptrace/handle_network.go` | Unchanged | Complex handler — gets Regs via dispatchSyscall (Opt 4) |
| `internal/ptrace/handle_read.go` | Modify | Simple fd handler — accept `*SyscallContext` (Opt 4) |
| `internal/ptrace/handle_write.go` | Modify | Simple fd handler — accept `*SyscallContext` (Opt 4) |
| `internal/ptrace/handle_close.go` | Modify | Simple fd handler — accept `*SyscallContext` (Opt 4) |

---

### Task 1: Config-aware exit stop elimination (Optimization 1)

**Files:**
- Modify: `internal/ptrace/tracer.go:465-479` (needsExitStop function)
- Modify: `internal/ptrace/tracer.go:900` (handleSyscallStop call site)
- Modify: `internal/ptrace/tracer.go:956` (handleSeccompStop call site)
- Test: `internal/ptrace/tracer_test.go`

- [ ] **Step 1: Write test for config-aware needsExitStop**

Add to `internal/ptrace/tracer_test.go`:

```go
func TestNeedsExitStop(t *testing.T) {
	tests := []struct {
		name           string
		nr             int
		maskTracerPid  bool
		traceNetwork   bool
		want           bool
	}{
		{"openat with mask on", unix.SYS_OPENAT, true, true, true},
		{"openat with mask off", unix.SYS_OPENAT, false, true, false},
		{"openat2 with mask off", unix.SYS_OPENAT2, false, true, false},
		{"connect with network on", unix.SYS_CONNECT, false, true, true},
		{"connect with network off", unix.SYS_CONNECT, false, false, false},
		{"read always true", unix.SYS_READ, false, false, true},
		{"pread64 always true", unix.SYS_PREAD64, false, false, true},
		{"execve always true", unix.SYS_EXECVE, false, false, true},
		{"execveat always true", unix.SYS_EXECVEAT, false, false, true},
		{"unlinkat never needs exit", unix.SYS_UNLINKAT, true, true, false},
		{"write never needs exit", unix.SYS_WRITE, true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Tracer{cfg: TracerConfig{
				MaskTracerPid: tt.maskTracerPid,
				TraceNetwork:  tt.traceNetwork,
			}}
			if got := tr.needsExitStop(tt.nr); got != tt.want {
				t.Errorf("needsExitStop(%d) = %v, want %v", tt.nr, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestNeedsExitStop -v`
Expected: FAIL — `needsExitStop` is a function, not a method; `Tracer` struct may not be directly constructable in tests.

- [ ] **Step 3: Convert needsExitStop to method on Tracer**

In `internal/ptrace/tracer.go`, replace lines 465-479:

```go
// needsExitStop returns true if the given syscall needs an exit-time stop
// for post-processing. Config-aware: skips exit stops when the relevant
// feature (MaskTracerPid, TraceNetwork) is disabled.
func (t *Tracer) needsExitStop(nr int) bool {
	switch nr {
	case unix.SYS_READ, unix.SYS_PREAD64: // handleReadExit (TracerPid masking)
		return true // only traced when escalated — always needs exit
	case unix.SYS_OPENAT, unix.SYS_OPENAT2: // handleOpenatExit (fd tracking)
		return t.cfg.MaskTracerPid
	case unix.SYS_CONNECT: // handleConnectExit (TLS fd watch)
		return t.cfg.TraceNetwork // inline skip in handleNetwork handles port granularity
	case unix.SYS_EXECVE, unix.SYS_EXECVEAT: // failed exec needs exit to reset InSyscall
		return true
	}
	return false
}
```

- [ ] **Step 4: Update call sites**

In `internal/ptrace/tracer.go`, line 900 (inside `handleSyscallStop`):
Change `state.NeedExitStop = needsExitStop(nr)` → `state.NeedExitStop = t.needsExitStop(nr)`

In `internal/ptrace/tracer.go`, line 956 (inside `handleSeccompStop`):
Change `state.NeedExitStop = needsExitStop(nr)` → `state.NeedExitStop = t.needsExitStop(nr)`

- [ ] **Step 5: Run tests**

Run: `go test ./internal/ptrace/ -run TestNeedsExitStop -v`
Expected: PASS

- [ ] **Step 6: Run full test suite and cross-compile**

Run: `go test ./... && GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/tracer_test.go
git commit -m "perf(ptrace): config-aware needsExitStop to skip unnecessary exit stops

Convert needsExitStop from standalone function to method on Tracer.
Skip openat exit stops when MaskTracerPid is off. Skip connect exit
stops when TraceNetwork is off. Saves one context switch per openat
in MaskTracerPid=off deployments."
```

---

### Task 2: Config-driven BPF filter — update syscall lists (Optimization 2a)

**Files:**
- Modify: `internal/ptrace/syscalls.go:51-83`
- Modify: `internal/ptrace/syscalls_test.go`

- [ ] **Step 1: Write tests for config-driven narrowTracedSyscallNumbers**

Replace the existing `TestTracedSyscallNumbers` in `internal/ptrace/syscalls_test.go` and add new tests:

```go
func TestNarrowTracedSyscallNumbers(t *testing.T) {
	// All features enabled, with handler
	allOn := &TracerConfig{
		TraceExecve:  true,
		TraceFile:    true,
		TraceNetwork: true,
		TraceSignal:  true,
		MaskTracerPid: true,
		NetworkHandler: mockNetHandler{},
	}
	nums := narrowTracedSyscallNumbers(allOn)

	// Must include policy-relevant syscalls
	assertContains(t, nums, unix.SYS_EXECVE, "SYS_EXECVE")
	assertContains(t, nums, unix.SYS_OPENAT, "SYS_OPENAT")
	assertContains(t, nums, unix.SYS_CONNECT, "SYS_CONNECT")
	assertContains(t, nums, unix.SYS_BIND, "SYS_BIND")
	assertContains(t, nums, unix.SYS_SENDTO, "SYS_SENDTO")
	assertContains(t, nums, unix.SYS_KILL, "SYS_KILL")
	assertContains(t, nums, unix.SYS_CLOSE, "SYS_CLOSE")

	// Must NOT include always-allowed syscalls
	assertNotContains(t, nums, unix.SYS_SOCKET, "SYS_SOCKET")
	assertNotContains(t, nums, unix.SYS_LISTEN, "SYS_LISTEN")

	// Must NOT include lazily-escalated syscalls
	assertNotContains(t, nums, unix.SYS_READ, "SYS_READ")
	assertNotContains(t, nums, unix.SYS_WRITE, "SYS_WRITE")
}

func TestNarrowTracedSyscallNumbersNetworkOff(t *testing.T) {
	cfg := &TracerConfig{TraceExecve: true, TraceFile: true}
	nums := narrowTracedSyscallNumbers(cfg)

	assertContains(t, nums, unix.SYS_EXECVE, "SYS_EXECVE")
	assertContains(t, nums, unix.SYS_OPENAT, "SYS_OPENAT")
	assertNotContains(t, nums, unix.SYS_CONNECT, "SYS_CONNECT")
	assertNotContains(t, nums, unix.SYS_BIND, "SYS_BIND")
	assertNotContains(t, nums, unix.SYS_SENDTO, "SYS_SENDTO")
	assertNotContains(t, nums, unix.SYS_CLOSE, "SYS_CLOSE")
}

func TestNarrowTracedSyscallNumbersNoHandler(t *testing.T) {
	cfg := &TracerConfig{TraceNetwork: true, NetworkHandler: nil}
	nums := narrowTracedSyscallNumbers(cfg)

	assertContains(t, nums, unix.SYS_CONNECT, "SYS_CONNECT")
	// sendto only with handler (DNS proxy)
	assertNotContains(t, nums, unix.SYS_SENDTO, "SYS_SENDTO")
}

func TestNarrowTracedSyscallNumbersCloseOnlyWithFdTracking(t *testing.T) {
	// No MaskTracerPid, no NetworkHandler → no close
	cfg := &TracerConfig{TraceFile: true}
	nums := narrowTracedSyscallNumbers(cfg)
	assertNotContains(t, nums, unix.SYS_CLOSE, "SYS_CLOSE")

	// MaskTracerPid on → close needed
	cfg2 := &TracerConfig{TraceFile: true, MaskTracerPid: true}
	nums2 := narrowTracedSyscallNumbers(cfg2)
	assertContains(t, nums2, unix.SYS_CLOSE, "SYS_CLOSE")
}

func TestTracedSyscallNumbersIncludesReadWrite(t *testing.T) {
	cfg := &TracerConfig{TraceExecve: true, TraceFile: true, TraceNetwork: true}
	nums := tracedSyscallNumbers(cfg)
	assertContains(t, nums, unix.SYS_READ, "SYS_READ")
	assertContains(t, nums, unix.SYS_PREAD64, "SYS_PREAD64")
	assertContains(t, nums, unix.SYS_WRITE, "SYS_WRITE")
}

// helpers
type mockNetHandler struct{}
func (mockNetHandler) HandleNetwork(_ context.Context, _ NetworkContext) NetworkResult {
	return NetworkResult{Allow: true}
}

func assertContains(t *testing.T, nums []int, target int, name string) {
	t.Helper()
	for _, n := range nums {
		if n == target {
			return
		}
	}
	t.Errorf("%s (%d) missing from syscall list", name, target)
}

func assertNotContains(t *testing.T, nums []int, target int, name string) {
	t.Helper()
	for _, n := range nums {
		if n == target {
			t.Errorf("%s (%d) should not be in syscall list", name, target)
			return
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/ptrace/ -run "TestNarrowTracedSyscallNumbers|TestTracedSyscallNumbers" -v`
Expected: FAIL — functions don't accept `*TracerConfig`

- [ ] **Step 3: Implement config-driven syscall lists**

Replace `internal/ptrace/syscalls.go:51-83` with:

```go
func tracedSyscallNumbers(cfg *TracerConfig) []int {
	nums := narrowTracedSyscallNumbers(cfg)
	// Full set includes read/write for TRACESYSGOOD fallback mode
	nums = append(nums, unix.SYS_READ, unix.SYS_PREAD64, unix.SYS_WRITE)
	return nums
}

func narrowTracedSyscallNumbers(cfg *TracerConfig) []int {
	var nums []int

	if cfg.TraceExecve {
		nums = append(nums, unix.SYS_EXECVE, unix.SYS_EXECVEAT)
	}
	if cfg.TraceFile {
		nums = append(nums,
			unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
			unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
			unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2, unix.SYS_FCHOWNAT,
		)
		nums = append(nums, legacyFileSyscalls()...)
	}
	if cfg.TraceNetwork {
		nums = append(nums, unix.SYS_CONNECT, unix.SYS_BIND)
		if cfg.NetworkHandler != nil {
			nums = append(nums, unix.SYS_SENDTO)
		}
		// socket, listen: removed — always allowed by handleNetwork
	}
	if cfg.TraceSignal {
		nums = append(nums,
			unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
			unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO,
		)
	}
	if cfg.MaskTracerPid || (cfg.TraceNetwork && cfg.NetworkHandler != nil) {
		nums = append(nums, unix.SYS_CLOSE)
	}

	return nums
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run "TestNarrowTracedSyscallNumbers|TestTracedSyscallNumbers" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ptrace/syscalls.go internal/ptrace/syscalls_test.go
git commit -m "perf(ptrace): config-driven BPF filter syscall lists

narrowTracedSyscallNumbers and tracedSyscallNumbers now accept
TracerConfig. Removes socket/listen (always allowed), sendto (only
with DNS proxy), and close (only with fd tracking) from the BPF
filter when not needed."
```

---

### Task 3: Config-driven BPF filter — update builders and call sites (Optimization 2b)

**Files:**
- Modify: `internal/ptrace/seccomp_filter.go:73-89`
- Modify: `internal/ptrace/inject_seccomp.go:31-35`
- Modify: `internal/ptrace/seccomp_filter_test.go`

- [ ] **Step 1: Update existing BPF filter tests**

In `internal/ptrace/seccomp_filter_test.go`, update tests to pass config:

```go
func allEnabledConfig() *TracerConfig {
	return &TracerConfig{
		TraceExecve:    true,
		TraceFile:      true,
		TraceNetwork:   true,
		TraceSignal:    true,
		MaskTracerPid:  true,
		NetworkHandler: mockNetHandler{},
	}
}

func TestPrefilterBPFNonEmpty(t *testing.T) {
	prog, err := buildPrefilterBPF(allEnabledConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) == 0 {
		t.Fatal("buildPrefilterBPF returned empty filter")
	}
}

func TestPrefilterBPFInstructionCount(t *testing.T) {
	cfg := allEnabledConfig()
	syscalls := tracedSyscallNumbers(cfg)
	prog, err := buildPrefilterBPF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := 4 + len(syscalls) + 2
	if len(prog) != want {
		t.Errorf("instruction count = %d, want %d (4 header + %d comparisons + 2 returns)",
			len(prog), want, len(syscalls))
	}
}

func TestPrefilterBPFContainsAllSyscalls(t *testing.T) {
	cfg := allEnabledConfig()
	syscalls := tracedSyscallNumbers(cfg)
	prog, err := buildPrefilterBPF(cfg)
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
	for _, nr := range syscalls {
		if !jeqValues[uint32(nr)] {
			t.Errorf("syscall %d not found as JEQ instruction in filter", nr)
		}
	}
}

func TestPrefilterBPFArchCheck(t *testing.T) {
	prog, err := buildPrefilterBPF(allEnabledConfig())
	if err != nil {
		t.Fatal(err)
	}
	if prog[0].Code != bpfLD|bpfW|bpfABS || prog[0].K != offsetArch {
		t.Errorf("first instruction should load arch (offset %d), got Code=0x%x K=%d",
			offsetArch, prog[0].Code, prog[0].K)
	}
	if prog[1].Code != bpfJMP|bpfJEQ|bpfK {
		t.Errorf("second instruction should be JEQ, got Code=0x%x", prog[1].Code)
	}
}

func TestNarrowPrefilterExcludesReadWrite(t *testing.T) {
	cfg := allEnabledConfig()
	prog, err := buildNarrowPrefilterBPF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	jeqValues := make(map[uint32]bool)
	for _, inst := range prog {
		if inst.Code == bpfJMP|bpfJEQ|bpfK {
			jeqValues[inst.K] = true
		}
	}
	if jeqValues[uint32(unix.SYS_READ)] {
		t.Error("narrow prefilter should not contain SYS_READ")
	}
	if jeqValues[uint32(unix.SYS_PREAD64)] {
		t.Error("narrow prefilter should not contain SYS_PREAD64")
	}
	if jeqValues[uint32(unix.SYS_WRITE)] {
		t.Error("narrow prefilter should not contain SYS_WRITE")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/ptrace/ -run "TestPrefilterBPF|TestNarrowPrefilter" -v`
Expected: FAIL — builders don't accept config

- [ ] **Step 3: Update BPF builder signatures**

In `internal/ptrace/seccomp_filter.go`, replace lines 73-89:

```go
func buildPrefilterBPF(cfg *TracerConfig) ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(tracedSyscallNumbers(cfg))
}

func buildNarrowPrefilterBPF(cfg *TracerConfig) ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(narrowTracedSyscallNumbers(cfg))
}

func buildEscalationBPF(syscalls []int) ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(syscalls)
}
```

- [ ] **Step 4: Update injectSeccompFilter to pass config**

In `internal/ptrace/inject_seccomp.go`, line 33:
Change `filters, bpfErr := buildNarrowPrefilterBPF()` → `filters, bpfErr := buildNarrowPrefilterBPF(&t.cfg)`

- [ ] **Step 5: Fix any remaining compile errors**

Search for other callers of `buildPrefilterBPF()` or `buildNarrowPrefilterBPF()` and update them to pass config. Check `tracedSyscallNumbers()` callers too — the TRACESYSGOOD fallback in tracer.go may call it.

Run: `go build ./internal/ptrace/`

- [ ] **Step 6: Run all tests**

Run: `go test ./internal/ptrace/ -v && GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/ptrace/seccomp_filter.go internal/ptrace/inject_seccomp.go internal/ptrace/seccomp_filter_test.go
git commit -m "perf(ptrace): config-driven BPF filter builders

buildPrefilterBPF and buildNarrowPrefilterBPF now accept TracerConfig
to generate filters with only policy-relevant syscalls. Removes
socket/listen/sendto/close from BPF filter when not needed."
```

---

### Task 4: BPF-level static denies — types and collection (Optimization 3a)

**Files:**
- Create: `internal/ptrace/static_deny.go`
- Create: `internal/ptrace/static_deny_test.go`

- [ ] **Step 1: Write tests for static deny types and collection**

Create `internal/ptrace/static_deny_test.go`:

```go
//go:build linux

package ptrace

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

type denyAllNetHandler struct{}

func (denyAllNetHandler) HandleNetwork(_ context.Context, _ NetworkContext) NetworkResult {
	return NetworkResult{Allow: false}
}

func (denyAllNetHandler) StaticDenySyscalls() []StaticDeny {
	return []StaticDeny{
		{Nr: unix.SYS_CONNECT, Errno: int(unix.EACCES)},
		{Nr: unix.SYS_BIND, Errno: int(unix.EACCES)},
	}
}

type allowAllNetHandler struct{}

func (allowAllNetHandler) HandleNetwork(_ context.Context, _ NetworkContext) NetworkResult {
	return NetworkResult{Allow: true}
}

func TestCollectStaticDeniesNilHandler(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{TraceNetwork: true, NetworkHandler: nil}}
	denies := tr.collectStaticDenies()
	if len(denies) != 2 {
		t.Fatalf("expected 2 denies for nil handler, got %d", len(denies))
	}
	if denies[0].Nr != unix.SYS_CONNECT || denies[1].Nr != unix.SYS_BIND {
		t.Error("expected connect and bind denies")
	}
}

func TestCollectStaticDeniesWithChecker(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{TraceNetwork: true, NetworkHandler: denyAllNetHandler{}}}
	denies := tr.collectStaticDenies()
	if len(denies) != 2 {
		t.Fatalf("expected 2 denies from checker, got %d", len(denies))
	}
}

func TestCollectStaticDeniesNoChecker(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{TraceNetwork: true, NetworkHandler: allowAllNetHandler{}}}
	denies := tr.collectStaticDenies()
	if len(denies) != 0 {
		t.Fatalf("expected 0 denies for non-checker handler, got %d", len(denies))
	}
}

func TestCollectStaticDeniesRejectsZeroErrno(t *testing.T) {
	denies := validateStaticDenies([]StaticDeny{
		{Nr: unix.SYS_CONNECT, Errno: int(unix.EACCES)},
		{Nr: unix.SYS_BIND, Errno: 0}, // invalid
	})
	if len(denies) != 1 {
		t.Fatalf("expected 1 valid deny after filtering, got %d", len(denies))
	}
}

func TestCollectStaticDeniesRejectsEscalationOverlap(t *testing.T) {
	denies := validateStaticDenies([]StaticDeny{
		{Nr: unix.SYS_READ, Errno: int(unix.EACCES)}, // overlaps escalation
		{Nr: unix.SYS_CONNECT, Errno: int(unix.EACCES)},
	})
	if len(denies) != 1 {
		t.Fatalf("expected 1 valid deny after filtering overlap, got %d", len(denies))
	}
	if denies[0].Nr != unix.SYS_CONNECT {
		t.Error("expected connect to survive, read to be filtered")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/ptrace/ -run TestCollectStaticDenies -v`
Expected: FAIL — types and functions don't exist

- [ ] **Step 3: Implement static deny types and collection**

Create `internal/ptrace/static_deny.go`:

```go
//go:build linux

package ptrace

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// StaticDenyChecker is an optional interface that handlers implement to declare
// syscalls that are always denied regardless of arguments for the session lifetime.
// This enables BPF-level enforcement (SECCOMP_RET_ERRNO) without ptrace stops.
type StaticDenyChecker interface {
	StaticDenySyscalls() []StaticDeny
}

// StaticDeny represents a syscall that should be denied at the BPF level.
type StaticDeny struct {
	Nr    int
	Errno int // must be > 0
}

// collectStaticDenies gathers all static deny declarations from handlers and config.
func (t *Tracer) collectStaticDenies() []StaticDeny {
	var denies []StaticDeny

	// Category enabled but handler nil → deny all relevant syscalls
	if t.cfg.TraceNetwork && t.cfg.NetworkHandler == nil {
		denies = append(denies,
			StaticDeny{Nr: unix.SYS_CONNECT, Errno: int(unix.EACCES)},
			StaticDeny{Nr: unix.SYS_BIND, Errno: int(unix.EACCES)},
		)
	}

	// Handler-declared denies
	if checker, ok := t.cfg.NetworkHandler.(StaticDenyChecker); ok {
		denies = append(denies, checker.StaticDenySyscalls()...)
	}
	if checker, ok := t.cfg.FileHandler.(StaticDenyChecker); ok {
		denies = append(denies, checker.StaticDenySyscalls()...)
	}
	if checker, ok := t.cfg.ExecHandler.(StaticDenyChecker); ok {
		denies = append(denies, checker.StaticDenySyscalls()...)
	}
	if checker, ok := t.cfg.SignalHandler.(StaticDenyChecker); ok {
		denies = append(denies, checker.StaticDenySyscalls()...)
	}

	return validateStaticDenies(denies)
}

// escalationSyscalls returns the set of syscalls used by lazy BPF escalation.
// Static denies must not overlap with these.
var escalationSyscalls = map[int]bool{
	unix.SYS_READ:    true,
	unix.SYS_PREAD64: true,
	unix.SYS_WRITE:   true,
}

// validateStaticDenies filters out invalid entries and logs warnings.
func validateStaticDenies(denies []StaticDeny) []StaticDeny {
	valid := make([]StaticDeny, 0, len(denies))
	for _, d := range denies {
		if d.Errno <= 0 {
			slog.Warn("static deny: rejecting entry with invalid errno",
				"nr", d.Nr, "errno", d.Errno)
			continue
		}
		if escalationSyscalls[d.Nr] {
			slog.Warn("static deny: rejecting entry that overlaps escalation syscalls",
				"nr", d.Nr)
			continue
		}
		valid = append(valid, d)
	}
	return valid
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run TestCollectStaticDenies -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ptrace/static_deny.go internal/ptrace/static_deny_test.go
git commit -m "perf(ptrace): add StaticDenyChecker interface and collection

Handlers can optionally implement StaticDenyChecker to declare syscalls
always denied for the session. Validates errno > 0 and rejects overlaps
with escalation syscalls (read/write/pread64)."
```

---

### Task 5: BPF-level static denies — extend BPF generation (Optimization 3b)

**Files:**
- Modify: `internal/ptrace/seccomp_filter.go`
- Modify: `internal/ptrace/inject_seccomp.go`
- Modify: `internal/ptrace/seccomp_filter_test.go`

- [ ] **Step 1: Write test for mixed-action BPF generation**

Add to `internal/ptrace/seccomp_filter_test.go`:

```go
func TestBuildBPFForActions(t *testing.T) {
	actions := []bpfSyscallAction{
		{Nr: unix.SYS_OPENAT, Action: seccompRetTrace},
		{Nr: unix.SYS_CONNECT, Action: seccompRetErrno(int(unix.EACCES))},
	}
	prog, err := buildBPFForActions(actions)
	if err != nil {
		t.Fatal(err)
	}

	// Verify both syscalls are in the filter
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

	// Verify there are at least 3 distinct return instructions
	// (ALLOW, TRACE, ERRNO)
	retInsts := 0
	for _, inst := range prog {
		if inst.Code == bpfRET|bpfK {
			retInsts++
		}
	}
	if retInsts < 3 {
		t.Errorf("expected at least 3 return instructions (ALLOW, TRACE, ERRNO), got %d", retInsts)
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

	// Find the ERRNO return instruction and verify the encoded errno
	found := false
	for _, inst := range prog {
		if inst.Code == bpfRET|bpfK && inst.K != seccompRetAllow && inst.K != seccompRetTrace {
			if inst.K != uint32(0x00050000|errno) {
				t.Errorf("ERRNO return has wrong value: 0x%x, want 0x%x", inst.K, 0x00050000|errno)
			}
			found = true
		}
	}
	if !found {
		t.Error("no ERRNO return instruction found")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/ptrace/ -run "TestBuildBPFForActions" -v`
Expected: FAIL — `buildBPFForActions`, `bpfSyscallAction`, `seccompRetErrno` don't exist

- [ ] **Step 3: Implement buildBPFForActions**

Add to `internal/ptrace/seccomp_filter.go`:

```go
const seccompRetErrnoBase = 0x00050000

// seccompRetErrno returns the SECCOMP_RET_ERRNO value for the given errno.
func seccompRetErrno(errno int) uint32 {
	return seccompRetErrnoBase | uint32(errno&0xFFFF)
}

// bpfSyscallAction pairs a syscall number with its BPF return action.
type bpfSyscallAction struct {
	Nr     int
	Action uint32 // seccompRetTrace or seccompRetErrno(errno)
}

// buildBPFForActions generates a seccomp-BPF filter with per-syscall return
// actions. Different syscalls can have different return values (TRACE vs ERRNO).
func buildBPFForActions(actions []bpfSyscallAction) ([]unix.SockFilter, error) {
	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = auditArchX86_64
	case "arm64":
		auditArch = auditArchAarch64
	default:
		return nil, fmt.Errorf("seccomp prefilter: unsupported architecture %s", runtime.GOARCH)
	}

	// Collect unique return actions (deduplicate).
	retActionSet := make(map[uint32]int) // action → index in retActions slice
	var retActions []uint32
	for _, a := range actions {
		if _, ok := retActionSet[a.Action]; !ok {
			retActionSet[a.Action] = len(retActions)
			retActions = append(retActions, a.Action)
		}
	}

	n := len(actions)
	nRet := len(retActions)
	// Program: 4 header + n comparisons + 1 default ALLOW + nRet action returns
	prog := make([]unix.SockFilter, 0, 4+n+1+nRet)

	// Header: load arch, check arch, load nr
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetArch})
	prog = append(prog, unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: auditArch})
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace}) // unknown arch → trace
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetNr})

	// Comparisons: each JEQ jumps to its action's return instruction.
	// Layout after comparisons: [ALLOW ret] [action0 ret] [action1 ret] ...
	for i, a := range actions {
		remaining := n - i - 1 // instructions remaining after this JEQ
		// Jump target = remaining comparisons + 1 (skip ALLOW) + retActionSet[a.Action]
		jumpTarget := uint8(remaining + 1 + retActionSet[a.Action])
		prog = append(prog, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jumpTarget,
			Jf:   0,
			K:    uint32(a.Nr),
		})
	}

	// Default: ALLOW
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})

	// Per-action return instructions
	for _, action := range retActions {
		prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: action})
	}

	return prog, nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run "TestBuildBPFForActions" -v`
Expected: PASS

- [ ] **Step 5: Integrate static denies into injectSeccompFilter**

In `internal/ptrace/inject_seccomp.go`, replace the top of `injectSeccompFilter` (lines 31-38, everything from the function signature through the BPF building) with the following. The remainder of the function (from `if len(filters) == 0` onward — scratch page allocation, BPF serialization, prctl/seccomp injection) stays unchanged, since it operates on the same `filters` variable:

```go
func (t *Tracer) injectSeccompFilter(tid int) error {
	// Collect static denies and narrow syscall list.
	denies := t.collectStaticDenies()
	narrowNums := narrowTracedSyscallNumbers(&t.cfg)

	var filters []unix.SockFilter
	var bpfErr error

	if len(denies) > 0 {
		// Build merged action list: denies get ERRNO, rest get TRACE.
		denySet := make(map[int]uint32) // nr → ERRNO action
		for _, d := range denies {
			denySet[d.Nr] = seccompRetErrno(d.Errno)
		}

		var actions []bpfSyscallAction
		for _, nr := range narrowNums {
			if errnoAction, ok := denySet[nr]; ok {
				actions = append(actions, bpfSyscallAction{Nr: nr, Action: errnoAction})
				delete(denySet, nr) // consumed
			} else {
				actions = append(actions, bpfSyscallAction{Nr: nr, Action: seccompRetTrace})
			}
		}
		// Add deny-only syscalls not in narrow list
		for nr, action := range denySet {
			actions = append(actions, bpfSyscallAction{Nr: nr, Action: action})
		}

		filters, bpfErr = buildBPFForActions(actions)
	} else {
		filters, bpfErr = buildNarrowPrefilterBPF(&t.cfg)
	}

	if bpfErr != nil {
		return bpfErr
	}
	if len(filters) == 0 {
		return fmt.Errorf("empty BPF program")
	}
	// --- everything below here is unchanged from the original function ---
```

After the successful `slog.Info("seccomp prefilter installed", ...)` line near the end of the function (line 122), add logging for static denies:

```go
	slog.Info("seccomp prefilter installed", "tid", tid, "filters", len(filters))
	for _, d := range denies {
		slog.Info("seccomp static deny active", "tid", tid, "nr", d.Nr, "errno", d.Errno)
	}
	return nil
```

- [ ] **Step 6: Run all tests and cross-compile**

Run: `go test ./internal/ptrace/ -v && go test ./... && GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/ptrace/seccomp_filter.go internal/ptrace/inject_seccomp.go internal/ptrace/seccomp_filter_test.go
git commit -m "perf(ptrace): BPF-level SECCOMP_RET_ERRNO for static deny policies

buildBPFForActions generates mixed TRACE/ERRNO filters. Static deny
syscalls are enforced entirely in-kernel without ptrace stops.
injectSeccompFilter merges static denies with the narrow filter."
```

---

### Task 6: PTRACE_GET_SYSCALL_INFO — SyscallContext and capability detection (Optimization 4a)

**Files:**
- Create: `internal/ptrace/syscall_context.go`
- Create: `internal/ptrace/syscall_context_test.go`
- Modify: `internal/ptrace/tracer.go` (add `hasSyscallInfo` field to Tracer)

- [ ] **Step 1: Write tests for SyscallContext**

Create `internal/ptrace/syscall_context_test.go`:

```go
//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSyscallContextLazyRegs(t *testing.T) {
	// SyscallContext should not load regs until Regs() is called
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

func TestSeccompRetErrnoEncoding(t *testing.T) {
	// SECCOMP_RET_ERRNO is 0x00050000 | errno
	got := seccompRetErrno(int(unix.EACCES))
	want := uint32(0x00050000 | unix.EACCES)
	if got != want {
		t.Errorf("seccompRetErrno(EACCES) = 0x%x, want 0x%x", got, want)
	}
}
```

- [ ] **Step 2: Implement SyscallContext**

Create `internal/ptrace/syscall_context.go`:

```go
//go:build linux

package ptrace

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ptraceGetSyscallInfo is the ptrace request number for PTRACE_GET_SYSCALL_INFO.
const ptraceGetSyscallInfo = 0x420e

// SyscallEntryInfo holds syscall number and arguments extracted at entry time.
type SyscallEntryInfo struct {
	Nr   int
	Args [6]uint64
}

// SyscallContext wraps entry info with lazy full-register access.
// Handlers use Info.Args for the fast allow path and call Regs() only
// when they need to modify registers (deny/redirect).
type SyscallContext struct {
	Info   SyscallEntryInfo
	tid    int
	tracer *Tracer
	regs   Regs
	loaded bool
}

// Regs lazily loads the full register set. Cached after first call.
func (sc *SyscallContext) Regs() (Regs, error) {
	if !sc.loaded {
		var err error
		sc.regs, err = sc.tracer.getRegs(sc.tid)
		if err != nil {
			return nil, err
		}
		sc.loaded = true
	}
	return sc.regs, nil
}

// ptraceSyscallInfo mirrors struct ptrace_syscall_info (Linux 5.3+).
// We only parse the entry variant (op == 1).
type ptraceSyscallInfo struct {
	Op                  uint8
	_                   [3]byte // pad
	Arch                uint32
	InstructionPointer  uint64
	StackPointer        uint64
	// Union: entry is the relevant variant.
	EntryNr             uint64
	EntryArgs           [6]uint64
}

const ptraceSyscallInfoSize = int(unsafe.Sizeof(ptraceSyscallInfo{}))

// getSyscallEntryInfo retrieves syscall entry info via PTRACE_GET_SYSCALL_INFO.
// Returns nil, errNotSupported on kernels < 5.3.
func (t *Tracer) getSyscallEntryInfo(tid int) (*SyscallEntryInfo, error) {
	var info ptraceSyscallInfo
	_, _, errno := unix.Syscall6(
		unix.SYS_PTRACE,
		uintptr(ptraceGetSyscallInfo),
		uintptr(tid),
		uintptr(ptraceSyscallInfoSize),
		uintptr(unsafe.Pointer(&info)),
		0, 0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("PTRACE_GET_SYSCALL_INFO: %w", errno)
	}
	// op == 1 means PTRACE_SYSCALL_INFO_ENTRY
	if info.Op != 1 {
		return nil, fmt.Errorf("PTRACE_GET_SYSCALL_INFO: unexpected op %d (want entry=1)", info.Op)
	}
	return &SyscallEntryInfo{
		Nr:   int(info.EntryNr),
		Args: info.EntryArgs,
	}, nil
}

// probePtraceSyscallInfo returns true if PTRACE_GET_SYSCALL_INFO is supported.
// Must be called from a goroutine locked to an OS thread.
func probePtraceSyscallInfo() bool {
	// A simple probe: call with pid=0 (invalid). If the kernel knows the
	// request, it returns ESRCH. If not, it returns EIO or EINVAL.
	var info ptraceSyscallInfo
	_, _, errno := unix.Syscall6(
		unix.SYS_PTRACE,
		uintptr(ptraceGetSyscallInfo),
		0, // invalid pid
		uintptr(ptraceSyscallInfoSize),
		uintptr(unsafe.Pointer(&info)),
		0, 0,
	)
	return errno == unix.ESRCH
}
```

- [ ] **Step 3: Add hasSyscallInfo to Tracer**

In `internal/ptrace/tracer.go`, add field to Tracer struct (find the struct definition and add):

```go
hasSyscallInfo bool // set at startup if PTRACE_GET_SYSCALL_INFO is available
```

In the `Run()` method, before the event loop, add capability detection:

```go
t.hasSyscallInfo = probePtraceSyscallInfo()
if t.hasSyscallInfo {
    slog.Info("ptrace: PTRACE_GET_SYSCALL_INFO supported")
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run "TestSyscallContext|TestSeccompRetErrno" -v`
Expected: PASS

- [ ] **Step 5: Run full suite and cross-compile**

Run: `go test ./... && GOOS=windows go build ./...`
Expected: PASS (syscall_context.go has `//go:build linux`)

- [ ] **Step 6: Commit**

```bash
git add internal/ptrace/syscall_context.go internal/ptrace/syscall_context_test.go internal/ptrace/tracer.go
git commit -m "perf(ptrace): add SyscallContext and PTRACE_GET_SYSCALL_INFO support

SyscallContext provides lazy register loading — handlers can read
syscall args from the lightweight SyscallEntryInfo and only fall
back to full getRegs when modifying registers. Probes for
PTRACE_GET_SYSCALL_INFO support at startup."
```

---

### Task 7: PTRACE_GET_SYSCALL_INFO — integrate into dispatch (Optimization 4b)

**Files:**
- Modify: `internal/ptrace/tracer.go` (handleSeccompStop, handleSyscallStop, dispatchSyscall)
- Modify: `internal/ptrace/handle_write.go` (use sc.Info.Args for fd)
- Modify: `internal/ptrace/handle_close.go` (use sc.Info.Args for fd)
- Modify: `internal/ptrace/handle_read.go` (use sc.Info.Args for fd)

**Strategy**: Minimize blast radius. Complex handlers (handleFile, handleNetwork, handleExecve, handleSignal) call `sc.Regs()` upfront in `dispatchSyscall` and keep their existing `Regs` signatures. Only simple fd-only handlers (handleWrite, handleClose, handleReadEntry) change to accept `*SyscallContext` and use `sc.Info.Args[0]`. This gets the main benefit (lighter syscall-number extraction in the dispatch path) without touching the complex handler internals.

- [ ] **Step 1: Extract buildSyscallContext helper**

Add to `internal/ptrace/syscall_context.go`:

```go
// buildSyscallContext constructs a SyscallContext for a stopped tracee.
// Uses PTRACE_GET_SYSCALL_INFO when available, falls back to full getRegs.
func (t *Tracer) buildSyscallContext(tid int) (*SyscallContext, error) {
	sc := &SyscallContext{tid: tid, tracer: t}

	if t.hasSyscallInfo {
		info, err := t.getSyscallEntryInfo(tid)
		if err == nil {
			sc.Info = *info
			return sc, nil
		}
		// Fallback to full register read
	}

	regs, err := t.getRegs(tid)
	if err != nil {
		return nil, err
	}
	sc.Info = SyscallEntryInfo{Nr: regs.SyscallNr()}
	for i := 0; i < 6; i++ {
		sc.Info.Args[i] = regs.Arg(i)
	}
	sc.regs = regs
	sc.loaded = true
	return sc, nil
}
```

- [ ] **Step 2: Update dispatchSyscall**

In `internal/ptrace/tracer.go`, change `dispatchSyscall` to accept `*SyscallContext`. Complex handlers get `Regs` via `sc.Regs()`, simple handlers get `*SyscallContext`:

```go
func (t *Tracer) dispatchSyscall(ctx context.Context, tid int, nr int, sc *SyscallContext) {
	switch {
	case isExecveSyscall(nr):
		regs, err := sc.Regs()
		if err != nil {
			t.allowSyscall(tid)
			return
		}
		t.handleExecve(ctx, tid, regs)
	case isFileSyscall(nr):
		regs, err := sc.Regs()
		if err != nil {
			t.allowSyscall(tid)
			return
		}
		t.handleFile(ctx, tid, regs)
	case isNetworkSyscall(nr):
		regs, err := sc.Regs()
		if err != nil {
			t.allowSyscall(tid)
			return
		}
		t.handleNetwork(ctx, tid, regs)
	case isSignalSyscall(nr):
		regs, err := sc.Regs()
		if err != nil {
			t.allowSyscall(tid)
			return
		}
		t.handleSignal(ctx, tid, regs)
	case isWriteSyscall(nr):
		t.handleWrite(ctx, tid, sc)
	case isCloseSyscall(nr):
		t.handleClose(ctx, tid, sc)
	case isReadSyscall(nr):
		t.handleReadEntry(tid, sc)
	default:
		t.allowSyscall(tid)
	}
}
```

Note: `handleFile`, `handleNetwork`, `handleExecve`, `handleSignal` keep their `Regs` signatures unchanged. `handleWrite`, `handleClose`, `handleReadEntry` change to `*SyscallContext`.

- [ ] **Step 3: Update handleSeccompStop to use buildSyscallContext**

Replace the register-reading block in `handleSeccompStop` (`tracer.go:940`):

```go
func (t *Tracer) handleSeccompStop(ctx context.Context, tid int) {
	sc, err := t.buildSyscallContext(tid)
	if err != nil {
		t.allowSyscall(tid)
		return
	}
	nr := sc.Info.Nr

	t.mu.Lock()
	state := t.tracees[tid]
	if state != nil {
		state.InSyscall = true
		state.LastNr = nr
		state.NeedExitStop = t.needsExitStop(nr)
		if state.NeedsReadEscalation && !state.ThreadHasReadEscalation {
			state.PendingReadEscalation = true
		}
		if state.NeedsWriteEscalation && !state.ThreadHasWriteEscalation {
			state.PendingWriteEscalation = true
		}
	}
	t.mu.Unlock()

	t.dispatchSyscall(ctx, tid, nr, sc)
}
```

- [ ] **Step 4: Update handleSyscallStop entry path**

Replace the `entering` branch (around `tracer.go:889`):

```go
	if entering {
		sc, err := t.buildSyscallContext(tid)
		if err != nil {
			t.allowSyscall(tid)
			return
		}
		nr := sc.Info.Nr
		state.LastNr = nr
		state.NeedExitStop = t.needsExitStop(nr)

		t.dispatchSyscall(ctx, tid, nr, sc)
	}
```

- [ ] **Step 5: Update handleWrite to accept SyscallContext**

In `internal/ptrace/handle_write.go`, change signature and fd extraction:

```go
func (t *Tracer) handleWrite(ctx context.Context, tid int, sc *SyscallContext) {
	if t.fds == nil {
		t.allowSyscall(tid)
		return
	}

	fd := int(int32(sc.Info.Args[0]))
	// ... rest unchanged (uses t.fds, t.mu, t.tracees — no regs needed)
```

- [ ] **Step 6: Update handleClose to accept SyscallContext**

In `internal/ptrace/handle_close.go`:

```go
func (t *Tracer) handleClose(_ context.Context, tid int, sc *SyscallContext) {
	fd := int(int32(sc.Info.Args[0]))
	// ... rest unchanged
```

- [ ] **Step 7: Update handleReadEntry to accept SyscallContext**

In `internal/ptrace/handle_read.go`:

```go
func (t *Tracer) handleReadEntry(tid int, sc *SyscallContext) {
	if t.fds != nil && t.cfg.MaskTracerPid {
		fd := int(int32(sc.Info.Args[0]))
		// ... rest unchanged
```

- [ ] **Step 8: Build and verify**

Run: `go build ./internal/ptrace/`
Expected: PASS. If there are compile errors, they'll be in handler call sites — fix argument mismatches.

- [ ] **Step 9: Run full test suite and cross-compile**

Run: `go test ./... && GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/syscall_context.go internal/ptrace/handle_write.go internal/ptrace/handle_close.go internal/ptrace/handle_read.go
git commit -m "perf(ptrace): use PTRACE_GET_SYSCALL_INFO for entry dispatch

handleSeccompStop and handleSyscallStop use buildSyscallContext for
lighter syscall-number extraction. Simple fd-only handlers (write,
close, read) use sc.Info.Args directly. Complex handlers (file,
network, exec, signal) get Regs via lazy loading in dispatchSyscall.
Falls back to getRegs on kernels without PTRACE_GET_SYSCALL_INFO."
```

---

### Task 8: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `go test ./... -v`
Expected: All PASS

- [ ] **Step 2: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: PASS

- [ ] **Step 3: Run benchmark (if Docker available)**

Run: `make bench`
Expected: Ptrace overhead should be measurably lower than the 621% baseline. Compare results against the table in the spec.

- [ ] **Step 4: Final commit if any fixups needed**

Only if benchmark reveals issues that require fixes.
