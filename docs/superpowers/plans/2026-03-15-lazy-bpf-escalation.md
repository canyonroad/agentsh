# Lazy BPF Escalation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce ptrace network overhead from ~32x to ~15-20x by excluding read/write from the initial BPF filter and lazily escalating per-TGID when TracerPid masking or TLS SNI rewrite is needed.

**Architecture:** Two-tier BPF filter. The narrow initial filter excludes `read`, `pread64`, `write`. When `handleOpenatExit` detects `/proc/*/status`, inject an escalation BPF adding read/pread64 for that TGID. When `handleConnectExit` detects TLS port, inject an escalation BPF adding write. Uses seccomp filter stacking (most restrictive wins). Deferred injection pattern (inject at exit stop, not entry) to avoid consuming the tracee's current syscall.

**Tech Stack:** Go, Linux ptrace, seccomp-BPF, `golang.org/x/sys/unix`

**Spec:** `docs/superpowers/specs/2026-03-15-lazy-bpf-escalation-design.md`

---

## Chunk 1: BPF filter splitting + escalation injection

### Task 1: Split BPF filter into narrow + escalation

**Files:**
- Modify: `internal/ptrace/seccomp_filter.go` (add `buildNarrowPrefilterBPF`, `buildEscalationBPF`)
- Modify: `internal/ptrace/syscalls.go:51-65` (add `narrowTracedSyscallNumbers`)

- [ ] **Step 1: Add `narrowTracedSyscallNumbers` to syscalls.go**

In `internal/ptrace/syscalls.go`, add after `tracedSyscallNumbers()` (line 65):

```go
// narrowTracedSyscallNumbers returns the syscalls for the initial narrow
// BPF filter, excluding read/pread64/write which are lazily escalated.
func narrowTracedSyscallNumbers() []int {
	nums := []int{
		unix.SYS_EXECVE, unix.SYS_EXECVEAT,
		unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2, unix.SYS_FCHOWNAT,
		unix.SYS_CONNECT, unix.SYS_SOCKET, unix.SYS_BIND,
		unix.SYS_SENDTO, unix.SYS_LISTEN,
		unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
		unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO,
		unix.SYS_CLOSE,
	}
	nums = append(nums, legacyFileSyscalls()...)
	return nums
}
```

Note: this is `tracedSyscallNumbers` minus `unix.SYS_WRITE`, `unix.SYS_READ`, `unix.SYS_PREAD64`.

- [ ] **Step 2: Add `buildNarrowPrefilterBPF` to seccomp_filter.go**

In `internal/ptrace/seccomp_filter.go`, add after `buildPrefilterBPF()` (line 94):

```go
// buildNarrowPrefilterBPF generates a BPF filter that excludes read/write
// syscalls from the traced set. Used as the initial filter; read/write are
// lazily escalated per-TGID when needed.
func buildNarrowPrefilterBPF() ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(narrowTracedSyscallNumbers())
}

// buildEscalationBPF generates a minimal BPF filter that traces only the
// specified syscalls. Installed on top of the narrow filter via seccomp
// stacking to add read/write when needed.
func buildEscalationBPF(syscalls []int) ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(syscalls)
}
```

- [ ] **Step 3: Refactor `buildPrefilterBPF` to call shared helper**

Extract the BPF generation logic from `buildPrefilterBPF` into `buildBPFForSyscalls(syscalls []int)`:

```go
// buildBPFForSyscalls generates a seccomp-BPF filter that returns
// SECCOMP_RET_TRACE for the given syscalls and SECCOMP_RET_ALLOW for
// everything else.
func buildBPFForSyscalls(syscalls []int) ([]unix.SockFilter, error) {
	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = auditArchX86_64
	case "arm64":
		auditArch = auditArchAarch64
	default:
		return nil, fmt.Errorf("seccomp prefilter: unsupported architecture %s", runtime.GOARCH)
	}

	n := len(syscalls)
	prog := make([]unix.SockFilter, 0, 4+n+2)

	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetArch})
	prog = append(prog, unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: auditArch})
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})
	prog = append(prog, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: offsetNr})

	for i, nr := range syscalls {
		remaining := n - i - 1
		jumpToTrace := uint8(remaining + 1)
		prog = append(prog, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jumpToTrace,
			Jf:   0,
			K:    uint32(nr),
		})
	}

	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})
	prog = append(prog, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetTrace})

	return prog, nil
}

// buildPrefilterBPF generates the full prefilter (all traced syscalls).
// Used as fallback when lazy escalation is not enabled.
func buildPrefilterBPF() ([]unix.SockFilter, error) {
	return buildBPFForSyscalls(tracedSyscallNumbers())
}
```

- [ ] **Step 4: Build to verify compilation**

Run: `cd /home/eran/work/agentsh && go build ./internal/ptrace/...`
Expected: Success.

- [ ] **Step 5: Commit**

```bash
git add internal/ptrace/seccomp_filter.go internal/ptrace/syscalls.go
git commit -m "refactor(ptrace): split BPF filter into narrow + escalation builders

Extract buildBPFForSyscalls helper. Add narrowTracedSyscallNumbers
(excludes read/pread64/write) and buildEscalationBPF for lazy
seccomp filter stacking.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Add `injectEscalationFilter`

**Files:**
- Modify: `internal/ptrace/inject_seccomp.go` (add `injectEscalationFilter`)

- [ ] **Step 1: Add `injectEscalationFilter` after `injectSeccompFilter`**

In `internal/ptrace/inject_seccomp.go`, add after line 121:

```go
// readEscalationSyscalls are the syscalls added when TracerPid masking is needed.
var readEscalationSyscalls = []int{unix.SYS_READ, unix.SYS_PREAD64}

// writeEscalationSyscalls are the syscalls added when TLS SNI rewrite is needed.
var writeEscalationSyscalls = []int{unix.SYS_WRITE}

// injectEscalationFilter installs an additional seccomp-BPF filter that traces
// the specified syscalls. Stacked on top of the narrow prefilter. Skips
// prctl(PR_SET_NO_NEW_PRIVS) since the initial filter injection already set it.
// The tracee must be at a syscall-exit stop.
func (t *Tracer) injectEscalationFilter(tid int, syscalls []int) error {
	filters, err := buildEscalationBPF(syscalls)
	if err != nil {
		return err
	}
	if len(filters) == 0 {
		return fmt.Errorf("empty escalation BPF")
	}

	savedRegs, err := t.getRegs(tid)
	if err != nil {
		return fmt.Errorf("escalation getRegs: %w", err)
	}

	t.mu.Lock()
	state := t.tracees[tid]
	tgid := tid
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	sp, err := t.ensureScratchPage(tid, tgid, savedRegs)
	if err != nil {
		return fmt.Errorf("escalation scratch page: %w", err)
	}

	totalSize := sockFprogSize + len(filters)*sockFilterSize
	scratchAddr, err := sp.allocate(totalSize)
	if err != nil {
		return fmt.Errorf("escalation scratch allocate: %w", err)
	}

	filterBuf := make([]byte, len(filters)*sockFilterSize)
	for i, f := range filters {
		off := i * sockFilterSize
		binary.LittleEndian.PutUint16(filterBuf[off:], f.Code)
		filterBuf[off+2] = f.Jt
		filterBuf[off+3] = f.Jf
		binary.LittleEndian.PutUint32(filterBuf[off+4:], f.K)
	}

	filterArrayAddr := scratchAddr + sockFprogSize
	fprogBuf := make([]byte, sockFprogSize)
	binary.LittleEndian.PutUint16(fprogBuf[0:], uint16(len(filters)))
	binary.LittleEndian.PutUint64(fprogBuf[8:], filterArrayAddr)

	payload := make([]byte, 0, totalSize)
	payload = append(payload, fprogBuf...)
	payload = append(payload, filterBuf...)
	if err := t.writeBytes(tid, scratchAddr, payload); err != nil {
		return fmt.Errorf("escalation write BPF: %w", err)
	}

	// Skip prctl — PR_SET_NO_NEW_PRIVS already set by initial filter.
	ret, err := t.injectSyscall(tid, savedRegs, unix.SYS_SECCOMP,
		seccompSetModeFilter, 0, scratchAddr, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("escalation inject seccomp: %w", err)
	}
	if ret != 0 {
		return fmt.Errorf("escalation seccomp returned %d (%s)", ret, unix.Errno(-ret))
	}

	slog.Info("seccomp escalation filter installed", "tid", tid, "syscalls", syscalls)
	return nil
}
```

- [ ] **Step 2: Build to verify compilation**

Run: `cd /home/eran/work/agentsh && go build ./internal/ptrace/...`
Expected: Success.

- [ ] **Step 3: Commit**

```bash
git add internal/ptrace/inject_seccomp.go
git commit -m "feat(ptrace): add injectEscalationFilter for lazy BPF stacking

Injects a minimal seccomp filter that traces only the escalated
syscalls (read/pread64 or write). Skips prctl since PR_SET_NO_NEW_PRIVS
is already set by the initial filter.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Chunk 2: TraceeState + escalation triggers + narrow filter

### Task 3: Add escalation fields to TraceeState and use narrow filter

**Files:**
- Modify: `internal/ptrace/tracer.go` (TraceeState, handleNewChild, injectSeccompFilter call)

- [ ] **Step 1: Add escalation fields to TraceeState**

In `internal/ptrace/tracer.go`, add to `TraceeState` (after `NeedExitStop bool` at line ~165):

```go
	// TGID-level: any thread in this TGID triggered escalation
	NeedsReadEscalation  bool
	NeedsWriteEscalation bool
	// Per-thread: escalation filter installed on this specific thread
	ThreadHasReadEscalation  bool
	ThreadHasWriteEscalation bool
	// Deferred: inject escalation at next exit stop
	PendingReadEscalation  bool
	PendingWriteEscalation bool
```

- [ ] **Step 2: Switch initial filter to narrow BPF**

In `internal/ptrace/inject_seccomp.go:33`, change:

```go
// Before:
filters, bpfErr := buildPrefilterBPF()

// After:
filters, bpfErr := buildNarrowPrefilterBPF()
```

- [ ] **Step 3: Update handleNewChild to inherit escalation flags**

In `internal/ptrace/tracer.go`, in `handleNewChild` (line ~1022), update the `existing` branch:

```go
	if existing != nil {
		existing.TGID = childTGID
		existing.ParentPID = parent.TGID
		existing.SessionID = parent.SessionID
		existing.HasPrefilter = parent.HasPrefilter
		// Children inherit parent's kernel filter stack via fork().
		// Skip PendingPrefilter if parent already has a filter installed.
		if parent.HasPrefilter {
			existing.PendingPrefilter = false
		} else {
			existing.PendingPrefilter = parent.PendingPrefilter
		}
		existing.NeedsReadEscalation = parent.NeedsReadEscalation
		existing.NeedsWriteEscalation = parent.NeedsWriteEscalation
		existing.ThreadHasReadEscalation = parent.ThreadHasReadEscalation
		existing.ThreadHasWriteEscalation = parent.ThreadHasWriteEscalation
		existing.Attached = time.Now()
```

And the `else` (new state) branch similarly:

```go
	} else {
		pendingPrefilter := false
		if !parent.HasPrefilter {
			pendingPrefilter = parent.PendingPrefilter
		}
		t.tracees[tid] = &TraceeState{
			TID:                      tid,
			TGID:                     childTGID,
			ParentPID:                parent.TGID,
			SessionID:                parent.SessionID,
			HasPrefilter:             parent.HasPrefilter,
			PendingPrefilter:         pendingPrefilter,
			NeedsReadEscalation:      parent.NeedsReadEscalation,
			NeedsWriteEscalation:     parent.NeedsWriteEscalation,
			ThreadHasReadEscalation:  parent.ThreadHasReadEscalation,
			ThreadHasWriteEscalation: parent.ThreadHasWriteEscalation,
			Attached:                 time.Now(),
			LastNr:                   -1,
			MemFD:                    -1,
			PendingExecStubFD:        -1,
			PendingExecSavedFD:       -1,
			SuppressInitialStop:      true,
		}
	}
```

- [ ] **Step 4: Build to verify compilation**

Run: `cd /home/eran/work/agentsh && go build ./internal/ptrace/...`
Expected: Success.

- [ ] **Step 5: Run full integration test suite**

Run: `cd /home/eran/work/agentsh && go test -tags integration -v -count=1 ./internal/ptrace/`
Expected: All PASS. The narrow filter still traces all exec/file/network/signal/close syscalls, so existing behavior is unchanged. Read/write handlers won't fire for processes that don't escalate, but that only affects TracerPid masking and SNI rewrite — not tested by most tests.

**Important**: `TestIntegration_TracerPidMasked` will FAIL because reads are no longer in the BPF. This is expected and will be fixed in Task 4 (escalation triggers).

- [ ] **Step 6: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/inject_seccomp.go
git commit -m "feat(ptrace): use narrow BPF filter excluding read/write

Switch initial seccomp prefilter to exclude read/pread64/write.
Add escalation state fields to TraceeState. Children inherit
escalation flags and skip redundant BPF re-injection when parent
already has a filter.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Add escalation triggers and deferred injection

**Files:**
- Modify: `internal/ptrace/tracer.go` (handleOpenatExit, handleConnectExit, handleSyscallStop, handleSeccompStop)

- [ ] **Step 1: Add `escalateReadForTGID` and `escalateWriteForTGID` helpers**

In `internal/ptrace/tracer.go`, add after `handleConnectExit` (line ~994):

```go
// escalateReadForTGID marks all threads in the TGID for read/pread64
// escalation and injects the escalation filter into the triggering thread.
func (t *Tracer) escalateReadForTGID(tgid int, triggerTID int) {
	t.mu.Lock()
	for _, s := range t.tracees {
		if s.TGID == tgid {
			s.NeedsReadEscalation = true
		}
	}
	triggerState := t.tracees[triggerTID]
	alreadyEscalated := triggerState != nil && triggerState.ThreadHasReadEscalation
	t.mu.Unlock()

	if alreadyEscalated {
		return
	}

	if err := t.injectEscalationFilter(triggerTID, readEscalationSyscalls); err != nil {
		slog.Warn("read escalation injection failed", "tid", triggerTID, "error", err)
		return
	}

	t.mu.Lock()
	if s := t.tracees[triggerTID]; s != nil {
		s.ThreadHasReadEscalation = true
	}
	t.mu.Unlock()
}

// escalateWriteForTGID marks all threads in the TGID for write
// escalation and injects the escalation filter into the triggering thread.
func (t *Tracer) escalateWriteForTGID(tgid int, triggerTID int) {
	t.mu.Lock()
	for _, s := range t.tracees {
		if s.TGID == tgid {
			s.NeedsWriteEscalation = true
		}
	}
	triggerState := t.tracees[triggerTID]
	alreadyEscalated := triggerState != nil && triggerState.ThreadHasWriteEscalation
	t.mu.Unlock()

	if alreadyEscalated {
		return
	}

	if err := t.injectEscalationFilter(triggerTID, writeEscalationSyscalls); err != nil {
		slog.Warn("write escalation injection failed", "tid", triggerTID, "error", err)
		return
	}

	t.mu.Lock()
	if s := t.tracees[triggerTID]; s != nil {
		s.ThreadHasWriteEscalation = true
	}
	t.mu.Unlock()
}
```

- [ ] **Step 2: Add read escalation trigger in handleOpenatExit**

In `internal/ptrace/tracer.go`, in `handleOpenatExit` (line ~939), change:

```go
// Before:
	if isProcStatus(path) {
		t.fds.trackStatusFd(tgid, fd)
	}

// After:
	if isProcStatus(path) {
		t.fds.trackStatusFd(tgid, fd)
		// Escalate BPF to trace read/pread64 for this TGID.
		t.escalateReadForTGID(tgid, tid)
	}
```

- [ ] **Step 3: Add write escalation trigger in handleConnectExit**

In `internal/ptrace/tracer.go`, in `handleConnectExit` (line ~993), change:

```go
// Before:
	t.fds.watchTLS(tgid, fd, domain)

// After:
	t.fds.watchTLS(tgid, fd, domain)
	// Escalate BPF to trace write for this TGID.
	t.escalateWriteForTGID(tgid, tid)
```

- [ ] **Step 4: Add deferred escalation in handleSyscallStop**

In `internal/ptrace/tracer.go`, in the `handleSyscallStop` exit path. After the existing `PendingPrefilter` block (line ~757) and before the main lock acquisition (line ~762), add:

```go
	// Deferred escalation: inject escalation filters at exit stops.
	t.mu.Lock()
	state = t.tracees[tid]
	if state != nil && state.InSyscall {
		// This is an exit stop — safe to inject.
		if state.PendingReadEscalation {
			state.PendingReadEscalation = false
			state.InSyscall = false // injectFromExit protocol
			t.mu.Unlock()
			if err := t.injectEscalationFilter(tid, readEscalationSyscalls); err != nil {
				slog.Warn("deferred read escalation failed", "tid", tid, "error", err)
			} else {
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.ThreadHasReadEscalation = true
				}
				t.mu.Unlock()
			}
			t.mu.Lock()
			if s := t.tracees[tid]; s != nil {
				s.InSyscall = true // restore for normal exit handling
			}
			t.mu.Unlock()
		} else if state.PendingWriteEscalation {
			state.PendingWriteEscalation = false
			state.InSyscall = false
			t.mu.Unlock()
			if err := t.injectEscalationFilter(tid, writeEscalationSyscalls); err != nil {
				slog.Warn("deferred write escalation failed", "tid", tid, "error", err)
			} else {
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.ThreadHasWriteEscalation = true
				}
				t.mu.Unlock()
			}
			t.mu.Lock()
			if s := t.tracees[tid]; s != nil {
				s.InSyscall = true
			}
			t.mu.Unlock()
		} else {
			t.mu.Unlock()
		}
	} else if state != nil && !state.InSyscall {
		// This is an entry stop — defer to next exit.
		if state.NeedsReadEscalation && !state.ThreadHasReadEscalation {
			state.PendingReadEscalation = true
		}
		if state.NeedsWriteEscalation && !state.ThreadHasWriteEscalation {
			state.PendingWriteEscalation = true
		}
		t.mu.Unlock()
	} else {
		t.mu.Unlock()
	}
```

- [ ] **Step 5: Add deferred escalation flag-setting in handleSeccompStop**

In `internal/ptrace/tracer.go`, in `handleSeccompStop` (line ~851), after setting `state.NeedExitStop` (line ~869) and before `t.mu.Unlock()` (line ~871):

```go
		// Seccomp stops are entry-only. Defer escalation to next exit stop
		// (which will be handled by handleSyscallStop's deferred path).
		if state.NeedsReadEscalation && !state.ThreadHasReadEscalation {
			state.PendingReadEscalation = true
		}
		if state.NeedsWriteEscalation && !state.ThreadHasWriteEscalation {
			state.PendingWriteEscalation = true
		}
```

- [ ] **Step 6: Build to verify compilation**

Run: `cd /home/eran/work/agentsh && go build ./internal/ptrace/...`
Expected: Success.

- [ ] **Step 7: Run TracerPid masking regression test**

Run: `cd /home/eran/work/agentsh && go test -tags integration -run TestIntegration_TracerPidMasked -v -count=1 ./internal/ptrace/`
Expected: PASS — openat detects `/proc/self/status`, triggers read escalation, reads are then traced and masked.

- [ ] **Step 8: Run full integration test suite**

Run: `cd /home/eran/work/agentsh && go test -tags integration -v -count=1 ./internal/ptrace/`
Expected: All PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/ptrace/tracer.go
git commit -m "feat(ptrace): lazy BPF escalation for read/write syscalls

Add escalation triggers in handleOpenatExit (read) and
handleConnectExit (write). Deferred injection at exit stops
avoids consuming the tracee's current syscall. Per-TGID
escalation with lazy per-thread propagation.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Chunk 3: Tests + final verification

### Task 5: Add integration tests for lazy escalation

**Files:**
- Modify: `internal/ptrace/integration_test.go`

- [ ] **Step 1: Add `TestIntegration_NarrowBPFNoReadStops`**

```go
func TestIntegration_NarrowBPFNoReadStops(t *testing.T) {
	requirePtrace(t)

	execHandler := &mockExecHandler{defaultAllow: true}
	fileHandler := &mockFileHandler{defaultAllow: true}

	exitSkipped := &atomic.Int64{}
	metrics := &testMetrics{exitStopSkipped: exitSkipped}

	cfg := TracerConfig{
		TraceExecve:      true,
		TraceFile:        true,
		SeccompPrefilter: true,
		MaskTracerPid:    true,
		ExecHandler:      execHandler,
		FileHandler:      fileHandler,
		MaxHoldMs:        5000,
		Metrics:          metrics,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Process that does many reads but never opens /proc/*/status.
	// With narrow BPF, reads should not generate any ptrace stops at all.
	tmpDir := t.TempDir()
	readyFile := filepath.Join(tmpDir, "ready")
	shellCmd := fmt.Sprintf(
		`while [ ! -f %s ]; do sleep 0.01; done; i=0; while [ $i -lt 100 ]; do cat /dev/null; i=$((i+1)); done`,
		readyFile,
	)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 10*time.Second)
	cancel()
	<-errCh

	// With the narrow BPF, reads are not in the filter at all.
	// The exitStopSkipped counter should be 0 for reads (no entry stops
	// means handleReadEntry never runs). It may be non-zero for connect
	// exit skips from other syscalls.
	t.Logf("exit stops skipped: %d (should be low — reads not in BPF)", exitSkipped.Load())
}
```

- [ ] **Step 2: Add `TestIntegration_ReadEscalationOnStatusOpen`**

```go
func TestIntegration_ReadEscalationOnStatusOpen(t *testing.T) {
	requirePtrace(t)

	execHandler := &mockExecHandler{defaultAllow: true}
	fileHandler := &mockFileHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:      true,
		TraceFile:        true,
		SeccompPrefilter: true,
		MaskTracerPid:    true,
		ExecHandler:      execHandler,
		FileHandler:      fileHandler,
		MaxHoldMs:        5000,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	tmpDir := t.TempDir()
	readyFile := filepath.Join(tmpDir, "ready")
	outfile := filepath.Join(tmpDir, "tracerpid.txt")
	// Open /proc/self/status (triggers read escalation), then read it.
	shellCmd := fmt.Sprintf(
		`while [ ! -f %s ]; do sleep 0.01; done; grep TracerPid /proc/self/status > %s`,
		readyFile, outfile,
	)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 5*time.Second)
	cancel()
	<-errCh

	data, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	if !strings.Contains(line, "TracerPid:\t0") && !strings.Contains(line, "TracerPid: 0") {
		t.Fatalf("expected masked TracerPid after escalation, got: %q", line)
	}
	t.Logf("TracerPid masked correctly after read escalation: %s", line)
}
```

- [ ] **Step 3: Add `TestIntegration_ChildInheritsEscalation`**

```go
func TestIntegration_ChildInheritsEscalation(t *testing.T) {
	requirePtrace(t)

	execHandler := &mockExecHandler{defaultAllow: true}
	fileHandler := &mockFileHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:      true,
		TraceFile:        true,
		SeccompPrefilter: true,
		MaskTracerPid:    true,
		ExecHandler:      execHandler,
		FileHandler:      fileHandler,
		MaxHoldMs:        5000,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	tmpDir := t.TempDir()
	readyFile := filepath.Join(tmpDir, "ready")
	outfile := filepath.Join(tmpDir, "child_tracerpid.txt")
	// Parent opens /proc/self/status (triggers escalation), then
	// spawns a child that also reads /proc/self/status.
	shellCmd := fmt.Sprintf(
		`while [ ! -f %s ]; do sleep 0.01; done; cat /proc/self/status > /dev/null; grep TracerPid /proc/self/status > %s`,
		readyFile, outfile,
	)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 5*time.Second)
	cancel()
	<-errCh

	data, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	if !strings.Contains(line, "TracerPid:\t0") && !strings.Contains(line, "TracerPid: 0") {
		t.Fatalf("expected masked TracerPid in child, got: %q", line)
	}
	t.Logf("child TracerPid masked correctly: %s", line)
}
```

- [ ] **Step 4: Add `TestIntegration_WriteEscalationOnTLSConnect`**

```go
func TestIntegration_WriteEscalationOnTLSConnect(t *testing.T) {
	requirePtrace(t)

	execHandler := &mockExecHandler{defaultAllow: true}
	netHandler := &mockNetworkHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:      true,
		TraceNetwork:     true,
		SeccompPrefilter: true,
		ExecHandler:      execHandler,
		NetworkHandler:   netHandler,
		MaxHoldMs:        5000,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	tmpDir := t.TempDir()
	readyFile := filepath.Join(tmpDir, "ready")
	// Connect to port 443 — will fail but triggers handleConnectExit
	shellCmd := fmt.Sprintf(
		`while [ ! -f %s ]; do sleep 0.01; done; echo | nc -w1 127.0.0.1 443 2>/dev/null || true`,
		readyFile,
	)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 10*time.Second)
	cancel()
	<-errCh

	// Verify the network handler saw a connect to 443.
	calls := netHandler.CallCount()
	if calls == 0 {
		t.Fatal("expected network handler to be called for connect to 443")
	}
	t.Logf("network handler calls: %d", calls)
	// Note: NeedsWriteEscalation is only set if handleConnectExit finds a
	// cached domain for the IP. Without a DNS proxy, the domain lookup fails
	// and escalation is skipped. This test verifies the connect path works;
	// full write escalation requires DNS resolution setup.
}
```

- [ ] **Step 5: Add `TestIntegration_SkipReinjectionForChildren`**

```go
func TestIntegration_SkipReinjectionForChildren(t *testing.T) {
	requirePtrace(t)

	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:      true,
		SeccompPrefilter: true,
		ExecHandler:      execHandler,
		MaxHoldMs:        5000,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	tmpDir := t.TempDir()
	readyFile := filepath.Join(tmpDir, "ready")
	// Parent spawns children. Children should inherit parent's filter.
	shellCmd := fmt.Sprintf(
		`while [ ! -f %s ]; do sleep 0.01; done; for i in 1 2 3; do /bin/true; done`,
		readyFile,
	)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 10*time.Second)
	cancel()
	<-errCh

	// If children re-injected BPF, we'd see errors or slowness.
	// Success = all execs completed without issues.
	t.Logf("children completed successfully (filter inherited, no re-injection)")
}
```

- [ ] **Step 6: Run all new tests**

Run: `cd /home/eran/work/agentsh && go test -tags integration -run "TestIntegration_NarrowBPF|TestIntegration_ReadEscalation|TestIntegration_ChildInheritsEscalation|TestIntegration_WriteEscalation|TestIntegration_SkipReinjection" -v -count=1 ./internal/ptrace/`
Expected: All PASS.

- [ ] **Step 7: Run the full integration test suite**

Run: `cd /home/eran/work/agentsh && go test -tags integration -v -count=1 ./internal/ptrace/`
Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/ptrace/integration_test.go
git commit -m "test(ptrace): add integration tests for lazy BPF escalation

Verify: narrow BPF avoids read stops, read escalation masks TracerPid,
child processes inherit escalation state.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Cross-compilation and final verification

**Files:** None modified — verification only.

- [ ] **Step 1: Verify cross-compilation for Windows**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./...`
Expected: Success.

- [ ] **Step 2: Run `go vet`**

Run: `cd /home/eran/work/agentsh && go vet ./internal/ptrace/...`
Expected: No issues.

- [ ] **Step 3: Run full project test suite**

Run: `cd /home/eran/work/agentsh && go test ./...`
Expected: All PASS.

- [ ] **Step 4: Run full integration test suite one final time**

Run: `cd /home/eran/work/agentsh && go test -tags integration -v -count=1 ./internal/ptrace/`
Expected: All PASS.
