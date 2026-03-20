# Ptrace Symlink Verification + vfork Fast-path Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two ptrace tracer gaps: exit-time openat path verification to catch symlink bypasses, and vfork child fast-path to prevent deadlocks with Python subprocess.run.

**Architecture:** Defense-in-depth exit-time fd verification for openat/openat2 catches any entry-time symlink resolution failure. vfork children skip policy evaluation for all non-exec syscalls, with the exit-time verification acting as a safety net.

**Tech Stack:** Go, Linux ptrace, seccomp-BPF, `/proc` filesystem

---

### Task 1: Fix PTRACE_GET_SYSCALL_INFO Op check for seccomp stops

**Files:**
- Modify: `internal/ptrace/syscall_context.go:45-77`
- Test: `internal/ptrace/syscall_context_test.go`

- [ ] **Step 1: Write test for Op=3 acceptance**

Add to `internal/ptrace/syscall_context_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it passes (baseline)**

Run: `cd /home/eran/work/agentsh && go test ./internal/ptrace/ -run TestGetSyscallEntryInfoAcceptsSeccompOp -v`

- [ ] **Step 3: Fix the Op check and update struct comment**

In `internal/ptrace/syscall_context.go`, make two changes:

1. Update the struct comment (line 45-47):
```go
// ptraceSyscallInfo mirrors struct ptrace_syscall_info (Linux 5.3+).
// The kernel struct is a union; we use the entry/seccomp fields (op==1 or op==3).
// Both variants share the same nr + args[6] layout at the same offset.
// We request ptraceSyscallInfoSize bytes; the kernel writes min(requested, actual).
```

2. Update the Op check (line 75-76):
```go
	if info.Op != 1 && info.Op != 3 {
		return nil, fmt.Errorf("PTRACE_GET_SYSCALL_INFO: unexpected op %d (want entry=1 or seccomp=3)", info.Op)
	}
```

- [ ] **Step 4: Run all syscall_context tests**

Run: `cd /home/eran/work/agentsh && go test ./internal/ptrace/ -run TestSyscallContext -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ptrace/syscall_context.go internal/ptrace/syscall_context_test.go
git commit -m "fix(ptrace): accept Op=3 (seccomp) in PTRACE_GET_SYSCALL_INFO

getSyscallEntryInfo rejected Op=3 (PTRACE_SYSCALL_INFO_SECCOMP), forcing
a fallback to full getRegs on every seccomp stop. The seccomp variant
has the same nr+args layout as entry — accept both."
```

---

### Task 2: Always require exit stops for openat/openat2

**Files:**
- Modify: `internal/ptrace/tracer.go:468-480`
- Test: `internal/ptrace/tracer_test.go:65-96`

- [ ] **Step 1: Update the existing needsExitStop tests**

The existing test at `tracer_test.go:74-75` expects `openat with mask off → false` and `openat2 with mask off → false`. These must change to `true`. Update `internal/ptrace/tracer_test.go`:

Change the test cases:
```go
{"openat with mask on", unix.SYS_OPENAT, true, true, true},
{"openat with mask off", unix.SYS_OPENAT, false, true, true},   // was false
{"openat2 with mask off", unix.SYS_OPENAT2, false, true, true}, // was false
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh && go test ./internal/ptrace/ -run TestNeedsExitStop -v`
Expected: FAIL — the two changed cases now expect `true` but get `false`

- [ ] **Step 3: Update needsExitStop**

In `internal/ptrace/tracer.go`, change the openat/openat2 case (line 472-473):

```go
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
		return true // exit-time path verification for symlink defense-in-depth
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh && go test ./internal/ptrace/ -run TestNeedsExitStop -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/tracer_test.go
git commit -m "fix(ptrace): always require exit stops for openat/openat2

Exit stops are now unconditional for openat/openat2, not just when
MaskTracerPid is set. This enables exit-time path verification to
catch symlink bypasses that evade entry-time resolution."
```

---

### Task 3: Exit-time path verification in handleOpenatExit

**Files:**
- Modify: `internal/ptrace/tracer.go:993-1036` (handleSyscallExit + handleOpenatExit)
- Modify: `internal/ptrace/handle_file.go` (add verifyOpenatPath)
- Test: `internal/ptrace/handle_file_test.go`

- [ ] **Step 1: Write test for symlink resolution through resolvePath**

Add to `internal/ptrace/handle_file_test.go`:

```go
func TestResolvePath_FollowsSymlink(t *testing.T) {
	// resolvePath must resolve symlinks to their targets.
	// If /tmp/link -> /etc/hostname, resolvePath should return /etc/hostname.
	tid := os.Getpid()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("x"), 0o644)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)

	resolved, err := resolvePath(tid, unix.AT_FDCWD, link)
	if err != nil {
		t.Fatalf("resolvePath: %v", err)
	}
	if resolved != target {
		t.Errorf("resolvePath(%q) = %q, want %q", link, resolved, target)
	}
}

func TestResolvePath_ChainedSymlinks(t *testing.T) {
	tid := os.Getpid()
	dir := t.TempDir()
	target := filepath.Join(dir, "final")
	os.WriteFile(target, []byte("x"), 0o644)
	link1 := filepath.Join(dir, "link1")
	link2 := filepath.Join(dir, "link2")
	os.Symlink(target, link1)
	os.Symlink(link1, link2)

	resolved, err := resolvePath(tid, unix.AT_FDCWD, link2)
	if err != nil {
		t.Fatalf("resolvePath: %v", err)
	}
	if resolved != target {
		t.Errorf("resolvePath(%q) = %q, want %q (through chain)", link2, resolved, target)
	}
}
```

- [ ] **Step 2: Run tests to verify they pass (confirming entry-time resolution works)**

Run: `cd /home/eran/work/agentsh && go test ./internal/ptrace/ -run "TestResolvePath_FollowsSymlink|TestResolvePath_ChainedSymlinks" -v`
Expected: PASS — confirms existing entry-time resolution works in unit tests

- [ ] **Step 3: Refactor handleOpenatExit to always read fd path**

In `internal/ptrace/tracer.go`, refactor `handleOpenatExit` to: (a) always run (not gated on MaskTracerPid), (b) read the fd path once, (c) use it for both TracerPid masking and the new verification. The function now takes `context.Context` for policy evaluation.

Replace the existing `handleOpenatExit` (lines 1005-1036) and update `handleSyscallExit` (line 999) to pass `ctx`:

First, update `handleSyscallExit` signature and the openat case:
```go
func (t *Tracer) handleSyscallExit(ctx context.Context, tid int, nr int, regs Regs) {
	switch {
	case isReadSyscall(nr):
		t.handleReadExit(tid, regs)
	case nr == unix.SYS_OPENAT || nr == unix.SYS_OPENAT2:
		t.handleOpenatExit(ctx, tid, regs)
	case nr == unix.SYS_CONNECT:
		t.handleConnectExit(tid, regs)
	}
}
```

Update the caller at line 932:
```go
			t.handleSyscallExit(ctx, tid, nr, exitRegs)
```

And for the seccomp path — since `handleSyscallStop` receives `ctx`, this just threads it through. The exit path in `handleSyscallStop` already has access to `ctx` from the function parameter.

Now replace `handleOpenatExit`:
```go
// handleOpenatExit verifies the opened path against policy and tracks
// /proc/*/status fds for TracerPid masking.
func (t *Tracer) handleOpenatExit(ctx context.Context, tid int, regs Regs) {
	retVal := regs.ReturnValue()
	if retVal < 0 {
		return // open failed
	}
	fd := int(retVal)

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	// Read the real path the kernel opened.
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, fd))
	if err != nil {
		// Cannot verify — fail closed. Close the fd and deny.
		slog.Warn("handleOpenatExit: cannot read fd path, denying",
			"tid", tid, "fd", fd, "error", err)
		savedRegs := regs.Clone()
		t.cleanupInjectedFD(tid, savedRegs, fd, -1)
		t.applyReturnOverride(tid, -int64(unix.EACCES))
		return
	}

	// TracerPid masking: track fds opened on /proc/*/status.
	if t.fds != nil && t.cfg.MaskTracerPid && isProcStatus(path) {
		t.fds.trackStatusFd(tgid, fd)
		t.escalateReadForTGID(tgid, tid)
	}

	// Exit-time path verification: evaluate policy against the real path.
	if t.cfg.FileHandler != nil && t.cfg.TraceFile && sessionID != "" {
		result := t.cfg.FileHandler.HandleFile(ctx, FileContext{
			PID:       tgid,
			SessionID: sessionID,
			Syscall:   unix.SYS_OPENAT,
			Path:      path,
			Operation: "open",
		})
		action := result.Action
		if action == "" {
			if result.Allow {
				action = "allow"
			} else {
				action = "deny"
			}
		}
		if action == "deny" {
			slog.Warn("handleOpenatExit: exit-time verification denied",
				"tid", tid, "fd", fd, "path", path)
			savedRegs := regs.Clone()
			t.cleanupInjectedFD(tid, savedRegs, fd, -1)
			t.applyReturnOverride(tid, -int64(unix.EACCES))
		}
	}
}
```

- [ ] **Step 4: Run all tests to verify nothing is broken**

Run: `cd /home/eran/work/agentsh && go test ./internal/ptrace/ -v -count=1 2>&1 | tail -20`
Expected: All existing tests PASS

- [ ] **Step 5: Run full build including cross-compilation**

Run: `cd /home/eran/work/agentsh && go build ./... && GOOS=windows go build ./...`
Expected: Both succeed

- [ ] **Step 6: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/handle_file.go internal/ptrace/handle_file_test.go
git commit -m "fix(ptrace): add exit-time path verification for openat/openat2

After a successful openat, read /proc/<tid>/fd/<fd> to verify the real
path against policy. If denied (e.g. symlink resolved to a forbidden
target), close the fd and override the return to -EACCES.

This is defense-in-depth: catches symlink bypasses regardless of whether
entry-time resolution via resolveViaProc fails due to environmental
issues. Also refactors handleOpenatExit to always run (not gated on
MaskTracerPid) and share the readlink result for both verification
and TracerPid masking."
```

---

### Task 4: vfork child fast-path in handleSeccompStop

**Files:**
- Modify: `internal/ptrace/tracer.go:940-969` (handleSeccompStop)
- Test: `internal/ptrace/tracer_test.go`

- [ ] **Step 1: Write test for vfork fast-path logic**

Add to `internal/ptrace/tracer_test.go`:

```go
func TestIsVforkFastPathSkipsNonExec(t *testing.T) {
	// Verify the fast-path condition: IsVforkChild && !isExecveSyscall
	tests := []struct {
		name      string
		isVfork   bool
		nr        int
		wantFast  bool
	}{
		{"vfork child close", true, unix.SYS_CLOSE, true},
		{"vfork child openat", true, unix.SYS_OPENAT, true},
		{"vfork child execve", true, unix.SYS_EXECVE, false},
		{"vfork child execveat", true, unix.SYS_EXECVEAT, false},
		{"non-vfork close", false, unix.SYS_CLOSE, false},
		{"non-vfork openat", false, unix.SYS_OPENAT, false},
		{"non-vfork execve", false, unix.SYS_EXECVE, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.isVfork && !isExecveSyscall(tt.nr)
			if got != tt.wantFast {
				t.Errorf("fastPath(%v, %d) = %v, want %v",
					tt.isVfork, tt.nr, got, tt.wantFast)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it passes (logic test)**

Run: `cd /home/eran/work/agentsh && go test ./internal/ptrace/ -run TestIsVforkFastPathSkipsNonExec -v`
Expected: PASS

- [ ] **Step 3: Add vfork fast-path to handleSeccompStop**

In `internal/ptrace/tracer.go`, modify `handleSeccompStop` (lines 940-969). Insert the fast-path check after the mutex unlock, before `dispatchSyscall`:

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
	isVfork := state != nil && state.IsVforkChild
	if state != nil {
		state.InSyscall = true
		state.LastNr = nr
		state.NeedExitStop = t.needsExitStop(nr)
		// Seccomp stops are entry-only. Defer escalation to next exit stop.
		if state.NeedsReadEscalation && !state.ThreadHasReadEscalation {
			state.PendingReadEscalation = true
		}
		if state.NeedsWriteEscalation && !state.ThreadHasWriteEscalation {
			state.PendingWriteEscalation = true
		}
	}
	t.mu.Unlock()

	// Fast-path: vfork children only need policy evaluation at execve.
	// All other syscalls between vfork and exec are async-signal-safe
	// setup operations (close, dup2, sigaction, etc.) — safe to allow.
	// For openat/openat2, NeedExitStop is already set above, so
	// exit-time path verification still runs as a safety net.
	if isVfork && !isExecveSyscall(nr) {
		t.allowSyscall(tid)
		return
	}

	t.dispatchSyscall(ctx, tid, nr, sc)
}
```

- [ ] **Step 4: Run all tests**

Run: `cd /home/eran/work/agentsh && go test ./internal/ptrace/ -v -count=1 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/tracer_test.go
git commit -m "fix(ptrace): fast-path vfork children in handleSeccompStop

Skip policy evaluation for non-execve syscalls when IsVforkChild is set.
Between vfork and exec, only async-signal-safe operations occur (close,
dup2, sigaction, etc.) which are safe to allow without policy evaluation.

Execve still gets full policy evaluation. For openat (undefined behavior
between vfork/exec), NeedExitStop is set before the fast-path check,
so exit-time path verification still catches policy violations."
```

---

### Task 5: vfork child fast-path in handleSyscallStop

**Files:**
- Modify: `internal/ptrace/tracer.go:886-904` (handleSyscallStop entry path)

- [ ] **Step 1: Add vfork fast-path to handleSyscallStop entry path**

In `internal/ptrace/tracer.go`, modify the `entering` branch (lines 890-903). Insert the fast-path check after setting `NeedExitStop` and before `dispatchSyscall`:

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

		// Fast-path vfork children (same logic as handleSeccompStop).
		if state.IsVforkChild && !isExecveSyscall(nr) {
			t.allowSyscall(tid)
			return
		}

		t.dispatchSyscall(ctx, tid, nr, sc)
	} else {
```

- [ ] **Step 2: Run all tests**

Run: `cd /home/eran/work/agentsh && go test ./internal/ptrace/ -v -count=1 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 3: Run full build including cross-compilation**

Run: `cd /home/eran/work/agentsh && go build ./... && GOOS=windows go build ./...`
Expected: Both succeed

- [ ] **Step 4: Commit**

```bash
git add internal/ptrace/tracer.go
git commit -m "fix(ptrace): fast-path vfork children in handleSyscallStop

Mirror the handleSeccompStop fast-path for the TRACESYSGOOD code path
(used when seccomp prefilter is disabled). Same logic: skip policy
evaluation for non-execve syscalls when IsVforkChild is set."
```

---

### Task 6: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cd /home/eran/work/agentsh && go test ./... -count=1 2>&1 | tail -30`
Expected: All tests PASS

- [ ] **Step 2: Verify cross-compilation**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./...`
Expected: SUCCESS

- [ ] **Step 3: Review all changes on the branch**

Run: `cd /home/eran/work/agentsh && git log --oneline main..HEAD`

Expected commits (oldest to newest):
1. `fix(ptrace): accept Op=3 (seccomp) in PTRACE_GET_SYSCALL_INFO`
2. `fix(ptrace): always require exit stops for openat/openat2`
3. `fix(ptrace): add exit-time path verification for openat/openat2`
4. `fix(ptrace): fast-path vfork children in handleSeccompStop`
5. `fix(ptrace): fast-path vfork children in handleSyscallStop`
