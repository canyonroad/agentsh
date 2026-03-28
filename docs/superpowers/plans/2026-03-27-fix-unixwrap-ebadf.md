# Fix agentsh-unixwrap EBADF Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix EBADF on shared library loading by only trapping write-flagged openat in the BPF filter, with a handler-level safety net.

**Architecture:** BPF filter uses per-flag `AddRuleConditional` with `CompareMaskedEqual` so read-only openat falls to `ActAllow`. Handler adds `isReadOnlyOpen()` guard before emulation as defense-in-depth.

**Tech Stack:** Go, libseccomp-golang (`seccomp.MakeCondition`/`AddRuleConditional`), x/sys/unix

**Spec:** `docs/superpowers/specs/2026-03-27-fix-unixwrap-ebadf-design.md`

---

### Task 1: Add `openatWriteMask` constant and `isReadOnlyOpen` helper

**Files:**
- Modify: `internal/netmonitor/unix/file_syscalls.go:47-51` (after `emulableFlagMask`)
- Test: `internal/netmonitor/unix/file_syscalls_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/netmonitor/unix/file_syscalls_test.go`:

```go
func TestIsReadOnlyOpen(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint32
		expected bool
	}{
		{"O_RDONLY", unix.O_RDONLY, true},
		{"O_RDONLY|O_CLOEXEC", unix.O_RDONLY | unix.O_CLOEXEC, true},
		{"O_RDONLY|O_NOFOLLOW", unix.O_RDONLY | unix.O_NOFOLLOW, true},
		{"O_RDONLY|O_DIRECTORY", unix.O_RDONLY | unix.O_DIRECTORY, true},
		{"O_RDONLY|O_NONBLOCK", unix.O_RDONLY | unix.O_NONBLOCK, true},
		{"O_WRONLY", unix.O_WRONLY, false},
		{"O_RDWR", unix.O_RDWR, false},
		{"O_RDONLY|O_CREAT", unix.O_RDONLY | unix.O_CREAT, false},
		{"O_RDONLY|O_TRUNC", unix.O_RDONLY | unix.O_TRUNC, false},
		{"O_RDONLY|O_APPEND", unix.O_RDONLY | unix.O_APPEND, false},
		{"O_TMPFILE", unix.O_TMPFILE, false},
		{"O_WRONLY|O_CREAT|O_TRUNC", unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isReadOnlyOpen(tt.flags), "flags=0x%x", tt.flags)
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/netmonitor/unix/ -run TestIsReadOnlyOpen -v -tags "linux,cgo"`
Expected: FAIL — `isReadOnlyOpen` not defined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/netmonitor/unix/file_syscalls.go`, after the `emulableFlagMask` const block (after line 51):

```go
// openatWriteMask defines flags that indicate a write/create operation.
// Matches the ptrace prefilter mask in seccomp_filter.go (0x400643).
// O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND | __O_TMPFILE.
// Uses __O_TMPFILE (0x400000) not unix.O_TMPFILE (0x410000) because
// the latter includes O_DIRECTORY which is not a write indicator.
const openatWriteMask = 0x400643

// isReadOnlyOpen returns true if the flags indicate a read-only open
// (no write, create, truncate, append, or tmpfile flags set).
func isReadOnlyOpen(flags uint32) bool {
	return flags&openatWriteMask == 0
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/netmonitor/unix/ -run TestIsReadOnlyOpen -v -tags "linux,cgo"`
Expected: PASS — all 12 cases pass.

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/file_syscalls.go internal/netmonitor/unix/file_syscalls_test.go
git commit -m "feat(seccomp): add openatWriteMask and isReadOnlyOpen helper

Shared constant matching ptrace prefilter mask (0x400643). Helper
classifies open flags as read-only when no write/create/truncate/
append/tmpfile bits are set."
```

---

### Task 2: BPF filter — flag-based openat conditional rules

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go:231-255` (the `FileMonitorEnabled` block)
- Test: `internal/netmonitor/unix/seccomp_linux_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/netmonitor/unix/seccomp_linux_test.go`:

```go
func TestFilterConfig_FileMonitorWriteFlags(t *testing.T) {
	// Verify the config accepts FileMonitorEnabled and the openat
	// write-flag constants are consistent with the ptrace prefilter.
	cfg := FilterConfig{
		UnixSocketEnabled:  true,
		FileMonitorEnabled: true,
	}
	require.True(t, cfg.FileMonitorEnabled)

	// Verify the write mask matches the ptrace prefilter value.
	// openatWriteMask is defined in file_syscalls.go.
	require.Equal(t, uint32(0x400643), uint32(openatWriteMask),
		"openatWriteMask must match ptrace prefilter")
}
```

- [ ] **Step 2: Run test to verify it passes** (this is a config/constant validation test)

Run: `go test ./internal/netmonitor/unix/ -run TestFilterConfig_FileMonitorWriteFlags -v -tags "linux,cgo"`
Expected: PASS (constants already defined in Task 1).

- [ ] **Step 3: Replace unconditional openat rule with per-flag conditional rules**

In `internal/netmonitor/unix/seccomp_linux.go`, replace lines 231-255 (the `if cfg.FileMonitorEnabled` block) with:

```go
	// File I/O monitoring via user-notify
	if cfg.FileMonitorEnabled {
		trap := seccomp.ActNotify

		// openat: only trap write-flagged opens.
		// Each rule checks one flag bit via MaskedEq: (flags & bit) == bit.
		// Multiple rules on the same syscall act as OR in libseccomp —
		// if ANY write flag is set, the open is trapped.
		// Read-only opens (no write flags) match no rule → ActAllow.
		openatWriteFlags := []uint64{
			unix.O_WRONLY, // 0x1
			unix.O_RDWR,   // 0x2
			unix.O_CREAT,  // 0x40
			unix.O_TRUNC,  // 0x200
			unix.O_APPEND, // 0x400
			0x400000,       // __O_TMPFILE (without O_DIRECTORY)
		}
		for _, flag := range openatWriteFlags {
			cond, err := seccomp.MakeCondition(2, seccomp.CompareMaskedEqual, flag, flag)
			if err != nil {
				return nil, fmt.Errorf("make openat condition for flag 0x%x: %w", flag, err)
			}
			if err := filt.AddRuleConditional(seccomp.ScmpSyscall(unix.SYS_OPENAT), trap, []seccomp.ScmpCondition{cond}); err != nil {
				return nil, fmt.Errorf("add openat conditional rule for flag 0x%x: %w", flag, err)
			}
		}

		// openat2: unconditional ActNotify (flags in struct pointer, can't
		// inspect in BPF). Handler falls back to CONTINUE via shouldFallbackToContinue.
		if err := filt.AddRule(seccomp.ScmpSyscall(unix.SYS_OPENAT2), trap); err != nil {
			return nil, fmt.Errorf("add openat2 rule: %w", err)
		}

		// Non-open file syscalls: unconditional ActNotify (always write operations).
		nonOpenFileRules := []seccomp.ScmpSyscall{
			seccomp.ScmpSyscall(unix.SYS_UNLINKAT),
			seccomp.ScmpSyscall(unix.SYS_MKDIRAT),
			seccomp.ScmpSyscall(unix.SYS_RENAMEAT2),
			seccomp.ScmpSyscall(unix.SYS_LINKAT),
			seccomp.ScmpSyscall(unix.SYS_SYMLINKAT),
			seccomp.ScmpSyscall(unix.SYS_FCHMODAT),
			seccomp.ScmpSyscall(unix.SYS_FCHOWNAT),
		}
		for _, sc := range nonOpenFileRules {
			if err := filt.AddRule(sc, trap); err != nil {
				return nil, fmt.Errorf("add file monitor rule %v: %w", sc, err)
			}
		}

		// Legacy open syscalls: unconditional ActNotify (rare on modern systems).
		for _, sc := range legacyFileSyscallList() {
			if err := filt.AddRule(seccomp.ScmpSyscall(sc), trap); err != nil {
				return nil, fmt.Errorf("add legacy file rule %v: %w", sc, err)
			}
		}
	}
```

- [ ] **Step 4: Verify build and existing tests pass**

Run: `go build ./... && go test ./internal/netmonitor/unix/ -v -tags "linux,cgo" -count=1`
Expected: Build succeeds, all existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go internal/netmonitor/unix/seccomp_linux_test.go
git commit -m "fix(seccomp): only trap write-flagged openat in BPF filter

Replace unconditional openat ActNotify with per-flag conditional rules
using CompareMaskedEqual. Read-only opens (O_RDONLY without write flags)
now fall to ActAllow — kernel handles them directly with zero overhead.
This fixes EBADF on dynamic linker loading shared libraries because
read-only opens are no longer routed through the emulation path.

openat2 remains unconditional (flags in struct pointer, handler uses
CONTINUE fallback). Non-open file syscalls unchanged (always writes)."
```

---

### Task 3: Handler defense-in-depth — read-only guard in emulation path

**Files:**
- Modify: `internal/netmonitor/unix/handler.go:604` (insert after ActionDeny branch, before NotifIDValid)
- Test: `internal/netmonitor/unix/file_handler_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/netmonitor/unix/file_handler_test.go`:

```go
func TestFileHandler_ReadOnlyOpen_SkipsEmulation(t *testing.T) {
	// When EmulateOpen is true, a read-only open should still get
	// ActionContinue from Handle (defense-in-depth: the handler
	// shouldn't try to emulate reads even if they reach it).
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/lib/x86_64-linux-gnu/libtinfo.so.6": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "system-allow",
			},
		},
	}
	emitter := &mockFileEmitter{}
	handler := NewFileHandler(policy, NewMountRegistry(), emitter, true)
	handler.SetEmulateOpen(true)

	// A read-only open — like the dynamic linker loading a shared library.
	req := FileRequest{
		PID:       500,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/lib/x86_64-linux-gnu/libtinfo.so.6",
		Operation: "open",
		Flags:     uint32(unix.O_RDONLY | unix.O_CLOEXEC),
		SessionID: "sess-test",
	}
	result := handler.Handle(req)
	assert.Equal(t, ActionContinue, result.Action,
		"read-only open must get ActionContinue even with emulation enabled")
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./internal/netmonitor/unix/ -run TestFileHandler_ReadOnlyOpen_SkipsEmulation -v -tags "linux,cgo"`
Expected: PASS — `Handle()` already returns `ActionContinue` for allowed reads (the handler decides allow/deny, the guard in the notification loop prevents emulation). This test validates the handler's decision is correct for reads.

Note: The actual emulation guard is in `handleFileNotificationEmulated` (the notification loop function), not in `Handle()`. The test above validates the handler's policy decision is correct for reads. The guard in the notification loop can't be unit tested without real seccomp notification fds (requires root/CAP_SYS_ADMIN). Its correctness follows from `isReadOnlyOpen` (tested in Task 1) — the guard is a one-line `if isReadOnlyOpen(flags) { CONTINUE }` check. End-to-end validation happens via the Runloop integration test (Task 4).

- [ ] **Step 3: Add read-only guard in handleFileNotificationEmulated**

In `internal/netmonitor/unix/handler.go`, insert after line 604 (after the `ActionDeny` return) and before line 605 (the `NotifIDValid` comment):

```go
		// Defense-in-depth: never emulate read-only opens.
		// With BPF flag filtering, reads should not reach here.
		// But if they do (openat2 fallback, future filter changes),
		// CONTINUE is always safe for reads — no TOCTOU risk.
		if isReadOnlyOpen(fileArgs.Flags) {
			if err := NotifRespondContinue(int(fd), req.ID); err != nil {
				slog.Debug("emulated file handler: read-only continue failed", "pid", pid, "error", err)
			}
			return
		}
```

- [ ] **Step 4: Verify build and all tests pass**

Run: `go build ./... && go test ./internal/netmonitor/unix/ -v -tags "linux,cgo" -count=1`
Expected: Build succeeds, all tests pass (including the new one from step 1).

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/handler.go internal/netmonitor/unix/file_handler_test.go
git commit -m "fix(seccomp): add read-only guard in emulation path

Defense-in-depth: if a read-only open reaches handleFileNotificationEmulated
(e.g., via openat2 fallback), respond with CONTINUE instead of emulating
via AddFD. Read-only opens have no TOCTOU risk and should never be emulated."
```

---

### Task 4: Cross-compile verification and full test run

**Files:** None (verification only)

- [ ] **Step 1: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: Build succeeds (`file_syscalls.go` has `//go:build linux && cgo` tag, so `openatWriteMask` is only compiled on Linux).

- [ ] **Step 2: Run full test suite**

Run: `go test ./... -tags "linux,cgo" -count=1`
Expected: All tests pass.

- [ ] **Step 3: Run just the changed package tests with race detector**

Run: `go test ./internal/netmonitor/unix/ -race -v -tags "linux,cgo" -count=1`
Expected: All tests pass, no race conditions.

- [ ] **Step 4: Runloop integration test (external, manual)**

The end-to-end validation is at `/home/eran/work/canyonroad/agentsh-runloop`. After building and deploying the updated agentsh binary, run:

```yaml
# config.yaml
sandbox:
  unix_sockets:
    enabled: true
  seccomp:
    enabled: true
    file_monitor:
      enabled: true
  ptrace:
    enabled: false
```

Run: `source .env && python3 example.py`
Expected: 73/73 tests pass, no EBADF on bash startup.
