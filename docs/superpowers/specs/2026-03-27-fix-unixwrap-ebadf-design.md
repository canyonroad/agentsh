# Fix agentsh-unixwrap EBADF — Design Spec

**Date:** 2026-03-27
**Status:** Draft
**Problem:** When `unix_sockets.enabled: true`, agentsh-unixwrap causes EBADF (Error 9) on bash.real loading shared libraries via the dynamic linker. The shell can't start at all.

## Root Cause

When `file_monitor.enabled: true`, the BPF filter traps ALL openat calls via `ActNotify` — including read-only opens by the dynamic linker (e.g., `openat("/lib/.../libtinfo.so.6", O_RDONLY|O_CLOEXEC)`). These read-only opens are routed to `handleFileNotificationEmulated`, which emulates them via `/proc/<pid>/root/<path>` + `SECCOMP_IOCTL_NOTIF_ADDFD`. The emulation path produces invalid fds for the tracee, causing EBADF when the dynamic linker tries to mmap the library.

The doc notes the bug "persists with `file_monitor.enabled: false`" — with file_monitor off, openat is NOT in the BPF filter (`seccomp_linux.go:232`), so this is likely a separate issue or stale observation. This spec fixes the primary (file_monitor=true) case.

## Approach: A+B Combined

**A — BPF-level flag filtering:** Only trap write-flagged openat in the BPF filter. Read-only opens stay `ActAllow` (kernel handles directly, zero overhead). This mirrors the proven ptrace prefilter approach (`openatWriteMask = 0x400643`).

**B — Handler defense-in-depth:** In `handleFileNotificationEmulated`, if a read-only open somehow reaches the handler, respond with `NotifRespondContinue` instead of emulating. This is a safety net — with fix A, read-only opens should never reach the handler.

## Detailed Design

### 1. Shared Write Mask Constant

**File:** `internal/netmonitor/unix/file_syscalls.go`

Define the write-flag mask alongside the existing `emulableFlagMask`:

```go
// openatWriteMask defines flags that indicate a write/create operation.
// Matches the ptrace prefilter mask (0x400643) for consistency.
// O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND | __O_TMPFILE
const openatWriteMask = 0x400643
```

Add a helper used by the handler guard:

```go
// isReadOnlyOpen returns true if the flags indicate a read-only open
// (no write, create, truncate, append, or tmpfile flags set).
func isReadOnlyOpen(flags uint32) bool {
    return flags & openatWriteMask == 0
}
```

### 2. BPF Filter Flag-Based Rules

**File:** `internal/netmonitor/unix/seccomp_linux.go`, `InstallFilterWithConfig()`

Replace the unconditional openat `ActNotify` rule with per-flag conditional rules.

**Key semantics:** Multiple `AddRuleConditional` calls on the same syscall create OR logic in libseccomp — if ANY condition matches, the action fires. This is exactly what we want: trap if any write flag is set. Architecture-specific syscall numbers are handled by `seccomp.ScmpSyscall(unix.SYS_*)` which abstracts the platform.

```go
if cfg.FileMonitorEnabled {
    trap := seccomp.ActNotify

    // openat: only trap write-flagged opens.
    // Each rule checks one flag bit via MaskedEq: (flags & bit) == bit.
    // Multiple rules on the same syscall act as OR in libseccomp —
    // if ANY write flag is set, the open is trapped.
    // Read-only opens (no write flags) match no rule → ActAllow.
    //
    // We use 0x400000 (__O_TMPFILE) rather than unix.O_TMPFILE (0x410000)
    // because the latter includes O_DIRECTORY. We only need the tmpfile bit.
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

    // openat2: unconditional ActNotify (flags are in a struct pointer,
    // can't inspect in BPF). Handler already falls back to CONTINUE
    // via shouldFallbackToContinue.
    if err := filt.AddRule(seccomp.ScmpSyscall(unix.SYS_OPENAT2), trap); err != nil {
        return nil, fmt.Errorf("add openat2 rule: %w", err)
    }

    // Non-open file syscalls: unconditional ActNotify (always writes).
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

    // Legacy open syscalls: unconditional ActNotify (rare on modern systems,
    // handler CONTINUE path handles them safely).
    for _, sc := range legacyFileSyscallList() {
        if err := filt.AddRule(seccomp.ScmpSyscall(sc), trap); err != nil {
            return nil, fmt.Errorf("add legacy file rule %v: %w", sc, err)
        }
    }
}
```

### 3. Handler Read-Only Guard

**File:** `internal/netmonitor/unix/handler.go`, `handleFileNotificationEmulated()`

Add a read-only guard after the `ActionDeny` branch but before the `NotifIDValid` check (between current lines 604 and 609). This avoids redundant ID validation for read-only opens:

```go
// Branch: is this an open syscall that we should emulate via AddFD?
if !forceContinue {
    if result.Action == ActionDeny {
        // ... existing deny logic ...
        return
    }

    // Defense-in-depth: never emulate read-only opens.
    // With BPF flag filtering, reads should not reach here.
    // But if they do (future filter changes, openat2 fallback),
    // CONTINUE is always safe for reads.
    if isReadOnlyOpen(fileArgs.Flags) {
        if err := NotifRespondContinue(int(fd), req.ID); err != nil {
            slog.Debug("emulated file handler: read-only continue failed", "pid", pid, "error", err)
        }
        return
    }

    // Existing emulation path for writes/creates...
    if err := NotifIDValid(notifFD, req.ID); err != nil { ... }
    emulateOpenat(fd, req, pid, path, fileArgs.Flags, fileArgs.Mode)
    return
}
```

### 4. Testing

**4a. `isReadOnlyOpen` unit test** — `file_syscalls_test.go`

Table-driven test:
| Flags | Expected |
|-------|----------|
| `O_RDONLY` | true |
| `O_RDONLY \| O_CLOEXEC` | true |
| `O_RDONLY \| O_NOFOLLOW` | true |
| `O_WRONLY` | false |
| `O_RDWR` | false |
| `O_RDONLY \| O_CREAT` | false |
| `O_RDONLY \| O_TRUNC` | false |
| `O_RDONLY \| O_APPEND` | false |
| `O_TMPFILE` | false |

**4b. Handler emulation guard test** — `file_integration_test.go`

Test that `handleFileNotificationEmulated` with a read-only openat request responds with CONTINUE, not AddFD emulation.

**4c. Integration test on Runloop**

Config: `unix_sockets.enabled: true`, `seccomp.enabled: true`, `file_monitor.enabled: true`, `ptrace.enabled: false`. Target: 73/73 tests, no EBADF on bash startup.

### 5. Files Changed

| File | Change |
|------|--------|
| `internal/netmonitor/unix/file_syscalls.go` | Add `openatWriteMask` constant, `isReadOnlyOpen()` helper |
| `internal/netmonitor/unix/seccomp_linux.go` | Replace unconditional openat `ActNotify` with per-flag conditional rules |
| `internal/netmonitor/unix/handler.go` | Add read-only guard in `handleFileNotificationEmulated` |
| `internal/netmonitor/unix/file_syscalls_test.go` | Add `isReadOnlyOpen` table-driven test |
| `internal/netmonitor/unix/file_integration_test.go` | Add emulation guard test |

### 6. What This Does NOT Change

- Non-open file syscalls (unlinkat, mkdirat, etc.) — always trapped, always writes
- openat2 — always trapped (can't inspect flags in BPF), handler already uses CONTINUE fallback
- Legacy open syscalls — always trapped, handler CONTINUE path is safe
- `handleFileNotification` (non-emulated path) — already uses CONTINUE for allowed opens
- Metadata syscalls (statx, etc.) — already uses CONTINUE, no emulation
- Unix socket handling — unrelated, unchanged
