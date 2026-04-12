# Yama-Aware PR_SET_PTRACER with ProcessVMReadv Self-Test

**Issue**: #218 — `file_monitor: PR_SET_PTRACER EINVAL treated as fatal on kernels without Yama LSM`
**Date**: 2026-04-12

## Problem

On kernels where Yama LSM is not loaded (e.g., Firecracker/Hopx microVMs with kernel 5.10), `prctl(PR_SET_PTRACER, ...)` returns `EINVAL` because the kernel doesn't recognize the Yama-specific option `0x59616d61`. The current wrapper logs a warning and continues, but downstream effects cause seccomp-notify handlers to fail when they can't read tracee memory — resulting in `permission denied` for all intercepted execs when `file_monitor.enabled: true`.

The root cause: `PR_SET_PTRACER` is only meaningful when Yama is loaded. Without Yama, standard Unix DAC governs ptrace and `ProcessVMReadv` works without any grant. The warning is misleading and the potential for downstream failures is unnecessary.

## Approach

Two changes:

1. **Yama-aware `PR_SET_PTRACER` in the wrapper** — skip the prctl entirely when Yama is not loaded.
2. **Server-side `ProcessVMReadv` self-test** — during the notify handler handshake, probe that the server can actually read from the wrapper's address space before processing any notifications.

## Design

### 1. Yama Detection

**File**: `cmd/agentsh-unixwrap/yama_linux.go` (new)

```go
const yamaPtraceScope = "/proc/sys/kernel/yama/ptrace_scope"

// isYamaActive returns true if the Yama LSM is loaded and active.
// When Yama is not loaded, PR_SET_PTRACER is meaningless (returns EINVAL)
// and ProcessVMReadv permissions fall back to standard Unix DAC.
func isYamaActive() bool {
    _, err := os.Stat(yamaPtraceScope)
    return err == nil
}
```

For testability, the sysctl path is a package-level variable that tests can override:

```go
var yamaPtraceScopePath = "/proc/sys/kernel/yama/ptrace_scope"

func isYamaActive() bool {
    _, err := os.Stat(yamaPtraceScopePath)
    return err == nil
}
```

### 2. Wrapper Changes

**File**: `cmd/agentsh-unixwrap/main.go` (lines 45-54)

Replace the unconditional `PR_SET_PTRACER` call with Yama-aware logic:

```go
if cfg.ServerPID > 0 {
    if isYamaActive() {
        if err := unix.Prctl(unix.PR_SET_PTRACER, uintptr(cfg.ServerPID), 0, 0, 0); err != nil {
            log.Printf("PR_SET_PTRACER(%d): %v (Yama active, ProcessVMReadv may fail)",
                cfg.ServerPID, err)
        }
    } else {
        log.Printf("yama: not active, skipping PR_SET_PTRACER (standard DAC governs ptrace)")
    }
}
```

**No change to the C ptracer library** (`cmd/agentsh-unixwrap/ptracer/ptracer.c`). It already ignores the prctl return value. The overhead of a failed prctl per child is negligible vs fork/exec cost.

### 3. ProcessVMReadv Self-Test

**File**: `internal/api/pvr_probe_linux.go` (new)

Three functions:

- `probeProcessVMReadv(pid int) error` — reads 8 bytes from a readable mapping in `/proc/<pid>/maps` via `ProcessVMReadv`. Returns nil on success.
- `probeProcMem(pid int) error` — reads 8 bytes from the same address via `/proc/<pid>/mem` (the fallback mechanism). Returns nil on success.
- `findReadableAddr(pid int) (uint64, error)` — parses `/proc/<pid>/maps` to find the start address of the first readable mapping (`r--` or `r-x` permissions). Scans at most 20 lines; returns error if no readable mapping found.

The caller resolves the address once via `findReadableAddr` and passes it to both probe functions to avoid parsing `/proc/maps` twice:

```go
func probeMemoryAccess(pid int) (pvrErr, memErr error) {
    addr, err := findReadableAddr(pid)
    if err != nil {
        return err, err
    }
    pvrErr = probeProcessVMReadvAt(pid, addr)
    if pvrErr != nil {
        memErr = probeProcMemAt(pid, addr)
    }
    return pvrErr, memErr
}
```

### 4. Self-Test Integration (Exec Path)

**File**: `internal/api/notify_linux.go`, in `startNotifyHandler()`

Insertion point: after notify fd is received (line 236) and before ACK is sent (line 300). The wrapper PID is already available from `SO_PEERCRED` (line 206).

```go
if wrapperPID > 0 {
    pvrErr, memErr := probeMemoryAccess(wrapperPID)

    if pvrErr != nil && memErr != nil {
        fileMonEnabled := config.FileMonitorBoolWithDefault(fileMonitorCfg.Enabled, false)
        if fileMonEnabled || execveHandler != nil {
            slog.Error("seccomp notify: ProcessVMReadv and /proc/mem both failed — "+
                "handler cannot read tracee memory for path resolution",
                "wrapper_pid", wrapperPID,
                "pvr_error", pvrErr, "mem_error", memErr,
                "session_id", sessID)
            return // Don't send ACK — wrapper fails with clear handshake error
        }
        slog.Warn("ProcessVMReadv probe failed, socket monitoring may be degraded",
            "wrapper_pid", wrapperPID, "pvr_error", pvrErr, "mem_error", memErr)
    } else if pvrErr != nil {
        slog.Debug("ProcessVMReadv failed, /proc/mem fallback works",
            "wrapper_pid", wrapperPID, "pvr_error", pvrErr)
    }
}
```

### 5. Self-Test Integration (Wrap Path)

**File**: `internal/api/wrap_linux.go`, in `startNotifyHandlerForWrap()`

Insertion point: before starting the handler goroutine (line 115). The `wrapperPID` is already a function parameter.

Same probe logic as the exec path. On fatal failure (both mechanisms broken + file_monitor/execve enabled), log the error and return without starting the handler.

### 6. Failure Behavior

| ProcessVMReadv | /proc/mem | file_monitor/execve | Action |
|---|---|---|---|
| OK | (not tested) | any | Continue normally |
| Fail | OK | any | Continue (debug log — degraded performance) |
| Fail | Fail | enabled | **Fatal** — don't send ACK, log clear error with diagnostics |
| Fail | Fail | disabled | Warn, continue (only socket monitoring is active) |

The fatal case produces an error like:
```
seccomp notify: ProcessVMReadv and /proc/mem both failed — handler cannot read tracee memory for path resolution
    wrapper_pid=1234, pvr_error=EPERM, mem_error=EACCES
Fix: check kernel.yama.ptrace_scope sysctl, ensure CAP_SYS_PTRACE capability,
or set 'sandbox.seccomp.file_monitor.enabled: false' in your config.
```

## Files Changed

| File | Change |
|---|---|
| `cmd/agentsh-unixwrap/yama_linux.go` | New — `isYamaActive()` Yama LSM detection |
| `cmd/agentsh-unixwrap/main.go` | Yama-aware PR_SET_PTRACER logic (lines 45-54) |
| `internal/api/pvr_probe_linux.go` | New — `probeProcessVMReadv()`, `probeProcMem()`, `findReadableAddr()` |
| `internal/api/pvr_probe_linux_test.go` | New — unit tests for probe functions |
| `internal/api/notify_linux.go` | Self-test insertion in `startNotifyHandler()` |
| `internal/api/wrap_linux.go` | Self-test insertion in `startNotifyHandlerForWrap()` |
| `cmd/agentsh-unixwrap/yama_linux_test.go` | New — unit tests for `isYamaActive()` |

## Testing

### Unit Tests

- **`TestIsYamaActive_WhenPresent`** / **`TestIsYamaActive_WhenAbsent`**: Use a package-level path variable overridden in tests to simulate Yama presence/absence.
- **`TestProbeProcessVMReadv_Self`**: Probe against `os.Getpid()` — succeeds on any Linux kernel.
- **`TestProbeProcMem_Self`**: Probe `/proc/self/mem` — succeeds on any Linux kernel.
- **`TestFindReadableAddr`**: Parses `/proc/self/maps` and returns a valid address.

### Integration Test

- **`TestProbeProcessVMReadv_CrossProcess`** (build-tagged `integration`): Fork a child, probe it from the parent. Validates the actual cross-process access pattern.

### Existing Coverage

- `ptracer_linux_test.go` — covers `setupPtracerPreload` (no changes to that code).
- `file_handler_test.go` — covers ProcessVMReadv-failure handler paths.

## Out of Scope

- **C ptracer library changes**: `libagentsh-ptracer.so` already ignores prctl errors. Making it Yama-aware would save a failed syscall per child but adds complexity for negligible benefit.
- **`agentsh detect` Yama tips**: The detect command's capability tips (#217) already cover Yama; this fix is orthogonal.
- **Handler-level fallback improvements**: The existing `/proc/mem` fallbacks in `readStringWithFallback` and `resolvePathAtWithFallback` are already correct. The self-test catches the case where both mechanisms are broken.
