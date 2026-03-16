# Design: Lazy BPF Escalation for Ptrace Read/Write Elimination

**Date:** 2026-03-15
**Status:** Approved

---

## 1. Problem

After the fd-aware exit stop optimization, ptrace network overhead is ~32x vs baseline. The remaining overhead is dominated by **entry stops** — the BPF filter traps `read`, `pread64`, and `write` into ptrace even though most processes never need them:

- `read`/`pread64` are only needed for TracerPid masking when the fd is `/proc/*/status`
- `write` is only needed for TLS SNI rewrite when the fd has a TLS watch

In the network benchmark (10 `curl` HTTPS requests), `curl` never opens `/proc/*/status`, so all ~200 read entry stops per invocation are pure waste. Write entry stops are only useful for ~1-2 ClientHello writes per TLS handshake, but all ~200 write entry stops are trapped.

## 2. Solution

**Two-tier BPF filter architecture with lazy per-TGID escalation.**

Install a **narrow** BPF at attach time that excludes `read`, `pread64`, and `write` from the traced set. When an event triggers the need for these syscalls, inject a second **escalation** BPF filter that adds them. Seccomp filter stacking ensures the combined result traces the union of both filters' syscall sets.

### Narrow filter (installed at attach)

Traces ~27 syscalls — the same set as today minus `read`, `pread64`, `write`:
- Exec: `execve`, `execveat`
- File: `openat`, `openat2`, `unlinkat`, `mkdirat`, `renameat2`, `linkat`, `symlinkat`, `fchmodat`, `fchmodat2`, `fchownat` + amd64 legacy
- Network: `connect`, `socket`, `bind`, `sendto`, `listen`
- Signal: `kill`, `tgkill`, `tkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`
- Close: `close`

### Escalation triggers

1. **Read escalation**: `handleOpenatExit` detects `/proc/*/status` → inject filter adding `read` + `pread64` for that TGID
2. **Write escalation**: `handleConnectExit` detects TLS port (443/853) with a cached domain → inject filter adding `write` for that TGID

### Seccomp stacking behavior

Seccomp filters are stackable and one-directional — installing a new filter can only make things MORE restrictive (add syscalls to trace), never less. This works in our favor:

- Initial filter: `SECCOMP_RET_ALLOW` for read/write → no entry stops
- Escalation filter: `SECCOMP_RET_TRACE` for read/write → entry stops begin
- Combined: most restrictive wins → read/write are traced after escalation

Once escalated, read/write are traced for the lifetime of that thread. This is acceptable because:
- Most processes (curl, git, shell commands) never trigger escalation
- Processes that do need it (e.g., those reading `/proc/self/status`) need it permanently

## 3. Per-thread escalation

Seccomp filters are per-thread (`task_struct->seccomp`), not per-TGID. `fork()` copies the parent's filter stack to the child, but installing a filter on one thread does NOT affect sibling threads.

### Lazy per-thread propagation

When escalation triggers on thread A of a TGID:
1. Set TGID-level flags: `NeedsReadEscalation` / `NeedsWriteEscalation`
2. Inject the escalation filter into thread A immediately
3. Set thread A's `ThreadHasReadEscalation` / `ThreadHasWriteEscalation`

For other threads in the same TGID:
4. On their next syscall stop (in `handleSeccompStop` or `handleSyscallStop`), check if the TGID needs escalation but the thread hasn't been escalated yet
5. Inject the escalation filter into that thread before dispatching
6. Set the thread's escalation flags

This avoids `PTRACE_INTERRUPT`ing running threads and handles propagation naturally as threads enter syscall stops.

### Race window

Between escalation on thread A and propagation to thread B, thread B's reads/writes pass through untraced. For TracerPid masking, this means a multi-threaded process could have one thread open `/proc/self/status` and another thread read it before escalation propagates. This is a narrow race — the same class of limitation as the existing fd-inheritance-across-fork issue. Acceptable.

## 4. Fork/clone inheritance

When a child process is created (`PTRACE_EVENT_CLONE/FORK/VFORK`), it inherits the parent's seccomp filter stack via the kernel's `fork()`. In `handleNewChild`:

1. Copy escalation flags from parent to child `TraceeState`:
   ```
   childState.NeedsReadEscalation = parentState.NeedsReadEscalation
   childState.NeedsWriteEscalation = parentState.NeedsWriteEscalation
   childState.ThreadHasReadEscalation = parentState.ThreadHasReadEscalation
   childState.ThreadHasWriteEscalation = parentState.ThreadHasWriteEscalation
   ```
2. The child already has the correct BPF stack — no re-injection needed.

**Bonus optimization**: Skip `PendingPrefilter` for auto-traced children when the parent already has `HasPrefilter = true`. Currently every new tracee with a session ID gets `PendingPrefilter = true`, causing BPF re-injection on the first syscall stop. Since the child inherits the parent's kernel filter stack via `fork()`, this is redundant. Only set `PendingPrefilter` for directly-attached processes (via `AttachPID`) or when the parent's `HasPrefilter` is false (filter not yet injected).

## 5. Changes

### `seccomp_filter.go`

Split `buildPrefilterBPF()` into two functions:

- `buildNarrowPrefilterBPF()` — same as `buildPrefilterBPF()` but calls `narrowTracedSyscallNumbers()` which excludes `SYS_READ`, `SYS_PREAD64`, `SYS_WRITE`
- `buildEscalationBPF(syscalls []int)` — builds a minimal BPF that returns `SECCOMP_RET_TRACE` for the specified syscalls and `SECCOMP_RET_ALLOW` for everything else

### `inject_seccomp.go`

Add `injectEscalationFilter(tid int, syscalls []int) error`:
- Builds escalation BPF via `buildEscalationBPF`
- Skips `prctl(PR_SET_NO_NEW_PRIVS)` — already set by initial filter injection
- Injects `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)` only
- Uses existing scratch page and `injectSyscall` machinery

### `tracer.go`

**TraceeState additions**:
```go
// TGID-level escalation flags (set when any thread in the TGID triggers escalation)
NeedsReadEscalation  bool
NeedsWriteEscalation bool
// Per-thread escalation flags (set after the filter is installed on this thread)
ThreadHasReadEscalation  bool
ThreadHasWriteEscalation bool
// Deferred escalation (set at entry, injected at next exit stop)
PendingReadEscalation  bool
PendingWriteEscalation bool
```

**`handleSeccompStop` / `handleSyscallStop` — lazy escalation check**:

Escalation injection consumes a syscall (via `injectSyscall`). To avoid silently dropping the tracee's current syscall, lazy escalation must NOT inject during entry. Instead, use the same deferred-injection pattern as `PendingPrefilter`:

- At entry: if TGID needs escalation and thread isn't escalated, set `PendingReadEscalation` / `PendingWriteEscalation` flag on the thread
- At exit (or on the next idle stop): inject the escalation filter and clear the pending flag

In `handleSyscallStop`, add a check in the exit path (alongside the existing `PendingPrefilter` exit injection):
```go
if !entering && state.PendingReadEscalation {
    state.PendingReadEscalation = false
    if err := t.injectEscalationFilter(tid, readEscalationSyscalls); err != nil {
        slog.Warn("deferred read escalation failed", "tid", tid, "error", err)
    } else {
        state.ThreadHasReadEscalation = true
    }
}
// Same for PendingWriteEscalation
```

In `handleSeccompStop`, do NOT inject — set the pending flag instead, so the next `handleSyscallStop` exit handles it.

**`handleOpenatExit` — read escalation trigger**:

After `trackStatusFd(tgid, fd)`:
```go
// Escalate all threads in this TGID to trace read/pread64
t.escalateReadForTGID(tgid, tid)
```

`escalateReadForTGID` sets `NeedsReadEscalation` on all TraceeStates with matching TGID, and injects the filter into the triggering thread (which is already stopped).

**`handleConnectExit` — write escalation trigger**:

After `watchTLS(tgid, fd, domain)`:
```go
// Escalate all threads in this TGID to trace write
t.escalateWriteForTGID(tgid, tid)
```

**`handleNewChild` — inherit escalation**:

Copy parent's escalation flags to child. Do NOT set `PendingPrefilter` for auto-traced children — they inherit the parent's filter stack.

**`injectSeccompFilter` — use narrow filter**:

Change `buildPrefilterBPF()` call to `buildNarrowPrefilterBPF()`.

### Files unchanged

| File | Why |
|------|-----|
| `handle_read.go` | `handleReadEntry` still works as-is — only called when reads are in the BPF |
| `handle_write.go` | `handleWrite` still works — only called when writes are in the BPF |
| `handle_network.go` | Connect exit skip still works |
| `fd_tracker.go` | No changes |
| `metrics.go` | `IncExitStopSkipped` still works |

## 6. Scope

| File | Change |
|------|--------|
| `internal/ptrace/seccomp_filter.go` | Add `buildNarrowPrefilterBPF`, `buildEscalationBPF`, `narrowTracedSyscallNumbers` |
| `internal/ptrace/inject_seccomp.go` | Add `injectEscalationFilter` |
| `internal/ptrace/tracer.go` | TraceeState fields, lazy escalation in stop handlers, escalation triggers in exit handlers, fork inheritance, narrow filter in initial injection |

## 7. Edge Cases

### Escalation injection fails

`injectEscalationFilter` may fail (ESRCH if process exited, scratch page issues, etc.). Fall back gracefully: log a warning, don't set the escalation flag. TracerPid masking or SNI rewrite won't work for that process. The existing `handleReadExit`/`handleWrite` safety nets are still in place for escalated threads.

### Multiple status fd opens

A process may open `/proc/self/status` multiple times. The first open triggers escalation; subsequent opens find `NeedsReadEscalation` already true and skip re-injection.

### Process exits during escalation

`injectSyscall` already handles ESRCH. The thread is cleaned up normally.

### Escalation at non-exit stop

The lazy propagation uses deferred injection: set a pending flag at entry, inject at the next exit stop. This matches the existing `PendingPrefilter` pattern and avoids consuming the tracee's current syscall.

For the triggering thread (in `handleOpenatExit` or `handleConnectExit`), injection happens at an exit stop where `injectFromExit` is safe.

### Clone during escalation propagation

When `escalateReadForTGID` iterates tracees to set `NeedsReadEscalation`, a thread in the same TGID could `clone()` concurrently. If `handleNewChild` runs for the new child before the cloning thread's TraceeState gets the flag, the child inherits stale state. Same class of race as the multi-thread read race in Section 3. Mitigated by the single-threaded event loop — `escalateReadForTGID` runs under `t.mu`, and `handleNewChild` also takes `t.mu`, so they cannot interleave.

## 8. Testing

- **`TestIntegration_NarrowBPFNoReadStops`**: Trace a process that does many reads but never opens `/proc/*/status`. Assert that `handleReadEntry` is never called (via a new metric `IncReadEntryHandled` or by checking exit-stops-skipped is zero — if reads aren't in the BPF, there are no entry stops to skip).
- **`TestIntegration_ReadEscalationOnStatusOpen`**: Trace a process that opens `/proc/self/status` then reads it. Assert TracerPid is masked.
- **`TestIntegration_WriteEscalationOnTLSConnect`**: Trace a process that connects to port 443. Assert `NeedsWriteEscalation` is set on the TGID.
- **`TestIntegration_ChildInheritsEscalation`**: Parent opens `/proc/self/status`, then forks. Assert child has `NeedsReadEscalation` and `ThreadHasReadEscalation`, and TracerPid masking works in the child.
- **`TestIntegration_SkipReinjectionForChildren`**: Verify auto-traced children don't get `PendingPrefilter` and don't trigger BPF re-injection.
- **Existing tests**: All must pass unchanged.
- **Benchmark**: Re-run `make bench`. Target: network ~32x → ~15-20x.

## 9. Performance Model

For `curl` HTTPS (10 requests, ~200 reads + ~200 writes per request):

**Before** (current, with fd-aware exit stops):
- 200 read entry stops (BPF traps) + 0 read exit stops (fd-aware skip) = 200 read context switches
- 200 write entry stops + 0 write exit stops = 200 write context switches
- Total read+write overhead: ~400 context switches per curl

**After** (narrow BPF + lazy escalation):
- 0 read entry stops (read not in BPF, curl never opens /proc/*/status)
- ~20 write entry stops (write escalated after first TLS connect, only for remaining writes)
- Total read+write overhead: ~20 context switches per curl

**Reduction**: ~380 fewer context switches per curl invocation. For 10 curls, ~3800 fewer total. This should cut network overhead roughly in half (from ~32x to ~15-18x).
