# Design: Fd-Aware Conditional Exit Stops for Ptrace Network Performance

**Date:** 2026-03-15
**Status:** Approved

---

## 1. Problem

Network-heavy workloads under ptrace show ~37x overhead vs baseline. The root cause: every `read`/`pread64` syscall generates an exit stop (`NeedExitStop = true` unconditionally), but `handleReadExit` checks `isStatusFd(tgid, fd)` and returns early ~99.9% of the time. Each wasted exit stop costs a full kernel→tracer→kernel context switch.

A single `curl` HTTPS request generates hundreds of `read` syscalls on socket fds. None of them are `/proc/self/status`. Every one of them currently gets an exit stop that does nothing.

The per-syscall resume optimization (commit 45c334f) correctly identified which syscall *numbers* need exit processing, but doesn't consider which *fd values* actually require it. This is the next level of granularity.

## 2. Solution

At syscall entry — where registers are already available — check the fd against the fd tracker. Only keep `NeedExitStop = true` when the exit handler will actually do work.

### Read/pread64

Replace the current entry-time pass-through:
```go
case isReadSyscall(nr):
    t.allowSyscall(tid)  // read is handled on exit, not entry
```

With a new `handleReadEntry` that checks the fd:
```go
case isReadSyscall(nr):
    t.handleReadEntry(tid, regs)
```

`handleReadEntry` reads `fd` from `regs.Arg(0)`, looks up `isStatusFd(tgid, fd)`, and clears `NeedExitStop` if the fd is not tracked. The exit handler (`handleReadExit`) remains unchanged as a safety net.

### Connect

After `handleNetwork` processes a `connect` and decides to allow it, check the parsed sockaddr. If the destination port is not 443 (HTTPS) or 853 (DNS-over-TLS), clear `NeedExitStop`. The sockaddr is already parsed by `handleNetwork` — no extra memory read needed.

### Connect — DNS redirect path

When `handleNetwork` detects a port-53 connect and the DNS proxy is active, it redirects the sockaddr and returns early via `allowSyscall` (handle_network.go:192). These connects have `NeedExitStop = true` from `needsExitStop(SYS_CONNECT)`, but `handleConnectExit` would return early (port 53 is not 443/853). Clear `NeedExitStop` before `allowSyscall` on this path too.

### Write/sendto (no change)

`write` is dispatched to `handleWrite` (handle_write.go), an entry-only handler. `sendto` is routed via `isNetworkSyscall` to `handleNetwork` (handle_network.go), also entry-only. Neither appears in `needsExitStop()` and both already resume with `PtraceCont` when the prefilter is active. No change needed. (Note: these take different code paths despite both being entry-only.)

## 3. Changes

### `handleReadEntry` (new function, ~15 lines)

```go
func (t *Tracer) handleReadEntry(tid int, regs Regs) {
    if t.fds != nil && t.cfg.MaskTracerPid {
        fd := int(int32(regs.Arg(0)))
        t.mu.Lock()
        state := t.tracees[tid]
        var tgid int
        if state != nil {
            tgid = state.TGID
        }
        t.mu.Unlock()

        if !t.fds.isStatusFd(tgid, fd) {
            t.mu.Lock()
            if s := t.tracees[tid]; s != nil {
                s.NeedExitStop = false
            }
            t.mu.Unlock()
        }
    } else {
        // MaskTracerPid disabled — read exit stops never needed.
        t.mu.Lock()
        if s := t.tracees[tid]; s != nil {
            s.NeedExitStop = false
        }
        t.mu.Unlock()
    }
    t.allowSyscall(tid)
}
```

### `dispatchSyscall` (1 line changed)

```go
// Before:
case isReadSyscall(nr):
    t.allowSyscall(tid)

// After:
case isReadSyscall(nr):
    t.handleReadEntry(tid, regs)
```

### `handleNetwork` — connect exit skip (~10 lines)

Two insertion points in `handleNetwork` (handle_network.go):

**Point 1: DNS redirect path (line ~192).** Before the early-return `allowSyscall` for port-53 redirects:
```go
// Before allowSyscall on DNS redirect path:
t.mu.Lock()
if s := t.tracees[tid]; s != nil {
    s.NeedExitStop = false
}
t.mu.Unlock()
t.allowSyscall(tid)
return
```

**Point 2: Policy allow path (line ~234).** Inside `case "allow", "continue":` before `allowSyscall`:
```go
case "allow", "continue":
    if nr == unix.SYS_CONNECT && port != 443 && port != 853 {
        t.mu.Lock()
        if s := t.tracees[tid]; s != nil {
            s.NeedExitStop = false
        }
        t.mu.Unlock()
    }
    t.allowSyscall(tid)
```

**Redirect path (`case "redirect":`)**: `redirectConnect` (redirect_net.go) rewrites the sockaddr in tracee memory and calls `allowSyscall`. The exit stop is needed because the redirect target port may be 443/853, which would trigger `handleConnectExit` to set up TLS fd watching for SNI rewrite. Since the redirect target isn't known at compile time (it comes from the policy handler's `RedirectPort`), we conservatively keep `NeedExitStop = true`. No change needed.

### Unchanged

| Component | Why unchanged |
|-----------|---------------|
| `needsExitStop()` | Still returns true for read/connect — the default before entry-time override |
| `handleReadExit` | Safety net. Still runs on exit when `NeedExitStop` is true |
| `handleConnectExit` | Still runs on exit when `NeedExitStop` is true |
| `handleSyscallStop` / `handleSeccompStop` | Set `NeedExitStop` from `needsExitStop(nr)` as before; entry handlers may override |
| `allowSyscall` / `resumeTracee` | Check `mustCatchExit(s)` as before — the override flows through naturally |
| BPF filter | Same syscall set. Reads still generate entry stops; we just skip most exit stops |
| `denySyscall` / `redirectExec` | Bypass `allowSyscall`, always use `PtraceSyscall` directly |

## 4. Scope

Three files changed. ~30 lines added/changed. No new files.

| File | Location | Change |
|------|----------|--------|
| `internal/ptrace/tracer.go` | `dispatchSyscall` | Route `isReadSyscall` to `handleReadEntry` (1 line) |
| `internal/ptrace/handle_read.go` | new function | `handleReadEntry`: fd-aware `NeedExitStop` override (~15 lines) |
| `internal/ptrace/handle_network.go` | `handleNetwork` | Clear `NeedExitStop` for non-TLS connect at two points (~10 lines) |

## 5. Edge Cases

### Fd reuse after close+open

A process could `close(fd)` then `open("/proc/self/status")` reusing the same fd number. Both `close` (entry handler: `closeFd`) and `openat` (exit handler: `trackStatusFd`) are processed synchronously in the event loop before any subsequent `read` on that fd. Safe.

### Fd inheritance across fork

The fd tracker is keyed by TGID. A forked child has a new TGID, so inherited status fds are not tracked for the child. This is a pre-existing limitation — the child must re-open `/proc/self/status` to get tracked. No regression.

### MaskTracerPid disabled

When `MaskTracerPid` is false, `handleReadEntry` clears `NeedExitStop` for all reads unconditionally. This is a bonus optimization — currently reads generate exit stops even when masking is disabled.

### NeedExitStop override order

`handleSeccompStop` and `handleSyscallStop` set `NeedExitStop = needsExitStop(nr)` before dispatching to `handleReadEntry`. The entry handler then overrides to false when appropriate. This is correct — the override is the more specific check.

On the exit side, `handleSyscallStop` (line 835) unconditionally clears `NeedExitStop = false` after running exit handlers. This is correct — if we reached exit processing, the handler already ran and the flag should be reset for the next syscall.

### Locking safety in handleReadEntry

`handleReadEntry` takes `t.mu` to read `tgid`, releases it, calls `isStatusFd` (which takes `ft.mu`), then re-takes `t.mu` to clear `NeedExitStop`. This lock-unlock-lock pattern is safe because the ptrace event loop is single-threaded (`runtime.LockOSThread()`). Between releasing and re-acquiring `t.mu`, no other ptrace stop for the same `tid` can be processed. The `tgid` and `NeedExitStop` values are stable until this handler returns.

### DNS-redirected connects (port 53)

When `handleNetwork` redirects a port-53 connect to the DNS proxy, it returns early via `allowSyscall` without clearing `NeedExitStop`. `handleConnectExit` would then run and return early (port 53 is not 443/853). This wastes an exit stop. The fix adds `NeedExitStop = false` before the early return on the DNS redirect path.

### False negatives

If a status fd is somehow not tracked (fd tracker bug), the entry check would clear `NeedExitStop`, skipping the exit handler. The masking would be missed for that read. This matches the existing behavior — `handleReadExit` already returns early for untracked fds, so the masking would also be missed without this change.

## 6. Testing

- **Existing tests**: All 76+ integration tests pass unchanged. No behavioral change for correctly-traced scenarios.
- **New test — read exit skip**: `TestIntegration_ReadExitSkipForNonStatusFd` — trace a process that does many reads on a socket fd. Assert deterministically via a new `Metrics.ExitStopsSkipped` counter (incremented in `handleReadEntry` when `NeedExitStop` is cleared) that exit stops were skipped. Do not rely on timing.
- **New test — connect exit skip (non-TLS)**: `TestIntegration_ConnectExitSkipNonTLS` — trace a process that connects to a non-TLS port (e.g., port 80). Assert via the same counter mechanism that the connect exit stop was skipped.
- **New test — connect exit retained (TLS)**: `TestIntegration_ConnectExitRetainedTLS` — trace a process that connects to port 443. Assert that the exit stop was NOT skipped and `handleConnectExit` ran (verify via TLS fd watch state).
- **New test — connect exit skip (DNS redirect)**: `TestIntegration_ConnectExitSkipDNSRedirect` — trace a process that connects to port 53 with DNS proxy active. Assert that the exit stop was skipped.
- **Regression test**: `TestIntegration_TracerPidMasked` (existing) — confirm TracerPid is still masked when reading `/proc/self/status`. The entry check should set `NeedExitStop = true` for status fds.
- **Benchmark**: Re-run `make bench` network phase. Target: ~37x overhead reduced to ~15-20x.

## 7. Performance Model

For a `curl` HTTPS request generating ~200 read syscalls:

**Before** (current): 200 entry stops + 200 exit stops = 400 context switch pairs
**After**: 200 entry stops + 0 exit stops = ~200 context switch pairs

(`curl` does not read `/proc/self/status`, so zero status-fd reads → zero read exit stops. The remaining exit stops come from `openat` (fd tracking, ~10-20 library opens) and `connect` to port 443 (~1-2 TLS connects). These are already needed and unchanged.)

That's a ~2x reduction in read-related ptrace overhead. Since reads dominate the network workload's syscall count, this should translate to a meaningful reduction in the 37x total network overhead.

The connect optimization saves exit stops for DNS-redirected connects (port 53) and non-TLS connects — small but free.
