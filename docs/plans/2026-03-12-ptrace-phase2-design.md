# ptrace Tracer Phase 2 — Full Syscall Coverage Design

> **Date:** 2026-03-12
> **Status:** Approved
> **Prerequisite:** Phase 1 (PR #121, merged)

## Goal

Add file, network, and signal syscall handling to the ptrace tracer, replacing the Phase 1 auto-allow stubs. Achieve allow/deny/audit parity with seccomp user-notify for these syscall categories. No steering/redirect (except signal redirect which is trivial via register rewrite).

## Architecture

Phase 2 follows Phase 1's pattern exactly:

1. **Syscall entry** — `dispatchSyscall` routes to `handleFile`, `handleNetwork`, or `handleSignal` based on existing `isFileSyscall`/`isNetworkSyscall`/`isSignalSyscall` classifiers
2. **Argument extraction** — Each handler reads arguments from tracee registers via `Regs` interface, then reads paths/addresses from tracee memory via `/proc/<tid>/mem`
3. **Path/address resolution** — File handler resolves relative paths against dirfd or cwd, then canonicalizes with `EvalSymlinks`. Network handler parses `sockaddr` structs. Signal handler extracts target PID and signal number.
4. **Policy evaluation** — Each handler calls its respective policy interface defined in the ptrace package. The integration layer maps these to existing policy engines (FilePolicyChecker, signal.Engine, etc.)
5. **Allow/deny/redirect** — Same mechanism as execve: `allowSyscall(tid)` or `denySyscall(tid, errno)`. Signal redirect rewrites the signal argument register before allowing.

No new goroutines or channels. Everything runs on the existing locked OS thread.

## Design Decisions

- **Thin ptrace-specific handlers, reuse policy engines** — Build handlers in the ptrace package that call policy interfaces, rather than reusing full handler structs from seccomp path (FileHandler, signal.Handler) which have FUSE/seccomp assumptions
- **Three separate handler interfaces** — `FileHandler`, `NetworkHandler`, `SignalHandler` in TracerConfig, matching the existing `ExecHandler` pattern. Nil = auto-allow.
- **Path canonicalization** — `filepath.EvalSymlinks` on all resolved paths before policy evaluation, preventing symlink-based bypasses
- **Network scope: connect/bind only** — No DNS inspection, no listen/socket interception
- **Signal redirect via register rewrite** — Overwrite signal argument in registers before allowing syscall

## Handler Interfaces

```go
// FileHandler evaluates file syscall policy.
type FileHandler interface {
    HandleFile(ctx context.Context, fc FileContext) FileResult
}

type FileContext struct {
    PID       int
    SessionID string
    Syscall   int      // SYS_OPENAT, SYS_UNLINKAT, etc.
    Path      string   // Resolved absolute path
    Path2     string   // Second path for rename/link
    Operation string   // "read", "write", "create", "delete", "chmod", etc.
    Flags     int      // O_RDONLY, O_WRONLY, etc.
}

type FileResult struct {
    Allow bool
    Errno int32
}

// NetworkHandler evaluates network syscall policy.
type NetworkHandler interface {
    HandleNetwork(ctx context.Context, nc NetworkContext) NetworkResult
}

type NetworkContext struct {
    PID       int
    SessionID string
    Syscall   int      // SYS_CONNECT, SYS_BIND
    Family    int      // AF_INET, AF_INET6, AF_UNIX
    Address   string   // IP or unix socket path
    Port      int
    Operation string   // "connect", "bind"
}

type NetworkResult struct {
    Allow bool
    Errno int32
}

// SignalHandler evaluates signal delivery policy.
type SignalHandler interface {
    HandleSignal(ctx context.Context, sc SignalContext) SignalResult
}

type SignalContext struct {
    PID       int      // Sender TGID
    SessionID string
    TargetPID int
    Signal    int
}

type SignalResult struct {
    Allow          bool
    Errno          int32
    RedirectSignal int  // 0 = no redirect
}
```

## File Syscall Handler

**Syscalls:** openat, unlinkat, mkdirat, renameat2, linkat, symlinkat, fchmodat, fchownat + amd64 legacy variants (open, unlink, rename, mkdir, rmdir, link, symlink, chmod, chown).

**Path resolution flow:**
1. Extract dirfd (arg0 for `*at` variants) and path pointer (arg1)
2. If `AT_FDCWD` (-100): read `/proc/<tid>/cwd`
3. Otherwise: `os.Readlink("/proc/<tid>/fd/<dirfd>")`
4. Read path string from tracee memory
5. Join base + relative path
6. `filepath.EvalSymlinks` for canonicalization
7. For two-path syscalls (rename, link, symlink): repeat for second path

**Operation mapping:** Static `syscallToOperation(nr, flags)` function:
- openat + O_RDONLY → "read"
- openat + O_WRONLY/O_RDWR → "write"
- openat + O_CREAT → "create"
- unlinkat → "delete"
- mkdirat → "create"
- renameat2 → "rename"
- fchmodat → "chmod"
- fchownat → "chown"
- linkat → "link"
- symlinkat → "symlink"

## Network Syscall Handler

**Syscalls handled for policy:** `connect` and `bind` only. All other network syscalls (socket, listen, sendto, etc.) routed through `handleNetwork` but auto-allowed.

**Sockaddr parsing:**
- Read raw bytes from tracee memory using `t.readBytes`
- Parse based on address family:
  - AF_INET: 4-byte IP + 2-byte port (big-endian)
  - AF_INET6: 16-byte IP + 2-byte port (big-endian)
  - AF_UNIX: path string from offset 2

**Excluded:** DNS inspection (sendto to port 53), listen/socket interception.

## Signal Syscall Handler

**Syscalls handled for policy:** `kill`, `tgkill`, `tkill`. Others (rt_sigaction, rt_sigprocmask) auto-allowed.

**Argument extraction by variant:**
- `kill(pid, sig)` — target from arg0, signal from arg1
- `tkill(tid, sig)` — target from arg0, signal from arg1
- `tgkill(tgid, tid, sig)` — target from arg0, signal from arg2

**Signal redirect:** Overwrite signal argument register via `regs.SetArg(n, redirectSignal)` + `t.setRegs(tid, regs)`, then `allowSyscall(tid)`. Kernel delivers the rewritten signal.

## TracerConfig Changes

```go
type TracerConfig struct {
    // ... existing fields unchanged ...
    FileHandler    FileHandler
    NetworkHandler NetworkHandler
    SignalHandler  SignalHandler
}
```

Each handler is nil-safe: if nil or if corresponding `TraceFile`/`TraceNetwork`/`TraceSignal` is false, the syscall is auto-allowed.

## Scope Exclusions

- DNS inspection via sendto — too complex for Phase 2
- listen/socket interception — rarely policy-relevant
- File/network/exec redirect/steering — Phase 4
- Sidecar auto-discovery — Phase 3
- Seccomp pre-filter injection for pid mode — Phase 3
- TracerPid masking — Phase 4

## File Listing

**New files (6):**

| File | Purpose |
|------|---------|
| `internal/ptrace/handle_file.go` | File syscall handler, path resolution, operation mapping |
| `internal/ptrace/handle_file_test.go` | Unit tests |
| `internal/ptrace/handle_network.go` | Network syscall handler, sockaddr parsing |
| `internal/ptrace/handle_network_test.go` | Unit tests |
| `internal/ptrace/handle_signal.go` | Signal syscall handler with redirect |
| `internal/ptrace/handle_signal_test.go` | Unit tests |

**Modified files (2):**

| File | Change |
|------|--------|
| `internal/ptrace/tracer.go` | Add handler interfaces, TracerConfig fields, update dispatchSyscall |
| `internal/ptrace/integration_test.go` | Add mock handlers, 5 new integration tests |

## Testing

**Unit tests:** operation mapping, dirfd resolution, sockaddr parsing, signal arg extraction. Use mock Regs, no ptrace capability needed.

**Integration tests (Docker, `//go:build integration && linux`):**
1. `TestIntegration_FileDeny` — deny openat, verify blocked
2. `TestIntegration_FileAllow` — allow, verify handler receives correct path/operation
3. `TestIntegration_NetworkDenyConnect` — deny connect to port, verify EACCES
4. `TestIntegration_SignalDeny` — deny kill, verify EPERM
5. `TestIntegration_SignalRedirect` — redirect SIGKILL→SIGTERM, verify delivery

Existing `Dockerfile.ptrace-test` and `make ptrace-test` run all tests unchanged.
