# Seccomp File I/O Monitor Design

**Status:** Proposed
**Created:** 2026-02-11
**Author:** Claude + Eran

## Overview

Extend the existing seccomp user-notify infrastructure to intercept path-based file syscalls (openat, unlinkat, mkdirat, etc.), enabling audit and policy enforcement for all file I/O under agentsh — independent of FUSE.

This provides defense-in-depth when FUSE is active (seccomp audits, FUSE enforces) and becomes the primary enforcement layer when FUSE is unavailable (containers without `/dev/fuse`, unprivileged environments).

## Goals

1. **Audit all path-based file operations** via seccomp user-notify, regardless of FUSE availability
2. **Enforce file policy** (allow/deny/redirect) when FUSE is not present
3. **Coexist with FUSE** — audit-only for paths under active FUSE mounts, enforce for everything else
4. **Reuse existing infrastructure** — policy engine, event pipeline, ServeNotify loop, no new subsystems

## Non-Goals

- Intercepting read/write on already-open file descriptors (too noisy, fd-based not path-based)
- Providing hard TOCTOU guarantees on path resolution (Landlock handles hard enforcement; seccomp is best-effort)
- Replacing FUSE — both coexist, FUSE remains primary enforcement where available

## Architecture

### Routing in the ServeNotify Loop

The existing `ServeNotifyWithExecve` routes notifications by syscall number. A new branch routes file syscalls to a `FileHandler`:

```
ServeNotify loop (agentsh parent, single notify fd)
  ├─ isUnixSocketSyscall(nr)  → unix socket handler   (existing)
  ├─ isExecveSyscall(nr)      → execve handler         (existing)
  └─ isFileSyscall(nr)        → file handler            (NEW)
       ├─ extract syscall args (dirfd, pathPtr, flags, mode)
       ├─ resolvePathAt(pid, dirfd, pathPtr) → absolute path
       ├─ check MountRegistry → audit-only or enforce
       ├─ policy.CheckFile(path, operation)
       ├─ emit event (source: "seccomp")
       └─ respond: CONTINUE or ERROR(-EACCES)
```

### File Handler Interface

Mirrors the existing `ExecveHandler` pattern:

```go
type FileHandler interface {
    Handle(ctx context.Context, req FileRequest) FileResult
}

type FileRequest struct {
    PID       uint32
    Syscall   int32       // SYS_OPENAT, SYS_UNLINKAT, etc.
    Path      string      // resolved absolute path
    Path2     string      // second path (rename/link only)
    Operation string      // "open", "create", "delete", "mkdir", "rename", ...
    Flags     uint32      // syscall-specific flags
    Mode      uint32      // file mode where applicable
    SessionID string
}

type FileResult struct {
    Action Action         // ActionContinue or ActionDeny
    Errno  int32          // e.g., EACCES
}
```

### Handle() Flow

```go
func (h *fileHandler) Handle(ctx context.Context, req FileRequest) FileResult {
    // 1. Check FUSE overlap — audit-only if FUSE is enforcing this path
    if h.mountRegistry.IsUnderFUSEMount(req.SessionID, req.Path) {
        dec := h.policy.CheckFile(req.Path, req.Operation)
        h.emit(req, dec, false, dec.EffectiveDecision == policy.Deny)
        return FileResult{Action: ActionContinue}
    }

    // 2. Policy check (reuses existing engine)
    dec := h.policy.CheckFile(req.Path, req.Operation)

    // 3. Handle rename/link second path
    if req.Path2 != "" {
        dec2 := h.policy.CheckFile(req.Path2, req.Operation)
        dec = combinePathDecisions(dec, dec2)
    }

    // 4. Emit event
    blocked := dec.EffectiveDecision == policy.Deny
    h.emit(req, dec, blocked, false)

    // 5. Enforce
    if blocked {
        return FileResult{Action: ActionDeny, Errno: EACCES}
    }
    return FileResult{Action: ActionContinue}
}
```

## Intercepted Syscalls

All path-based file syscalls that use the dirfd+path pattern:

| Syscall | Operation | Key Args |
|---------|-----------|----------|
| `openat` | open/create | dirfd, path, flags (`O_CREAT` distinguishes create vs open) |
| `openat2` | open/create | dirfd, path, how (`open_how` struct) |
| `unlinkat` | delete/rmdir | dirfd, path, flags (`AT_REMOVEDIR` = rmdir) |
| `mkdirat` | mkdir | dirfd, path, mode |
| `renameat2` | rename | olddirfd, oldpath, newdirfd, newpath, flags |
| `linkat` | link | olddirfd, oldpath, newdirfd, newpath |
| `symlinkat` | symlink | target, newdirfd, linkpath |
| `fchmodat` | chmod | dirfd, path, mode |
| `fchownat` | chown | dirfd, path, uid, gid |

### Operation Mapping

The `Operation` string passed to `policy.CheckFile()` is derived from the syscall:

```go
func syscallToOperation(nr int32, flags uint32) string {
    switch nr {
    case SYS_OPENAT, SYS_OPENAT2:
        if flags&(O_CREAT|O_TMPFILE) != 0 {
            return "create"
        }
        if flags&(O_WRONLY|O_RDWR|O_APPEND|O_TRUNC) != 0 {
            return "write"
        }
        return "open"
    case SYS_UNLINKAT:
        if flags&AT_REMOVEDIR != 0 {
            return "rmdir"
        }
        return "delete"
    case SYS_MKDIRAT:
        return "mkdir"
    case SYS_RENAMEAT2:
        return "rename"
    case SYS_LINKAT:
        return "link"
    case SYS_SYMLINKAT:
        return "symlink"
    case SYS_FCHMODAT:
        return "chmod"
    case SYS_FCHOWNAT:
        return "chown"
    }
}
```

## Path Resolution

Same pattern as the existing execve handler's dirfd resolution, extracted into a shared utility:

```go
func resolvePathAt(pid uint32, dirfd int32, pathPtr uint64) (string, error) {
    // 1. Read path string from tracee memory (ProcessVMReadv, cap 4096 bytes)
    path := readString(pid, pathPtr, 4096)

    // 2. Absolute path — done
    if filepath.IsAbs(path) {
        return filepath.Clean(path), nil
    }

    // 3. AT_FDCWD — resolve relative to /proc/<pid>/cwd
    if dirfd == AT_FDCWD {
        cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
        return filepath.Join(cwd, path), nil
    }

    // 4. dirfd — resolve relative to /proc/<pid>/fd/<dirfd>
    base, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
    return filepath.Join(base, path), nil
}
```

### TOCTOU Acknowledgment

The path string lives in the tracee's memory. Between `ProcessVMReadv` and the kernel resolving the path, the tracee (or another thread) could modify it. We accept this race:

- **Landlock** provides hard enforcement at the kernel level (no TOCTOU)
- **FUSE** intercepts at the VFS level (no TOCTOU for mounted paths)
- **Seccomp** provides best-effort audit and policy — correct in the common case, not guaranteed under adversarial conditions

## FUSE Coexistence

### Mount Registry

A lightweight registry tracks which paths have active FUSE mounts per session:

```go
type MountRegistry struct {
    mu     sync.RWMutex
    mounts map[string][]string // sessionID → list of real source paths
}

func (r *MountRegistry) Register(sessionID, sourcePath string)
func (r *MountRegistry) Deregister(sessionID, sourcePath string)
func (r *MountRegistry) IsUnderFUSEMount(sessionID, path string) bool
```

**Lifecycle**: Registered when FUSE mount succeeds, deregistered on unmount. The file handler checks on every request.

### Behavior Matrix

| FUSE active? | Seccomp policy decision | Seccomp action | Event emitted |
|-------------|------------------------|----------------|---------------|
| Yes | Allow | CONTINUE | `source: "seccomp"` |
| Yes | Deny | CONTINUE (defer to FUSE) | `source: "seccomp", shadow_deny: true` |
| No | Allow | CONTINUE | `source: "seccomp"` |
| No | Deny | ERROR(-EACCES) | `source: "seccomp", blocked: true` |

The `shadow_deny` field flags cases where seccomp would deny but defers to FUSE. Useful for detecting policy disagreements between the two layers.

### Automatic Fallback

If FUSE mount fails at session startup (no `/dev/fuse`, permission denied, etc.), the mount registry stays empty for that session. Seccomp automatically becomes the enforcing layer — no configuration change needed.

## Changes to agentsh-unixwrap

### Filter Extension

The seccomp filter in `agentsh-unixwrap` gains file syscalls when `file_monitor_enabled` is set:

```go
if cfg.FileMonitorEnabled {
    for _, nr := range []int{
        SYS_OPENAT, SYS_OPENAT2,
        SYS_UNLINKAT, SYS_MKDIRAT,
        SYS_RENAMEAT2, SYS_LINKAT,
        SYS_SYMLINKAT, SYS_FCHMODAT,
        SYS_FCHOWNAT,
    } {
        filt.AddRule(nr, seccomp.ActNotify)
    }
}
```

### Config Extension

The JSON config passed via `AGENTSH_SECCOMP_CONFIG` gains one field:

```json
{
  "unix_socket_enabled": true,
  "execve_enabled": true,
  "file_monitor_enabled": true,
  "signal_filter_enabled": true,
  "blocked_syscalls": ["..."]
}
```

No changes to the notify fd handoff — the same fd carries all notifications.

### Landlock Interaction

Landlock runs inside the child process (post-fork, pre-exec). Seccomp runs at the kernel boundary. Both are independent — Landlock may deny a syscall before seccomp even sees it, or seccomp may deny before Landlock checks. Both are deny-additional layers; the stricter one wins. No coordination needed.

## Event Schema

Events follow the existing `emitFileEvent` pattern. The `Source` field distinguishes seccomp from FUSE events:

```go
types.Event{
    ID:        uuid,
    Timestamp: time.Now(),
    Type:      "file_open",  // file_create, file_delete, file_mkdir, file_rename, ...
    SessionID: sessionID,
    Source:    "seccomp",    // vs "fuse"
    Data: map[string]any{
        "path":         "/workspace/src/main.go",
        "operation":    "open",
        "pid":          1234,
        "syscall":      "openat",
        "decision":     "allow",
        "effective":    "allow",
        "rule":         "workspace-files",
        "blocked":      false,
        "shadow_deny":  false,
    },
}
```

## Configuration

Under the existing `sandbox.seccomp` section:

```yaml
sandbox:
  seccomp:
    unix_socket:
      enabled: true
    execve:
      enabled: true
    file_monitor:
      enabled: true
      enforce_without_fuse: true
      audit_under_fuse: true
```

| `enabled` | FUSE available | `enforce_without_fuse` | Behavior |
|-----------|---------------|----------------------|----------|
| false | — | — | No file syscalls in seccomp filter |
| true | yes | — | Audit-only for FUSE paths, enforce for non-FUSE paths |
| true | no | true | Full enforcement (seccomp is primary) |
| true | no | false | Audit-only everywhere (observe, never deny) |

Defaults: `enabled: true`, `enforce_without_fuse: true`, `audit_under_fuse: true`.

## New Files

```
internal/netmonitor/unix/
  ├── handler.go              (MODIFY — add isFileSyscall routing branch)
  ├── file_handler.go         (NEW — FileHandler, Handle(), emit logic)
  ├── file_handler_test.go    (NEW)
  ├── file_syscalls.go        (NEW — syscall arg extraction, resolvePathAt,
  │                                   syscallToOperation, isFileSyscall)
  ├── file_syscalls_test.go   (NEW)
  └── mount_registry.go       (NEW — MountRegistry for FUSE overlap detection)

internal/seccomp/
  └── filter.go               (MODIFY — add file syscalls to ActNotify)

cmd/agentsh-unixwrap/
  └── main.go                 (MODIFY — wire file_monitor_enabled config flag)

internal/api/
  └── core.go                 (MODIFY — pass file_monitor_enabled in seccomp config,
                                         wire MountRegistry into FileHandler)
```

No new packages. All new code lives in existing packages following established patterns.

## Performance Considerations

- **Filter cost**: Adding 9 syscall numbers adds ~9 BPF instructions. Negligible.
- **Per-operation cost**: Each intercepted file syscall context-switches to agentsh (wake notify loop → read tracee memory → policy check → respond). Expect ~50-100μs per operation.
- **Hot path optimization**: The `isFileSyscall` check in the notify loop is a simple switch — no allocation.
- **Metrics**: Log syscall-interception count at session shutdown for tuning. Not a new metrics subsystem.
- **Escape hatch**: Set `file_monitor.enabled: false` to disable entirely if overhead is unacceptable.
