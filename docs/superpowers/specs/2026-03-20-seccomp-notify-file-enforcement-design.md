# Seccomp User-Notify Filesystem Enforcement Backend

**Date:** 2026-03-20
**Status:** Draft
**Scope:** Linux only (seccomp user notification)

## Background

agentsh runs inside Deno Deploy Sandboxes (Firecracker microVMs) where neither FUSE (`/dev/fuse` not exposed) nor Landlock (`/sys/kernel/security/landlock/` not mounted) can enforce `file_rules`. The policy is parsed from YAML but not kernel-enforced — it is dead config in this environment.

SECCOMP_RET_USER_NOTIF is available and already working for command interception (exec syscalls) and unix socket monitoring. The existing `file_monitor` seccomp path intercepts filesystem syscalls but uses `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for allowed operations, which is vulnerable to TOCTOU races on pointer arguments.

This design extends the existing seccomp file monitoring to become a full enforcement backend with TOCTOU-safe openat emulation via `SECCOMP_IOCTL_NOTIF_ADDFD`.

## What Changes

### 1. BPF Filter: New Syscalls

**File:** `internal/netmonitor/unix/seccomp_linux.go`

Add five metadata/create syscalls to `InstallFilterWithConfig` when `FileMonitorEnabled` is true:

| Syscall | Nr (amd64) | Purpose |
|---------|-----------|---------|
| `statx` | 332 | Modern stat |
| `newfstatat` | 262 | fstatat(2) |
| `faccessat2` | 439 | Access checks |
| `readlinkat` | 267 | Symlink target reads |
| `mknodat` | 259 | Device/FIFO/socket creation |

The `intercept_metadata` config flag controls whether `statx`, `newfstatat`, `faccessat2`, and `readlinkat` are added to the filter. When false, only write-affecting syscalls are intercepted.

Add io_uring blocking with `ActErrno(EPERM)` (not notify, not kill):
- `io_uring_setup` (425)
- `io_uring_enter` (426)

Controlled by the `block_io_uring` config flag.

### 2. Syscall Routing and Arg Extraction

**Files:** `internal/netmonitor/unix/file_syscalls.go`, `handler.go`

**`isFileSyscall`** — add `statx`, `newfstatat`, `faccessat2`, `readlinkat`, `mknodat`.

**`extractFileArgs`** — new cases:
- `statx(dirfd, path, flags, mask, statxbuf)` — dirfd=arg0, path=arg1, flags=arg2
- `newfstatat(dirfd, path, statbuf, flags)` — dirfd=arg0, path=arg1, flags=arg3
- `faccessat2(dirfd, path, mode, flags)` — dirfd=arg0, path=arg1
- `readlinkat(dirfd, path, buf, bufsiz)` — dirfd=arg0, path=arg1
- `mknodat(dirfd, path, mode, dev)` — dirfd=arg0, path=arg1, mode=arg2

**`syscallToOperation`** mappings:
- `statx`, `newfstatat` → `"stat"`
- `faccessat2` → `"access"`
- `readlinkat` → `"readlink"`
- `mknodat` → `"mknod"`

Routing in `handleFileNotification` is unchanged — all syscalls flow through: extract args → resolve path → build `FileRequest` → `FileHandler.Handle()` → respond.

### 3. openat AddFD Emulation

**File:** `internal/netmonitor/unix/handler.go` — new function `handleFileNotificationEmulated`

When `FileHandler.emulateOpen` is true and the syscall is `openat`/`openat2`, allowed opens are emulated by the supervisor instead of using CONTINUE:

1. Extract args, resolve path, evaluate policy (same as existing path).
2. **Denied**: respond with `-EACCES` (unchanged).
3. **Allowed openat/openat2**:
   a. Supervisor opens the file via `/proc/<pid>/root/<resolved_path>` using the child's flags. Forwarded flags: `O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_APPEND`, `O_TRUNC`, `O_CREAT` (with mode), `O_NOFOLLOW`, `O_DIRECTORY`, `O_PATH`, `O_NOCTTY`, `O_CLOEXEC`, `O_NONBLOCK`.
   b. If supervisor open fails → respond with the errno from the failed open.
   c. If supervisor open succeeds → inject fd via `NotifAddFD(notifFD, reqID, supervisorFD, 0, SECCOMP_ADDFD_FLAG_SEND)`. The `SEND` flag atomically injects the fd AND completes the notification response — no separate `NotifRespond` call.
   d. Close the supervisor's copy of the fd.
4. **Allowed non-openat** (unlinkat, statx, etc.): ID validation bracket + CONTINUE (section 4).

**Fallbacks to CONTINUE + ID validation** (accept residual TOCTOU):
- `openat2` with non-zero `RESOLVE_*` flags — supervisor cannot replicate `RESOLVE_NO_SYMLINKS`, `RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`, `RESOLVE_NO_XDEV` from its own namespace.
- `O_TMPFILE` — supervisor's tmpfile may land on a different filesystem.

**Activation**: `emulateOpen` is set in `createFileHandler()` when `cfg.OpenatEmulation && !fuseAvailable && !landlockAvailable`. When FUSE or Landlock handles enforcement, seccomp stays in CONTINUE mode.

### 4. TOCTOU Mitigation: ID Validation Bracketing

**File:** `internal/netmonitor/unix/addfd_linux.go`

New helper:
```go
func NotifIDValid(notifFD int, notifID uint64) error
```

Uses `SECCOMP_IOCTL_NOTIF_ID_VALID` (ioctl `0x40082102`). Returns nil if valid, `ENOENT` if stale.

For all syscalls that use `SECCOMP_USER_NOTIF_FLAG_CONTINUE`:
1. Read path from tracee memory.
2. `NotifIDValid(notifFD, reqID)` — if stale, skip response.
3. Evaluate policy.
4. `NotifIDValid(notifFD, reqID)` — if stale, skip response.
5. Respond with CONTINUE or `-EACCES`.

This narrows but does not eliminate the TOCTOU window for CONTINUE-mode syscalls. The real fix is AddFD emulation for openat (section 3). For non-fd-returning syscalls, the residual risk is accepted — blast radius is contained within the sandbox.

### 5. /proc/self/fd/N Interception

**File:** `internal/netmonitor/unix/file_handler.go`

A process can bypass path-based policy by opening `/proc/self/fd/<N>` to re-derive a path from an existing fd.

In `FileHandler.Handle()`, before policy evaluation:
1. Check if the resolved path matches `/proc/self/fd/<N>`, `/proc/<pid>/fd/<N>` (where pid matches the requesting process or thread group), or `/dev/fd/<N>`.
2. If matched, resolve the actual target via readlink on `/proc/<pid>/fd/<N>`.
3. Evaluate policy against the **target path**, not the procfs path.
4. For AddFD emulation: open the target path (not the procfs path).

**New helper** in `file_syscalls.go`:
```go
func resolveProcFD(pid int, path string) (resolvedPath string, wasProcFD bool)
```

### 6. execve file_rules Evaluation

**File:** `internal/netmonitor/unix/handler.go`

In `handleExecveNotification`, after `ExecveHandler.Handle()` returns `ActionContinue`:
1. Call `fileHandler.Handle(FileRequest{Path: filename, Operation: "execute", ...})`.
2. If file policy denies → respond with `-EACCES`.
3. If file policy allows → proceed with CONTINUE.

The `fileHandler` parameter is added to `handleExecveNotification`. `ServeNotifyWithExecve` already has both handlers in scope.

Operation `"execute"` is distinct from `"open"` — policy authors can write rules targeting execution specifically.

No AddFD needed — execve doesn't return an fd. CONTINUE is correct.

### 7. Backend Selection and Detection

**File:** `internal/api/file_monitor_linux.go`

`createFileHandler` sets:
```go
emulateOpen = cfg.OpenatEmulation && !fuseAvailable && !landlockAvailable
```

Where `fuseAvailable` = mount registry has active FUSE mounts for this session, `landlockAvailable` = `capabilities.DetectLandlock().Available`.

**File:** `internal/capabilities/detect_linux.go`

New function `detectFileEnforcementBackend() string`:
- `"landlock"` — Landlock available and enabled
- `"fuse"` — /dev/fuse accessible
- `"seccomp-notify"` — seccomp user-notify available, neither Landlock nor FUSE is
- `"none"` — nothing available

Added to `DetectResult.Capabilities` as `file_enforcement`.

**File:** `internal/cli/detect.go` — render in table/json/yaml output.

### 8. Config Changes

**File:** `internal/config/config.go`

```go
type SandboxSeccompFileMonitorConfig struct {
    Enabled            bool `yaml:"enabled"`
    EnforceWithoutFUSE bool `yaml:"enforce_without_fuse"`
    InterceptMetadata  bool `yaml:"intercept_metadata"`
    OpenatEmulation    bool `yaml:"openat_emulation"`
    BlockIOUring       bool `yaml:"block_io_uring"`
}
```

**Defaults** (in `applyDefaults`):

| Condition | InterceptMetadata | OpenatEmulation | BlockIOUring |
|-----------|:-:|:-:|:-:|
| `enabled + enforce_without_fuse` | true | true | true |
| `enabled` only (audit mode) | false | false | false |

All three can be explicitly overridden.

**Example config (Deno Deploy):**
```yaml
sandbox:
  seccomp:
    file_monitor:
      enabled: true
      enforce_without_fuse: true
```

### 9. Testing

**Unit tests:**

1. `file_syscalls_test.go` — five new syscalls in `extractFileArgs` and `syscallToOperation`.
2. `file_handler_test.go`:
   - `/proc/self/fd/N` resolution + policy evaluation against target path.
   - `/dev/fd/N` same.
   - `emulateOpen` allow → AddFD called (not CONTINUE).
   - `emulateOpen` deny → `-EACCES`.
   - Fallback to CONTINUE for openat2 RESOLVE_* and O_TMPFILE.
3. `addfd_linux_test.go` — `NotifIDValid` with valid and stale IDs.
4. `handler_test.go` — execve + file_rules: command_rules allows, file_rules denies → `-EACCES`.

**Integration tests** (`file_integration_test.go`):
5. Fork child, install filter, exercise: openat with AddFD (verify valid fd + correct contents), openat denied (EACCES), statx on denied path (EACCES), io_uring_setup (EPERM).

**End-to-end (Deno test suite):**
6. Compile small C binary inside sandbox making raw syscalls (openat, statx, unlinkat) to verify kernel-level enforcement independent of exec API.

## Security Model Summary

| Syscall class | Response strategy | TOCTOU | Rationale |
|---|---|---|---|
| openat/openat2 (no RESOLVE_*) | AddFD emulation | Eliminated | Supervisor opens file, injects fd atomically |
| openat2 with RESOLVE_* | CONTINUE + ID validation | Residual | Can't replicate resolve semantics from supervisor |
| O_TMPFILE | CONTINUE + ID validation | Residual | Supervisor may hit wrong filesystem |
| unlinkat, renameat2, mkdirat, etc. | CONTINUE + ID validation | Residual (low severity) | Non-fd syscalls; worst case = wrong file affected within sandbox |
| statx, newfstatat, faccessat2, readlinkat | CONTINUE + ID validation | Residual (low severity) | Read-only metadata; information leak bounded by sandbox |
| execve/execveat | CONTINUE | N/A | Kernel loads binary; no fd returned |
| io_uring_setup/enter | ERRNO(EPERM) | N/A | Blocked at BPF level |

## Dependencies

- Linux 5.14+ for `SECCOMP_ADDFD_FLAG_SEND` (atomic AddFD + respond).
- Existing `github.com/seccomp/libseccomp-golang` (CGO) — no new dependencies.
- Existing `NotifAddFD` implementation in `addfd_linux.go`.

## Out of Scope

- Replacing libseccomp-golang with pure Go — decided against to maintain consistency.
- AddFD emulation when FUSE is the primary backend — FUSE already controls opens.
- `read(2)` / `write(2)` interception — controlling at openat time is sufficient.
- New top-level `file_enforcement` config section — backend selection is runtime auto-detection, not config.
