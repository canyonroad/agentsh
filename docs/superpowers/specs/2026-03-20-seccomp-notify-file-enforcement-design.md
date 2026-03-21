# Seccomp User-Notify Filesystem Enforcement Backend

**Date:** 2026-03-20
**Status:** Implemented
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

Add io_uring blocking. Use `seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))` (not notify, not kill):
- `io_uring_setup` (425)
- `io_uring_enter` (426)
- `io_uring_register` (427) — a process could use this to register fds with an inherited io_uring instance

Controlled by the `block_io_uring` config flag.

**FilterConfig bridge:** Add `InterceptMetadata bool` and `BlockIOUring bool` fields to the `FilterConfig` struct in `seccomp_linux.go`. The `SandboxSeccompFileMonitorConfig` values are mapped to `FilterConfig` in `createFileHandler` / the wrapper setup code.

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

When `FileHandler.emulateOpen` is true and the syscall is `openat` or legacy `open`/`creat` on amd64, allowed opens are emulated by the supervisor instead of using CONTINUE:

1. Extract args, resolve path, evaluate policy (same as existing path).
2. **Denied**: respond with `-EACCES` (unchanged).
3. **Allowed openat** (and legacy `open`/`creat` on amd64):
   a. Supervisor opens the file via `/proc/<pid>/root/<resolved_path>` using the child's flags. Forwarded flags: `O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_APPEND`, `O_TRUNC`, `O_CREAT` (with mode), `O_NOFOLLOW`, `O_DIRECTORY`, `O_PATH`, `O_NOCTTY`, `O_CLOEXEC`, `O_NONBLOCK`.
   b. When `O_CREAT` is set, the tracee's umask is read from `/proc/<pid>/status` and applied to `mode` so created files have the same permissions the kernel would produce. If umask cannot be read → fall back to CONTINUE (not raw mode, not error).
   c. If supervisor open fails → respond with the actual errno from the failed open (not EIO).
   d. If supervisor open succeeds → inject fd via `seccompNotifAddFD` struct with `SECCOMP_ADDFD_FLAG_SEND`. `O_CLOEXEC` from the original flags is propagated to `newfdFlags` so the injected fd has the correct close-on-exec flag in the tracee. The `SEND` flag atomically injects the fd AND completes the notification response — no separate `NotifRespond` call.
   e. Close the supervisor's copy of the fd. If AddFD fails with `ENOENT` (notification stale), skip response. Other AddFD failures propagate the actual errno to the tracee.
4. **Allowed non-openat** (unlinkat, statx, etc.): ID validation bracket + CONTINUE (section 4).

**`openat2` is never emulated — always uses CONTINUE + ID validation.** The `open_how` struct's `resolve` field (`RESOLVE_NO_SYMLINKS`, `RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`, `RESOLVE_NO_XDEV`, etc.) encodes semantics the supervisor cannot replicate from its own namespace. Attempting to emulate even zero-`resolve` `openat2` was rejected to avoid subtle correctness bugs as new `RESOLVE_*` flags are added by future kernels. Invalid `openat2` args (`how_ptr=0` or `how_size<24`) are passed directly to the kernel via CONTINUE.

**Additional CONTINUE fallbacks** (accept residual TOCTOU):
- `O_TMPFILE` — supervisor's tmpfile may land on a different filesystem.

**Error handling in emulation mode:** When `emulateOpen` is true and path resolution fails (tracee memory read error, dirfd resolution error), the handler **denies** the syscall with `-EACCES` (fail-secure). This differs from the existing CONTINUE-mode behavior where path resolution failure results in allowing the syscall. Fail-open is acceptable for audit mode; fail-secure is required for enforcement mode.

**Mount namespace assumption:** The supervisor opens files via `/proc/<pid>/root/<path>` which correctly traverses the tracee's mount namespace. This assumes the supervisor has sufficient privileges to access `/proc/<pid>/root` (requires ptrace access or same user). In the Deno Deploy / Firecracker target environment, supervisor and tracee share the same mount namespace, so this is not a concern.

**Activation**: `emulateOpen` is set in `createFileHandler()` when `cfg.OpenatEmulation && !fuseAvailable && !landlockAvailable`. When FUSE or Landlock handles enforcement, seccomp stays in CONTINUE mode.

### 4. TOCTOU Mitigation: ID Validation Bracketing

**File:** `internal/netmonitor/unix/addfd_linux.go`

New helper:
```go
func NotifIDValid(notifFD int, notifID uint64) error
```

Uses `SECCOMP_IOCTL_NOTIF_ID_VALID`. The ioctl number changed between kernel versions: `0x40082102` (pre-5.17, `_IOW`) and `0xC0082102` (5.17+, `_IOWR`, after kernel commit 47e33c05f9f07). The implementation should try the newer value first and fall back to the older one on `ENOTTY`. Returns nil if valid, `ENOENT` if stale.

For all syscalls that use `SECCOMP_USER_NOTIF_FLAG_CONTINUE`:
1. Read path from tracee memory.
2. `NotifIDValid(notifFD, reqID)` — if stale, skip response.
3. Evaluate policy.
4. `NotifIDValid(notifFD, reqID)` — if stale, skip response.
5. Respond with CONTINUE or `-EACCES`.

This narrows but does not eliminate the TOCTOU window for CONTINUE-mode syscalls. The real fix is AddFD emulation for openat (section 3). For non-fd-returning syscalls, the residual risk is accepted — blast radius is contained within the sandbox.

### 5. /proc/self/fd/N Interception

**File:** `internal/netmonitor/unix/file_syscalls.go`

A process can bypass path-based policy by opening `/proc/self/fd/<N>` to re-derive a path from an existing fd.

In `FileHandler.Handle()` and `handleFileNotificationEmulated()`, before policy evaluation:
1. Check if the resolved path matches any of the following:
   - `/proc/self/fd/<N>`
   - `/proc/thread-self/fd/<N>`
   - `/proc/<pid>/fd/<N>` where `<pid>` is the requesting TID or TGID (multi-threaded processes may reference either)
   - `/dev/fd/<N>`
   - `/dev/stdin`, `/dev/stdout`, `/dev/stderr` (mapped to fd 0, 1, 2 respectively)
   - `/proc/self/fd/<N>/suffix` and similar paths with trailing path components (with directory check)
2. If matched, resolve the actual target via `readlink` on `/proc/<pid>/fd/<N>`.
3. Non-filesystem pseudo-paths (`pipe:[...]`, `socket:[...]`, `anon_inode:[...]`) are **not** substituted — they have no absolute path to enforce against.
4. For `/fd/N/suffix` paths: verify the fd target is a directory before appending the suffix. If not a directory, leave path unrewritten (kernel will return `ENOTDIR` via CONTINUE).
5. Evaluate policy against the **target path**, not the procfs path.
6. For AddFD emulation: open the target path (not the procfs path).

**TOCTOU note:** A concurrent thread could close fd N and reopen a different file on that fd number between the supervisor's `readlink` and the policy evaluation. For AddFD-emulated opens, this is mitigated because the supervisor opens the resolved target path (not the procfs symlink). For CONTINUE-mode syscalls (e.g., `fstatat` on `/proc/self/fd/N`), this residual race exists but is bounded by the sandbox.

**Helper** in `file_syscalls.go`:
```go
func resolveProcFD(pid int, path string) (resolvedPath string, wasProcFD bool)
```

### 6. execve file_rules Evaluation

**Status: Deferred.** This section was removed from the implementation. `openat` interception already covers access to binary files before execution, making a separate `execve` file_rules check redundant in practice. The `handleExecveNotification` function signature was not changed — no `fileHandler` parameter was added.

The design below is preserved for reference in case this is revisited:

> In `handleExecveNotification`, after `ExecveHandler.Handle()` returns `ActionContinue`, call `fileHandler.Handle(FileRequest{Path: filename, Operation: "execute", ...})`. If file policy denies → respond with `-EACCES`. Operation `"execute"` is distinct from `"open"` — policy authors can write rules targeting execution specifically.

### 7. Backend Selection and Detection

**File:** `internal/api/file_monitor_linux.go`

`createFileHandler` enables AddFD emulation when all of the following are true:

1. `cfg.OpenatEmulation` is true (or defaults to true when `enforce_without_fuse` is true)
2. `cfg.EnforceWithoutFUSE` is true (enforcement mode, not audit mode)
3. `unixmon.ProbeAddFDSupport()` returns true — kernel is >= 5.14 (checked via `uname`, not ioctl probe; ioctl probes with invalid fds are unreliable as `EBADF` may occur before ioctl command dispatch)
4. `landlockEnabled` is false OR `capabilities.DetectLandlock().Available` is false — Landlock is not actively enforcing
5. `registry.HasAnyMounts()` is false — no FUSE mounts are active for this session

```go
emulateOpen = openatEmulation && enforce && ProbeAddFDSupport() &&
              !landlockActive && !fuseActive
```

The `landlockEnabled` boolean is threaded from `a.cfg.Landlock.Enabled` through `startNotifyHandler` into `createFileHandler`, distinguishing "Landlock configured by the user" from "Landlock kernel-available" (`capabilities.DetectLandlock().Available`). Both must be true for Landlock to be considered active.

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
| openat/open/creat (no O_TMPFILE) | AddFD emulation | Eliminated | Supervisor opens file, injects fd atomically |
| openat2 (all cases) | CONTINUE + ID validation | Residual | Never emulated — `resolve` flags encode semantics the supervisor cannot replicate; blanket exclusion avoids correctness bugs as new RESOLVE_* flags are added |
| O_TMPFILE | CONTINUE + ID validation | Residual | Supervisor may hit wrong filesystem |
| unlinkat, renameat2, mkdirat, mknodat, etc. | CONTINUE + ID validation | Residual (low severity) | Non-fd syscalls; worst case = wrong file affected within sandbox |
| statx, newfstatat, faccessat2, readlinkat | CONTINUE + ID validation | Residual (low severity) | Read-only metadata; information leak bounded by sandbox |
| execve/execveat | CONTINUE | N/A | Kernel loads binary; no fd returned. file_rules check deferred (openat interception covers binary access) |
| io_uring_setup/enter/register | ERRNO(EPERM) | N/A | Blocked at BPF level |

## Dependencies

- Linux 5.14+ for `SECCOMP_ADDFD_FLAG_SEND` (atomic AddFD + respond). Detected at runtime via `uname` kernel version check (`ProbeAddFDSupport`), not ioctl probe.
- Existing `github.com/seccomp/libseccomp-golang` (CGO) — no new dependencies.
- Existing `NotifAddFD` implementation in `addfd_linux.go`.

## Out of Scope

- Replacing libseccomp-golang with pure Go — decided against to maintain consistency.
- AddFD emulation when FUSE is the primary backend — FUSE already controls opens.
- `read(2)` / `write(2)` interception — controlling at openat time is sufficient.
- New top-level `file_enforcement` config section — backend selection is runtime auto-detection, not config.
