# Seccomp Direct Ioctl for File Monitor Enforcement

## Problem

When the file_rules policy denies a write operation via the seccomp file monitor, the handler correctly evaluates the policy, logs the event as `effective_action: "blocked"`, but the actual `openat` syscall succeeds in the tracee. This only affects `O_WRONLY` on existing files. `O_CREAT` operations are correctly blocked because Landlock catches them independently.

Evidence from the AST probe on Blaxel:
- `openat("/etc/hostname", O_WRONLY)` — event log says blocked, but probe sees success
- `openat("/etc/ast-probe-write-test", O_WRONLY|O_CREAT|O_TRUNC)` — correctly blocked (Landlock)
- `openat("/root/.bashrc", O_WRONLY|O_APPEND)` — event log says blocked, but probe sees success

## Root Cause Analysis

The code path from policy evaluation to seccomp response is logically correct:

1. `FileHandler.Handle()` returns `FileResult{Action: ActionDeny, Errno: EACCES}` (correct)
2. `handleFileNotification()` constructs `ScmpNotifResp{Error: -13}` (correct)
3. `seccomp.NotifRespond(fd, &resp)` is called — but the **error is discarded** with `_`

The response delivery goes through the libseccomp-golang binding's `NotifRespond` function, which is the ONLY seccomp ioctl in the codebase that uses the Go binding rather than a direct `unix.Syscall(SYS_IOCTL, ...)` call. The existing `NotifIDValid` and `NotifAddFD` functions both use direct ioctls (in `addfd_linux.go`).

If `NotifRespond` silently fails (binding serialization issue, stale notification, fd issue), the event still says "blocked" (emitted before the response) but the tracee continues with success because no valid response was delivered.

## Solution

Replace all `seccomp.NotifRespond()` calls with direct ioctl wrappers, matching the pattern already established for `NotifIDValid` and `NotifAddFD`. Check and log all response errors.

## Design

### 1. New ioctl wrapper (addfd_linux.go)

**Struct** matching `struct seccomp_notif_resp` from `<linux/seccomp.h>`:

```go
type seccompNotifResp struct {
    id    uint64  // notification ID
    val   int64   // syscall return value (__s64 in kernel, not uint64)
    error int32   // negative errno (e.g., -13 for EACCES)
    flags uint32  // SECCOMP_USER_NOTIF_FLAG_CONTINUE
}
```

Note: the kernel defines `val` as `__s64` (signed). The libseccomp-golang binding uses `uint64` (unsigned). Matching the kernel layout is correct.

**Ioctl constant**: `ioctlNotifSend = 0xC0182101` — `_IOWR('!', 1, struct seccomp_notif_resp)`

**Helper functions**:

```go
func NotifRespondDeny(notifFD int, id uint64, errno int32) error
func NotifRespondContinue(notifFD int, id uint64) error
```

Both call `unix.Syscall(SYS_IOCTL, fd, ioctlNotifSend, &resp)` and return the error.

### 2. Replace all seccomp.NotifRespond calls in handler.go

Every `_ = seccomp.NotifRespond(fd, &resp)` is replaced with the appropriate direct ioctl call.

**Error handling**:
- Deny response failures: `slog.Error` (security-relevant enforcement failure)
- Continue response failures: `slog.Debug` (non-critical, usually stale notification)
- No retry — if the ioctl fails, the notification is likely stale (ENOENT)

**Scope**: ALL handler paths — file (4 calls in non-emulated, ~13 in emulated), execve (~7 calls), unix socket (~5 calls). This removes the runtime dependency on `seccomp.NotifRespond` entirely.

After this change, `seccomp.NotifReceive` is the only remaining libseccomp call in the notify loop.

### 3. Testing

- **Struct layout test**: Verify `seccompNotifResp` is 24 bytes with correct field offsets via `unsafe.Sizeof`/`unsafe.Offsetof`
- **Ioctl constant test**: Verify `ioctlNotifSend` matches `_IOWR('!', 1, 24)` computation
- **Integration coverage**: Existing file handler integration tests cover policy evaluation. The AST probe serves as end-to-end validation.

## Files Changed

1. `internal/netmonitor/unix/addfd_linux.go` — new struct, ioctl constant, `NotifRespondDeny`, `NotifRespondContinue`
2. `internal/netmonitor/unix/handler.go` — replace all `seccomp.NotifRespond` calls
3. `internal/netmonitor/unix/addfd_linux_test.go` — struct layout and ioctl constant tests

## Impact

Fixes AST probe score from 15/28 (54%) to 18-19/28 (64-68%) by making `O_WRONLY` enforcement on existing files actually return `EACCES` to the tracee.
