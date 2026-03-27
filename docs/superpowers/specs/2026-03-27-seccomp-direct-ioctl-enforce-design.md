# Seccomp Direct Ioctl for File Monitor Enforcement

## Problem

When the file_rules policy denies a write operation via the seccomp file monitor, the handler correctly evaluates the policy, logs the event as `effective_action: "blocked"`, but the actual `openat` syscall succeeds in the tracee. This only affects `O_WRONLY` on existing files. `O_CREAT` operations are correctly blocked because Landlock catches them independently.

Evidence from the AST probe on Blaxel:
- `openat("/etc/hostname", O_WRONLY)` — event log says blocked, but probe sees success
- `openat("/etc/ast-probe-write-test", O_WRONLY|O_CREAT|O_TRUNC)` — correctly blocked (Landlock)
- `openat("/root/.bashrc", O_WRONLY|O_APPEND)` — event log says blocked, but probe sees success

## Root Cause

**Double-negation bug in libseccomp-golang's `toNative` method.**

The handler code sets `resp.Error = -int32(unix.EACCES)` (i.e., `-13`, pre-negated). The libseccomp-golang binding's `toNative` method then negates it again:

```go
// seccomp_internal.go:737 in libseccomp-golang
resp.error = (C.__s32(scmpResp.Error) * -1) // "kernel requires a negated value"
```

Result: `(-13) * -1 = +13`. The kernel receives `+13` in the error field, which is not a valid negative errno. The kernel treats it as no error and the syscall succeeds.

This explains the full pattern:
- **CONTINUE works**: `flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE`, `error = 0`. `toNative` negates: `0 * -1 = 0`. Kernel sees flags + zero error → continues syscall.
- **DENY fails**: `error = -13`. `toNative` negates: `(-13) * -1 = +13`. Kernel sees positive error → treats as success.
- **O_CREAT blocked**: Landlock enforces independently — seccomp denial also fails silently, but Landlock catches it.

The libseccomp-golang binding's contract is that `ScmpNotifResp.Error` should be a **positive** errno (e.g., `13`), and `toNative` negates it for the kernel. The handler code passes a pre-negated value, triggering the double-negation.

## Solution

Replace all `seccomp.NotifRespond()` calls with direct ioctl wrappers, matching the pattern already established for `NotifIDValid` and `NotifAddFD` in `addfd_linux.go`. This bypasses the double-negation entirely and gives direct error visibility.

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

**Constants**:
- `ioctlNotifSend = 0xC0182101` — `_IOWR('!', 1, struct seccomp_notif_resp)`
- `seccompUserNotifFlagContinue = 0x1` — `SECCOMP_USER_NOTIF_FLAG_CONTINUE`

**Helper functions**:

```go
func NotifRespondDeny(notifFD int, id uint64, errno int32) error
func NotifRespondContinue(notifFD int, id uint64) error
```

Both call `unix.Syscall(SYS_IOCTL, fd, ioctlNotifSend, &resp)` directly and return any error. `NotifRespondDeny` sets `error = -errno` (correctly negated once). `NotifRespondContinue` sets `flags = seccompUserNotifFlagContinue`.

**Expected ioctl errors**:
- `ENOENT` — notification stale (process exited/killed). Non-critical.
- `EINVAL` — invalid notification ID or malformed response.
- `EBADF` — notify fd closed (handler shutting down). Non-critical.

### 2. Replace all seccomp.NotifRespond calls

Every `_ = seccomp.NotifRespond(fd, &resp)` is replaced with the appropriate direct ioctl call.

**Error handling**:
- Deny response failures: `slog.Error` (security-relevant enforcement failure)
- Continue response failures: `slog.Debug` (non-critical, usually stale notification)
- No retry — if the ioctl fails, the notification is likely stale (ENOENT)

**Scope**: ALL handler paths in `handler.go` — file (~17 calls across emulated and non-emulated), execve (~7 calls), unix socket (~5 calls). Also replace `Filter.Respond()` in `seccomp_linux.go` which has the same double-negation bug.

Signal filter calls in `internal/signal/seccomp_linux.go` are **out of scope** — the signal filter uses its own dedicated `SignalFilter.Respond()` method and is not part of the file enforcement path. It has the same double-negation bug but will be addressed separately.

After this change, `seccomp.NotifReceive` is the only remaining libseccomp call in the notify loop.

### 3. Testing

- **Struct layout test**: Verify `seccompNotifResp` is 24 bytes with correct field offsets via `unsafe.Sizeof`/`unsafe.Offsetof`
- **Ioctl constant test**: Verify `ioctlNotifSend` matches `_IOWR('!', 1, 24)` computation
- **Invalid-fd test**: Call `NotifRespondDeny(-1, 0, EACCES)` and verify it returns an error (matching existing `TestAddFD_InvalidFD` pattern)
- **Integration coverage**: Existing file handler integration tests cover policy evaluation. The AST probe serves as end-to-end validation.

## Files Changed

1. `internal/netmonitor/unix/addfd_linux.go` — new struct, constants, `NotifRespondDeny`, `NotifRespondContinue`
2. `internal/netmonitor/unix/handler.go` — replace all `seccomp.NotifRespond` calls (~29 sites)
3. `internal/netmonitor/unix/seccomp_linux.go` — replace `Filter.Respond()` to use direct ioctl
4. `internal/netmonitor/unix/addfd_linux_test.go` — struct layout, ioctl constant, and invalid-fd tests

## Impact

Fixes AST probe score from 15/28 (54%) to 18-19/28 (64-68%) by making `O_WRONLY` enforcement on existing files actually return `EACCES` to the tracee.
