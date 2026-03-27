# Seccomp Direct Ioctl Enforcement Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace libseccomp-golang's `NotifRespond` with direct ioctl calls to fix the double-negation bug that causes seccomp file monitor denials to silently succeed.

**Architecture:** Add `NotifRespondDeny` and `NotifRespondContinue` functions to `addfd_linux.go` using the same direct `unix.Syscall(SYS_IOCTL, ...)` pattern as the existing `NotifIDValid` and `NotifAddFD`. Replace all 29 `seccomp.NotifRespond` call sites in `handler.go` and the 1 call in `seccomp_linux.go:Filter.Respond()`. Log errors instead of discarding them.

**Tech Stack:** Go, linux/seccomp.h ioctls, `golang.org/x/sys/unix`

**Spec:** `docs/superpowers/specs/2026-03-27-seccomp-direct-ioctl-enforce-design.md`

---

### Task 1: Add direct ioctl response wrapper

**Files:**
- Modify: `internal/netmonitor/unix/addfd_linux.go` (append after line 165)
- Test: `internal/netmonitor/unix/addfd_linux_test.go`

- [ ] **Step 1: Write failing tests for the new struct, constants, and functions**

Add to `internal/netmonitor/unix/addfd_linux_test.go`:

```go
func TestNotifSend_StructLayout(t *testing.T) {
	var s seccompNotifResp
	require.Equal(t, uintptr(24), unsafe.Sizeof(s), "seccompNotifResp should be 24 bytes")
	require.Equal(t, uintptr(0), unsafe.Offsetof(s.id), "id at offset 0")
	require.Equal(t, uintptr(8), unsafe.Offsetof(s.val), "val at offset 8")
	require.Equal(t, uintptr(16), unsafe.Offsetof(s.err), "err at offset 16")
	require.Equal(t, uintptr(20), unsafe.Offsetof(s.flags), "flags at offset 20")
}

func TestNotifSend_IoctlNumber(t *testing.T) {
	// _IOWR('!', 1, struct seccomp_notif_resp) = 0xC0182101
	require.Equal(t, uintptr(0xC0182101), uintptr(ioctlNotifSend))
}

func TestNotifSend_ContinueFlag(t *testing.T) {
	require.Equal(t, uint32(0x1), uint32(seccompUserNotifFlagContinue))
}

func TestNotifRespondDeny_InvalidFD(t *testing.T) {
	err := NotifRespondDeny(-1, 0, 13)
	require.Error(t, err, "NotifRespondDeny with invalid fd should fail")
}

func TestNotifRespondContinue_InvalidFD(t *testing.T) {
	err := NotifRespondContinue(-1, 0)
	require.Error(t, err, "NotifRespondContinue with invalid fd should fail")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/netmonitor/unix/ -run 'TestNotifSend|TestNotifRespond(Deny|Continue)_InvalidFD' -v`
Expected: FAIL — `seccompNotifResp`, `ioctlNotifSend`, `NotifRespondDeny`, `NotifRespondContinue` undefined.

- [ ] **Step 3: Write the implementation**

Add to `internal/netmonitor/unix/addfd_linux.go` after line 165:

```go
// seccompNotifResp matches struct seccomp_notif_resp from <linux/seccomp.h>.
// Layout must exactly mirror the kernel struct:
//
//	struct seccomp_notif_resp {
//	    __u64 id;
//	    __s64 val;
//	    __s32 error;
//	    __u32 flags;
//	};
type seccompNotifResp struct {
	id    uint64 // notification ID from seccomp_notif_req
	val   int64  // syscall return value (__s64, not uint64)
	err   int32  // negative errno (e.g., -EACCES = -13)
	flags uint32 // SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// ioctlNotifSend is SECCOMP_IOCTL_NOTIF_SEND.
// Computed as _IOWR('!', 1, struct seccomp_notif_resp) = 0xC0182101.
const ioctlNotifSend = 0xC0182101

// seccompUserNotifFlagContinue tells the kernel to execute the syscall
// as if seccomp were not installed.
const seccompUserNotifFlagContinue = 0x1

// NotifRespondDeny responds to a seccomp notification with an error,
// causing the trapped syscall to fail with the given errno.
// The errno parameter should be a positive value (e.g., unix.EACCES = 13);
// this function negates it for the kernel.
func NotifRespondDeny(notifFD int, id uint64, errno int32) error {
	resp := seccompNotifResp{
		id:  id,
		err: -errno, // kernel expects negative errno
	}
	_, _, e := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifFD),
		uintptr(ioctlNotifSend),
		uintptr(unsafe.Pointer(&resp)),
	)
	if e != 0 {
		return e
	}
	return nil
}

// NotifRespondContinue responds to a seccomp notification with CONTINUE,
// allowing the trapped syscall to proceed as if seccomp were not installed.
func NotifRespondContinue(notifFD int, id uint64) error {
	resp := seccompNotifResp{
		id:    id,
		flags: seccompUserNotifFlagContinue,
	}
	_, _, e := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifFD),
		uintptr(ioctlNotifSend),
		uintptr(unsafe.Pointer(&resp)),
	)
	if e != 0 {
		return e
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/netmonitor/unix/ -run 'TestNotifSend|TestNotifRespond(Deny|Continue)_InvalidFD' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/addfd_linux.go internal/netmonitor/unix/addfd_linux_test.go
git commit -m "feat: add direct ioctl wrappers for seccomp notify responses

NotifRespondDeny and NotifRespondContinue bypass libseccomp-golang's
NotifRespond which has a double-negation bug in its toNative method
that causes deny responses to be silently treated as success."
```

---

### Task 2: Replace seccomp.NotifRespond in handleFileNotification (non-emulated path)

This is the primary fix — the code path that handles O_WRONLY on existing files when Landlock is active and emulateOpen is false.

**Files:**
- Modify: `internal/netmonitor/unix/handler.go` — lines 376-447 (`handleFileNotification`)

There are 4 `seccomp.NotifRespond` calls in this function (lines 396, 408, 419, 446).

- [ ] **Step 1: Replace all 4 calls**

Replace line 394-397 (openat2 how read failure):
```go
// Before:
slog.Debug("file handler: failed to read open_how, allowing", "pid", pid, "error", err)
resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
_ = seccomp.NotifRespond(fd, &resp)

// After:
slog.Debug("file handler: failed to read open_how, allowing", "pid", pid, "error", err)
if err := NotifRespondContinue(int(fd), req.ID); err != nil {
    slog.Debug("file handler: continue response failed", "pid", pid, "error", err)
}
```

Replace line 406-409 (primary path resolve failure):
```go
// Before:
slog.Debug("file handler: failed to resolve path, allowing", "pid", pid, "error", err)
resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
_ = seccomp.NotifRespond(fd, &resp)

// After:
slog.Debug("file handler: failed to resolve path, allowing", "pid", pid, "error", err)
if err := NotifRespondContinue(int(fd), req.ID); err != nil {
    slog.Debug("file handler: continue response failed", "pid", pid, "error", err)
}
```

Replace line 417-420 (second path resolve failure):
```go
// Before:
slog.Debug("file handler: failed to resolve second path, allowing", "pid", pid, "error", err)
resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
_ = seccomp.NotifRespond(fd, &resp)

// After:
slog.Debug("file handler: failed to resolve second path, allowing", "pid", pid, "error", err)
if err := NotifRespondContinue(int(fd), req.ID); err != nil {
    slog.Debug("file handler: continue response failed", "pid", pid, "error", err)
}
```

Replace lines 440-446 (the main response — **the critical fix**):
```go
// Before:
resp := seccomp.ScmpNotifResp{ID: req.ID}
if result.Action == ActionDeny {
    resp.Error = -result.Errno
} else {
    resp.Flags = seccomp.NotifRespFlagContinue
}
_ = seccomp.NotifRespond(fd, &resp)

// After:
if result.Action == ActionDeny {
    if err := NotifRespondDeny(int(fd), req.ID, result.Errno); err != nil {
        slog.Error("file handler: deny response failed", "pid", pid, "path", path, "error", err)
    }
} else {
    if err := NotifRespondContinue(int(fd), req.ID); err != nil {
        slog.Debug("file handler: continue response failed", "pid", pid, "error", err)
    }
}
```

- [ ] **Step 2: Build to verify no compilation errors**

Run: `go build ./internal/netmonitor/unix/`
Expected: SUCCESS

- [ ] **Step 3: Run existing tests**

Run: `go test ./internal/netmonitor/unix/ -run TestFileHandler -v`
Expected: PASS (existing unit tests still pass)

- [ ] **Step 4: Commit**

```bash
git add internal/netmonitor/unix/handler.go
git commit -m "fix: use direct ioctl for deny responses in non-emulated file handler

Fixes openat(O_WRONLY) on existing files not being enforced.
The libseccomp-golang binding double-negates the error field,
turning -EACCES into +13 which the kernel treats as success."
```

---

### Task 3: Replace seccomp.NotifRespond in handleFileNotificationEmulated

**Files:**
- Modify: `internal/netmonitor/unix/handler.go` — lines 455-681 (`handleFileNotificationEmulated`)

There are 12 `seccomp.NotifRespond` calls across this function and its helper `emulateOpenat`. The pattern is identical to Task 2:
- Deny responses → `NotifRespondDeny(int(fd), req.ID, errno)` with `slog.Error` on failure
- Continue responses → `NotifRespondContinue(int(fd), req.ID)` with `slog.Debug` on failure

- [ ] **Step 1: Replace all calls in handleFileNotificationEmulated**

Apply the same substitution pattern to every `seccomp.NotifRespond` call in the function:
- Lines 475, 482: openat2 arg validation → Continue
- Lines 502, 507: path resolve failures → Continue or Deny based on `forceContinue`
- Lines 519, 524: second path resolve failures → Continue or Deny based on `forceContinue`
- Line 572: emulated deny → Deny
- Line 593: CONTINUE-path deny → Deny
- Line 607: CONTINUE-path allow → Continue
- Line 630: umask fallback → Continue
- Line 644: supervisor open failure → Deny (use the specific errno from the open failure, not EACCES)
- Line 678: AddFD failure → Deny (use the specific errno from the AddFD failure)

For the `emulateOpenat` sub-function (lines 614-681), the deny responses at lines 644 and 678 use variable errnos from actual failures, not policy denials. Use `NotifRespondDeny` with the actual errno:

```go
// Line 644 — supervisor open failed:
// Before:
resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(errno)}
_ = seccomp.NotifRespond(fd, &resp)
// After:
if err := NotifRespondDeny(int(fd), req.ID, int32(errno)); err != nil {
    slog.Debug("emulateOpenat: deny response failed", "pid", pid, "error", err)
}
```

- [ ] **Step 2: Build and test**

Run: `go build ./internal/netmonitor/unix/ && go test ./internal/netmonitor/unix/ -run TestFileHandler -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/netmonitor/unix/handler.go
git commit -m "fix: use direct ioctl for responses in emulated file handler"
```

---

### Task 4: Replace seccomp.NotifRespond in execve and unix socket handlers

**Files:**
- Modify: `internal/netmonitor/unix/handler.go` — `handleExecveNotification` (lines 259-371), `ServeNotifyWithExecve` (lines 156-254), `ServeNotify` (lines 30-88)

- [ ] **Step 1: Replace calls in handleExecveNotification (8 calls)**

Lines 288, 305, 322: fail-secure denials:
```go
if err := NotifRespondDeny(int(fd), req.ID, int32(unix.EACCES)); err != nil {
    slog.Error("execve handler: deny response failed", "pid", pid, "error", err)
}
```

Lines 346, 352: redirect failures:
```go
if err := NotifRespondDeny(int(fd), req.ID, int32(unix.EPERM)); err != nil {
    slog.Error("execve handler: deny response failed", "pid", pid, "error", err)
}
```

Line 358: redirect CONTINUE:
```go
if err := NotifRespondContinue(int(fd), req.ID); err != nil {
    slog.Debug("execve handler: continue response failed", "pid", pid, "error", err)
}
```

Line 363: policy deny:
```go
if err := NotifRespondDeny(int(fd), req.ID, result.Errno); err != nil {
    slog.Error("execve handler: deny response failed", "pid", pid, "cmd", ectx.Filename, "error", err)
}
```

Line 368: policy continue:
```go
if err := NotifRespondContinue(int(fd), req.ID); err != nil {
    slog.Debug("execve handler: continue response failed", "pid", pid, "error", err)
}
```

- [ ] **Step 2: Replace calls in ServeNotifyWithExecve main loop (3 calls)**

Line 220: non-handled syscall fallback → `NotifRespondContinue(int(scmpFD), req.ID)`
Line 226: no-policy unix socket fallback → `NotifRespondContinue(int(scmpFD), req.ID)`
Line 252: unix socket response → split into deny/continue like the file handler

For line 246-252 (unix socket response):
```go
// Before:
resp := seccomp.ScmpNotifResp{ID: req.ID}
if allow {
    resp.Flags = seccomp.NotifRespFlagContinue
} else {
    resp.Error = -errno
}
_ = seccomp.NotifRespond(scmpFD, &resp)

// After:
if allow {
    if err := NotifRespondContinue(int(scmpFD), req.ID); err != nil {
        slog.Debug("unix socket: continue response failed", "error", err)
    }
} else {
    if err := NotifRespondDeny(int(scmpFD), req.ID, errno); err != nil {
        slog.Error("unix socket: deny response failed", "path", path, "error", err)
    }
}
```

- [ ] **Step 3: Replace calls in ServeNotify (2 calls)**

Line 61: non-unix syscall → `NotifRespondContinue(int(scmpFD), req.ID)`
Line 86: unix socket response → split into deny/continue (same pattern as above)

- [ ] **Step 4: Build and run all tests**

Run: `go build ./internal/netmonitor/unix/ && go test ./internal/netmonitor/unix/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/handler.go
git commit -m "fix: use direct ioctl for responses in execve and unix socket handlers"
```

---

### Task 5: Replace Filter.Respond() in seccomp_linux.go

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go` — lines 130-141

- [ ] **Step 1: Replace Filter.Respond()**

```go
// Before (lines 130-141):
// Respond replies to a notification.
func (f *Filter) Respond(reqID uint64, allow bool, errno int32) error {
	resp := seccomp.ScmpNotifResp{ID: reqID}
	if allow {
		resp.Error = 0
		resp.Val = 0
		resp.Flags = seccomp.NotifRespFlagContinue
	} else {
		resp.Error = -errno
	}
	return seccomp.NotifRespond(f.fd, &resp)
}

// After:
// Respond replies to a notification.
func (f *Filter) Respond(reqID uint64, allow bool, errno int32) error {
	if allow {
		return NotifRespondContinue(int(f.fd), reqID)
	}
	return NotifRespondDeny(int(f.fd), reqID, errno)
}
```

- [ ] **Step 2: Build and run full test suite**

Run: `go build ./... && go test ./internal/netmonitor/unix/ -v`
Expected: PASS

- [ ] **Step 3: Verify no remaining seccomp.NotifRespond references**

Run: `grep -rn 'seccomp\.NotifRespond' internal/netmonitor/unix/`
Expected: No matches (only `seccomp.NotifReceive` should remain)

- [ ] **Step 4: Remove unused imports**

Run: `grep -n 'seccomp\.ScmpNotifResp\|seccomp\.NotifRespFlagContinue\|seccomp\.NotifRespond' internal/netmonitor/unix/handler.go internal/netmonitor/unix/seccomp_linux.go`

If no matches remain, these symbols are unused. The `seccomp` import itself is still needed for `seccomp.ScmpFd`, `seccomp.ScmpNotifReq`, `seccomp.NotifReceive`, etc. The Go compiler will error if any import becomes fully unused — fix as needed. Run `go build ./internal/netmonitor/unix/` to verify.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./... && GOOS=linux go build ./...`
Expected: PASS (build tags `linux && cgo` gate these files)

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go internal/netmonitor/unix/handler.go
git commit -m "fix: replace Filter.Respond with direct ioctl, remove seccomp.NotifRespond usage

All seccomp notification responses now bypass libseccomp-golang,
eliminating the double-negation bug in the deny path."
```
