# FUSE New Mount API Fallback

**Date:** 2026-03-20
**Status:** Draft
**Scope:** Linux only

## Background

On Cloudflare Firecracker VMs, the traditional `mount()` syscall hangs. This is not a seccomp issue (there is no seccomp filter in the guest) — it appears to be a Firecracker virtio/kernel-level issue specific to the `mount()` syscall.

The existing `probeMountSyscall()` in agentsh detects this (500ms timeout → returns false), but when fusermount is also unavailable, FUSE is reported as unavailable — even though `/dev/fuse` opens fine and the kernel supports FUSE.

The Linux new mount API (kernel 5.2+) works perfectly in these environments: `fsopen`, `fsconfig`, `fsmount`, and `move_mount` all succeed. This design adds the new mount API as a fallback between fusermount and legacy mount().

## What Changes

### 1. Detection — Mount Method Selection

**File:** `internal/platform/linux/filesystem.go`

The `Filesystem` struct gets a new field `mountMethod string` recording which mount path is available:

- `"fusermount"` — fusermount3/fusermount suid binary found
- `"new-api"` — kernel >= 5.2, `/dev/fuse` opens, `fsopen("fuse")` succeeds
- `"direct"` — CAP_SYS_ADMIN + mount() probe passes
- `""` — nothing works (FUSE unavailable)

`canMountFUSE()` becomes `detectMountMethod() string` and tries each in order:

1. `/dev/fuse` open check (shared prerequisite — if this fails, all paths fail)
2. `hasFusermount()` → return `"fusermount"`
3. `checkNewMountAPI()` → try `unix.Fsopen("fuse", 0)` as a probe (close immediately). If ENOSYS, the kernel doesn't support the new mount API; if ENODEV, the fuse module isn't loaded. On success → return `"new-api"`. No kernel version parsing needed — `fsopen` is the ground truth.
4. `checkDirectMount()` → existing CAP_SYS_ADMIN + mount probe → return `"direct"`
5. Return `""` (unavailable)

`MountMethod() string` is exposed on the `Filesystem` struct for `agentsh detect` output.

**Recheck()**: `Recheck()` must also re-detect and store `mountMethod` (not just `available`), since deferred FUSE detection (E2B sandbox case) may discover a new mount method after startup.

**Logging**: `detectMountMethod` logs at info level which method was selected, and at debug level which methods were tried and why they failed. This is critical for debugging Firecracker environments.

**`checkFUSE()` in `security_caps.go`**: The parallel `checkFUSE()` in `internal/capabilities/security_caps.go` must delegate to the same detection logic (or call `Filesystem.MountMethod() != ""`), so that `agentsh detect` correctly reports `fuse: true` when the new-api path is available.

### 2. New Mount API Implementation

**File:** `internal/platform/linux/filesystem.go`

New function `mountFUSEViaNewAPI(mountPoint string, opts *fuse.MountOptions) (fuseFD int, err error)`:

1. Open `/dev/fuse` with `O_RDWR|O_CLOEXEC` → `fuseDev` fd
2. `unix.Fsopen("fuse", 0)` → `fsctx` fd
3. `unix.FsconfigSetString(fsctx, "fd", strconv.Itoa(fuseDev))`
4. `unix.FsconfigSetString(fsctx, "rootmode", "40000")` (directory)
5. `unix.FsconfigSetString(fsctx, "user_id", strconv.Itoa(os.Geteuid()))`
6. `unix.FsconfigSetString(fsctx, "group_id", strconv.Itoa(os.Getegid()))`
7. `unix.FsconfigSetString(fsctx, "max_read", strconv.Itoa(opts.MaxWrite))` — match go-fuse's behavior
8. If `opts.AllowOther`: `unix.FsconfigSetFlag(fsctx, "allow_other")`
9. `unix.FsconfigCreate(fsctx)` — finalize the superblock
10. `unix.Fsmount(fsctx, 0, 0)` → `mntFD`
11. Close `fsctx` (no longer needed after fsmount)
12. `unix.MoveMount(mntFD, "", unix.AT_FDCWD, mountPoint, unix.MOVE_MOUNT_F_EMPTY_PATH)`
13. Close `mntFD` (no longer needed after move_mount)
14. Return `fuseDev` — this is the fd go-fuse will use

**Error cleanup sequence**: Each step checks the previous step's error. On failure, close fds in reverse order of opening: `mntFD` (if opened), `fsctx` (if opened), `fuseDev` (if opened). Use `defer` with a success flag to ensure no fd leaks on any partial failure path.

**O_CLOEXEC**: The `fuseDev` fd is opened with `O_CLOEXEC` (Go's `unix.Open` sets this by default). This matches go-fuse's behavior with fusermount. The fd is returned to go-fuse and must survive for the lifetime of the FUSE connection but not leak across exec.

### 3. go-fuse Integration via /dev/fd/N

**File:** `internal/platform/linux/filesystem.go` (in `Filesystem.Mount()`)

When `mountMethod == "new-api"`:

1. Call `mountFUSEViaNewAPI(mountPoint, opts)` → get `fuseFD`
2. Store the real `mountPoint` for later unmount and logging
3. Pass `/dev/fd/<fuseFD>` as the mountpoint to go-fuse's `fs.Mount()` instead of the real mountpoint
4. go-fuse detects the `/dev/fd/N` magic path, uses the fd directly, skips its own mount logic

The existing `MountWorkspace` in `internal/fsmonitor/mount.go` receives either the real path (fusermount/direct) or `/dev/fd/N` (new API). From go-fuse's perspective, `/dev/fd/N` is a pre-mounted FUSE connection — it reads/writes the FUSE protocol on it directly.

**Real mountpoint preservation**: The `Mount` struct returned by `MountWorkspace` stores `mountPoint`. When the new-api path is used, the caller must ensure the *real* mountpoint (not `/dev/fd/N`) is stored for display, logging, `/proc/mounts` lookups, and unmount. This is done at the `Filesystem.Mount()` level — it passes `/dev/fd/N` to go-fuse but stores the real path in the returned `FSMount`.

For fusermount and direct mount paths, the flow is unchanged — the real mountpoint is passed through.

**Unmount**: go-fuse's `Server.Unmount()` refuses to unmount `/dev/fd/N` magic mountpoints (returns an error). For the new-api path, unmount is performed by calling `unix.Unmount(realMountPoint, 0)` directly, bypassing `Server.Unmount()`. The `Filesystem.Unmount()` method checks the mount method and dispatches accordingly:
- fusermount/direct: `server.Unmount()` (existing path)
- new-api: `unix.Unmount(realMountPoint, 0)` + close the FUSE fd

### 4. Detection Output

**Files:** `internal/capabilities/detect_linux.go`, `internal/cli/detect.go`

Add `fuse_mount_method` to the capabilities map:

```
caps["fuse_mount_method"] = "fusermount" | "new-api" | "direct" | "none"
```

Derived from `Filesystem.MountMethod()`. The existing `fuse: true/false` capability is unchanged; `fuse_mount_method` is a companion field providing detail.

**No config changes.** The mount method is auto-detected, not configurable.

### 5. Testing

**Unit tests** in `internal/platform/linux/filesystem_test.go`:

1. `TestDetectMountMethod` — verify the function returns a valid method string on the current system.
2. `TestCheckNewMountAPI_FsopenProbe` — verify `unix.Fsopen("fuse", 0)` succeeds on kernels that support it. Skip if ENOSYS.
3. `TestMountFUSEViaNewAPI_ErrorCleanup` — verify that partial failures (e.g., fsconfig error) close all fds without leaking.

**Integration test** (requires Docker with `--device /dev/fuse`):

4. Full mount cycle: `mountFUSEViaNewAPI` → verify in `/proc/mounts` → write through mount → `unix.Unmount` → verify clean teardown. Only when `/dev/fuse` available and kernel >= 5.2.

## Fallback Chain Summary

| Priority | Method | Requirements | Works on Firecracker |
|----------|--------|-------------|---------------------|
| 1 | fusermount3/fusermount | suid binary in PATH | Yes (if installed) |
| 2 | New mount API | /dev/fuse, fsopen succeeds | Yes |
| 3 | Direct mount() | CAP_SYS_ADMIN, no seccomp block | No (hangs) |

## Dependencies

- `golang.org/x/sys v0.40.0` (already in go.mod) — provides `Fsopen`, `FsconfigSetString`, `FsconfigSetFlag`, `FsconfigCreate`, `Fsmount`, `MoveMount`
- `github.com/hanwen/go-fuse/v2 v2.9.0` (already in go.mod) — `/dev/fd/N` magic mountpoint support
- Linux 5.2+ for the new mount API syscalls (detected at runtime via `fsopen` probe, not version parsing)

## Out of Scope

- Removing the legacy mount() fallback — it still works on non-Firecracker environments
- Configurable mount method selection — auto-detection is sufficient
- macOS/Windows changes — this is Linux-only
