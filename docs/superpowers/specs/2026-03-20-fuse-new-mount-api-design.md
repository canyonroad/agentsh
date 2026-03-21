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
3. `checkNewMountAPI()` → kernel >= 5.2 via uname, then `unix.Fsopen("fuse", 0)` as a probe (close immediately) → return `"new-api"`
4. `checkDirectMount()` → existing CAP_SYS_ADMIN + mount probe → return `"direct"`
5. Return `""` (unavailable)

`MountMethod() string` is exposed on the `Filesystem` struct for `agentsh detect` output.

### 2. New Mount API Implementation

**File:** `internal/platform/linux/filesystem.go`

New function `mountFUSEViaNewAPI(mountPoint string, opts *fuse.MountOptions) (fuseFD int, err error)`:

1. Open `/dev/fuse` → `fuseDev` fd
2. `unix.Fsopen("fuse", 0)` → `fsctx` fd
3. `unix.FsconfigSetString(fsctx, "fd", strconv.Itoa(fuseDev))`
4. `unix.FsconfigSetString(fsctx, "rootmode", "40000")` (directory)
5. `unix.FsconfigSetString(fsctx, "user_id", strconv.Itoa(os.Geteuid()))`
6. `unix.FsconfigSetString(fsctx, "group_id", strconv.Itoa(os.Getegid()))`
7. If `opts.AllowOther`: `unix.FsconfigSetFlag(fsctx, "allow_other")`
8. `unix.FsconfigCreate(fsctx)` — finalize the superblock
9. `unix.Fsmount(fsctx, 0, 0)` → `mntFD`
10. `unix.MoveMount(mntFD, "", unix.AT_FDCWD, mountPoint, unix.MOVE_MOUNT_F_EMPTY_PATH)`
11. Close `fsctx` and `mntFD` (no longer needed after move_mount)
12. Return `fuseDev` — this is the fd go-fuse will use

On any error, close all opened fds and return a descriptive error.

### 3. go-fuse Integration via /dev/fd/N

**File:** `internal/platform/linux/filesystem.go` (in `Filesystem.Mount()`)

When `mountMethod == "new-api"`:

1. Call `mountFUSEViaNewAPI(mountPoint, opts)` → get `fuseFD`
2. Pass `/dev/fd/<fuseFD>` as the mountpoint to go-fuse's `fs.Mount()` instead of the real mountpoint
3. go-fuse detects the `/dev/fd/N` magic path, uses the fd directly, skips its own mount logic

The existing `MountWorkspace` in `internal/fsmonitor/mount.go` receives either the real path (fusermount/direct) or `/dev/fd/N` (new API). From go-fuse's perspective, `/dev/fd/N` is a pre-mounted FUSE connection — it reads/writes the FUSE protocol on it directly.

For fusermount and direct mount paths, the flow is unchanged — the real mountpoint is passed through.

**Unmount**: `unix.Unmount(mountPoint, 0)` works normally since `move_mount` created a real VFS mount entry. go-fuse's `server.Unmount()` handles this.

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
2. `TestCheckNewMountAPI_KernelVersion` — verify kernel >= 5.2 detection via `parseKernelVersion`.
3. `TestMountFUSEViaNewAPI_FsopenProbe` — if kernel >= 5.2, verify `unix.Fsopen("fuse", 0)` succeeds. Skip on older kernels.

**Integration test** (requires Docker with `--device /dev/fuse`):

4. Full mount cycle: `mountFUSEViaNewAPI` → verify in `/proc/mounts` → write through mount → `unix.Unmount` → verify clean teardown. Only when `/dev/fuse` available and kernel >= 5.2.

## Fallback Chain Summary

| Priority | Method | Requirements | Works on Firecracker |
|----------|--------|-------------|---------------------|
| 1 | fusermount3/fusermount | suid binary in PATH | Yes (if installed) |
| 2 | New mount API | Kernel >= 5.2, /dev/fuse | Yes |
| 3 | Direct mount() | CAP_SYS_ADMIN, no seccomp block | No (hangs) |

## Dependencies

- `golang.org/x/sys v0.40.0` (already in go.mod) — provides `Fsopen`, `FsconfigSetString`, `FsconfigSetFlag`, `FsconfigCreate`, `Fsmount`, `MoveMount`
- `github.com/hanwen/go-fuse/v2 v2.9.0` (already in go.mod) — `/dev/fd/N` magic mountpoint support
- Linux 5.2+ for the new mount API syscalls

## Out of Scope

- Removing the legacy mount() fallback — it still works on non-Firecracker environments
- Configurable mount method selection — auto-detection is sufficient
- macOS/Windows changes — this is Linux-only
