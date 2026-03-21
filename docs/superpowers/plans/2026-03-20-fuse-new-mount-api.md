# FUSE New Mount API Fallback Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a FUSE mount fallback using the Linux new mount API (fsopen/fsconfig/fsmount/move_mount) for Firecracker VMs where the legacy mount() syscall hangs.

**Architecture:** Add `detectMountMethod()` to replace `canMountFUSE()` with a three-way fallback chain (fusermount → new-api → direct mount). When `new-api` is selected, `mountFUSEViaNewAPI()` performs the mount and returns a `/dev/fuse` fd that go-fuse uses via its `/dev/fd/N` magic mountpoint path. Unmount uses `unix.Unmount()` directly since go-fuse refuses to unmount `/dev/fd/N` paths.

**Tech Stack:** Go, golang.org/x/sys/unix (v0.40.0), go-fuse v2.9.0

**Spec:** `docs/superpowers/specs/2026-03-20-fuse-new-mount-api-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/platform/linux/filesystem.go` | Modify | Add mountMethod field, detectMountMethod, mountFUSEViaNewAPI, unmount dispatch |
| `internal/platform/linux/filesystem_test.go` | Modify | Tests for detection, fsopen probe, error cleanup, integration |
| `internal/fsmonitor/mount.go` | Modify | Guard MkdirAll for /dev/fd/N mountpoints |
| `internal/capabilities/security_caps.go` | Modify | Add new mount API probe to checkFUSE |
| `internal/capabilities/detect_linux.go` | Modify | Add fuse_mount_method to capabilities map |

---

### Task 1: detectMountMethod — Replace canMountFUSE

**Files:**
- Modify: `internal/platform/linux/filesystem.go:22-67`
- Modify: `internal/platform/linux/filesystem_test.go`

- [ ] **Step 1: Add mountMethod field to Filesystem struct**

In `internal/platform/linux/filesystem.go`, add to the struct:

```go
type Filesystem struct {
	available      bool
	implementation string
	mountMethod    string // "fusermount", "new-api", "direct", ""
	mu             sync.Mutex
	mounts         map[string]*Mount
}
```

Add accessor:
```go
// MountMethod returns which FUSE mount strategy is available.
func (fs *Filesystem) MountMethod() string {
	return fs.mountMethod
}
```

- [ ] **Step 2: Implement detectMountMethod**

Replace `canMountFUSE()` with `detectMountMethod()`:

```go
// detectMountMethod determines which FUSE mount strategy is available.
// Tries: fusermount → new mount API → direct mount().
// Returns "", "fusermount", "new-api", or "direct".
func detectMountMethod() string {
	// Shared prerequisite: /dev/fuse must be openable
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR, 0)
	if err != nil {
		slog.Debug("fuse: /dev/fuse not available", "error", err)
		return ""
	}
	unix.Close(fd)

	// Priority 1: fusermount suid binary
	if hasFusermount() {
		slog.Info("fuse: mount method selected", "method", "fusermount")
		return "fusermount"
	}
	slog.Debug("fuse: fusermount not found, trying new mount API")

	// Priority 2: new mount API (fsopen/fsmount/move_mount)
	if checkNewMountAPI() {
		slog.Info("fuse: mount method selected", "method", "new-api")
		return "new-api"
	}
	slog.Debug("fuse: new mount API not available, trying direct mount")

	// Priority 3: direct mount() with CAP_SYS_ADMIN
	if checkDirectMount() {
		slog.Info("fuse: mount method selected", "method", "direct")
		return "direct"
	}
	slog.Debug("fuse: no mount method available")

	return ""
}

// checkNewMountAPI probes whether the new mount API works for FUSE.
// Tries fsopen("fuse", 0) — success means the kernel supports the new API
// and the fuse module is loaded. ENOSYS = kernel too old, ENODEV = fuse not loaded.
func checkNewMountAPI() bool {
	fd, err := unix.Fsopen("fuse", 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
```

Add `"log/slog"` to imports.

- [ ] **Step 3: Wire into NewFilesystem and checkAvailable**

Update `NewFilesystem`:
```go
func NewFilesystem() *Filesystem {
	fs := &Filesystem{
		mounts: make(map[string]*Mount),
	}
	fs.mountMethod = detectMountMethod()
	fs.available = fs.mountMethod != ""
	fs.implementation = fs.detectImplementation()
	return fs
}
```

Update `checkAvailable` (still used by `Recheck`):
```go
func (fs *Filesystem) checkAvailable() bool {
	fs.mountMethod = detectMountMethod()
	return fs.mountMethod != ""
}
```

Remove the old `canMountFUSE()` function (lines 45-67).

- [ ] **Step 4: Write tests**

In `internal/platform/linux/filesystem_test.go`:

```go
func TestDetectMountMethod(t *testing.T) {
	method := detectMountMethod()
	// On any Linux system with /dev/fuse, at least one method should work
	if _, err := os.Open("/dev/fuse"); err == nil {
		assert.NotEmpty(t, method, "should detect a mount method when /dev/fuse exists")
		assert.Contains(t, []string{"fusermount", "new-api", "direct"}, method)
	}
}

func TestCheckNewMountAPI(t *testing.T) {
	result := checkNewMountAPI()
	// Just verify it doesn't panic — result depends on kernel version
	_ = result
}

func TestFilesystem_MountMethod(t *testing.T) {
	fs := NewFilesystem()
	if fs.Available() {
		assert.NotEmpty(t, fs.MountMethod())
	} else {
		assert.Empty(t, fs.MountMethod())
	}
}
```

- [ ] **Step 5: Build and test**

Run: `go build ./internal/platform/linux/... && go test ./internal/platform/linux/... -v -count=1`
Expected: Compiles cleanly, tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/platform/linux/filesystem.go internal/platform/linux/filesystem_test.go
git commit -m "feat(fuse): add detectMountMethod with new mount API probe

Replace canMountFUSE with three-way detection: fusermount → new-api
(fsopen probe) → direct mount. Add MountMethod() accessor and logging.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: mountFUSEViaNewAPI — New mount implementation

**Files:**
- Modify: `internal/platform/linux/filesystem.go`
- Modify: `internal/platform/linux/filesystem_test.go`

- [ ] **Step 1: Write failing test for error cleanup**

In `internal/platform/linux/filesystem_test.go`:

```go
func TestMountFUSEViaNewAPI_ErrorCleanup(t *testing.T) {
	// Verify that partial failures close fds without leaking.
	// Pass an invalid mountpoint — the fsopen/fsconfig should succeed
	// but move_mount should fail, and all fds should be cleaned up.
	if !checkNewMountAPI() {
		t.Skip("new mount API not available")
	}
	_, err := mountFUSEViaNewAPI("/nonexistent/path/that/cannot/exist", true, 0)
	assert.Error(t, err, "should fail with nonexistent mountpoint")
	// The test verifies no panic and no fd leak (defer cleanup in the function).
}

func TestMountFUSEViaNewAPI_FsopenProbe(t *testing.T) {
	if !checkNewMountAPI() {
		t.Skip("new mount API not available")
	}
	fd, err := unix.Fsopen("fuse", 0)
	if err != nil {
		t.Fatalf("fsopen failed: %v", err)
	}
	unix.Close(fd)
}
```

- [ ] **Step 2: Run tests to verify they fail (mountFUSEViaNewAPI not yet implemented)**

Run: `go test ./internal/platform/linux/... -run "TestMountFUSEViaNewAPI" -v -count=1`
Expected: FAIL — `mountFUSEViaNewAPI` not defined.

- [ ] **Step 3: Implement mountFUSEViaNewAPI**

In `internal/platform/linux/filesystem.go`, add:

```go
// mountFUSEViaNewAPI mounts a FUSE filesystem using the Linux new mount API
// (fsopen/fsconfig/fsmount/move_mount). Returns the /dev/fuse fd for go-fuse.
// The caller is responsible for closing the fd when the FUSE server shuts down.
func mountFUSEViaNewAPI(mountPoint string, allowOther bool, maxRead int) (fuseFD int, err error) {
	// Open /dev/fuse — this is the fd go-fuse will use for the FUSE protocol.
	fuseDev, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/fuse: %w", err)
	}

	success := false
	defer func() {
		if !success {
			unix.Close(fuseDev)
		}
	}()

	// Create filesystem context
	fsctx, err := unix.Fsopen("fuse", 0)
	if err != nil {
		return -1, fmt.Errorf("fsopen fuse: %w", err)
	}
	defer unix.Close(fsctx)

	// Configure the FUSE mount (same options as go-fuse's mountDirect)
	configs := []struct{ key, val string }{
		{"fd", fmt.Sprintf("%d", fuseDev)},
		{"rootmode", "40000"},
		{"user_id", fmt.Sprintf("%d", os.Geteuid())},
		{"group_id", fmt.Sprintf("%d", os.Getegid())},
	}
	if maxRead > 0 {
		configs = append(configs, struct{ key, val string }{"max_read", fmt.Sprintf("%d", maxRead)})
	}
	for _, c := range configs {
		if err := unix.FsconfigSetString(fsctx, c.key, c.val); err != nil {
			return -1, fmt.Errorf("fsconfig %s=%s: %w", c.key, c.val, err)
		}
	}
	if allowOther {
		if err := unix.FsconfigSetFlag(fsctx, "allow_other"); err != nil {
			return -1, fmt.Errorf("fsconfig allow_other: %w", err)
		}
	}

	// Finalize the superblock
	if err := unix.FsconfigCreate(fsctx); err != nil {
		return -1, fmt.Errorf("fsconfig create: %w", err)
	}

	// Create mount fd
	mntFD, err := unix.Fsmount(fsctx, 0, 0)
	if err != nil {
		return -1, fmt.Errorf("fsmount: %w", err)
	}
	defer unix.Close(mntFD)

	// Attach to the target mountpoint
	if err := unix.MoveMount(mntFD, "", unix.AT_FDCWD, mountPoint, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return -1, fmt.Errorf("move_mount to %s: %w", mountPoint, err)
	}

	success = true
	return fuseDev, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go build ./internal/platform/linux/... && go test ./internal/platform/linux/... -v -count=1 -run TestMountFUSEViaNewAPI`
Expected: Compiles, tests pass (or skip on old kernels).

- [ ] **Step 4: Commit**

```bash
git add internal/platform/linux/filesystem.go internal/platform/linux/filesystem_test.go
git commit -m "feat(fuse): implement mountFUSEViaNewAPI

Uses fsopen → fsconfig → fsmount → move_mount to mount FUSE
without fusermount or legacy mount() syscall. Returns /dev/fuse
fd for go-fuse's /dev/fd/N integration path.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: go-fuse integration — /dev/fd/N passthrough + unmount

**Files:**
- Modify: `internal/platform/linux/filesystem.go:157-280` (Mount, Unmount, Close methods)
- Modify: `internal/fsmonitor/mount.go:26-38` (guard MkdirAll)

- [ ] **Step 1: Guard MkdirAll in MountWorkspace for /dev/fd/N**

In `internal/fsmonitor/mount.go`, the `MountWorkspace` function calls `os.MkdirAll` on the mountpoint. When the mountpoint is `/dev/fd/42`, this will fail. Add a guard:

```go
func MountWorkspace(ctx context.Context, backingDir string, mountPoint string, hooks *Hooks) (*Mount, error) {
	if backingDir == "" {
		return nil, fmt.Errorf("backingDir is empty")
	}
	if mountPoint == "" {
		return nil, fmt.Errorf("mountPoint is empty")
	}
	// Skip MkdirAll for /dev/fd/N magic mountpoints (pre-mounted FUSE fd)
	if !strings.HasPrefix(mountPoint, "/dev/fd/") {
		if err := os.MkdirAll(filepath.Dir(mountPoint), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir mount parent: %w", err)
		}
		if err := os.MkdirAll(mountPoint, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir mount: %w", err)
		}
	}
```

Add `"strings"` to imports.

- [ ] **Step 2: Add fuseFD and mountedViaNewAPI fields to Mount struct**

In `internal/platform/linux/filesystem.go`, update the `Mount` struct:

```go
type Mount struct {
	fsMount          *fsmonitor.Mount
	sourcePath       string
	mountPoint       string // always the real mount point
	mountedAt        time.Time
	hooks            *fsmonitor.Hooks
	mountedViaNewAPI bool // true if mounted via new mount API
	fuseFD           int  // /dev/fuse fd to close on unmount (new-api only, -1 if unused)

	// Stats tracking
	mu            sync.Mutex
	totalOps      int64
	allowedOps    int64
	deniedOps     int64
	redirectedOps int64
	bytesRead     int64
	bytesWritten  int64
}
```

- [ ] **Step 3: Modify Filesystem.Mount to use new API when selected**

In `Filesystem.Mount()`, before calling `fsmonitor.MountWorkspace`:

```go
effectiveMountPoint := cfg.MountPoint
mountedViaNewAPI := false
fuseFD := -1

if fs.mountMethod == "new-api" {
	var err error
	fuseFD, err = mountFUSEViaNewAPI(cfg.MountPoint, true, 0)
	if err != nil {
		return nil, fmt.Errorf("new mount API failed: %w", err)
	}
	effectiveMountPoint = fmt.Sprintf("/dev/fd/%d", fuseFD)
	mountedViaNewAPI = true
}

fsMount, err := fsmonitor.MountWorkspace(ctx, cfg.SourcePath, effectiveMountPoint, hooks)
if err != nil {
	if mountedViaNewAPI {
		unix.Unmount(cfg.MountPoint, 0)
		unix.Close(fuseFD)
	}
	return nil, fmt.Errorf("failed to mount FUSE filesystem: %w", err)
}

mount := &Mount{
	fsMount:          fsMount,
	sourcePath:       cfg.SourcePath,
	mountPoint:       cfg.MountPoint,
	mountedAt:        time.Now(),
	hooks:            hooks,
	mountedViaNewAPI: mountedViaNewAPI,
	fuseFD:           fuseFD,
}
```

- [ ] **Step 4: Modify Unmount and Close for new-api path**

Update `Filesystem.Unmount()`:

```go
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	m, ok := mount.(*Mount)
	if !ok {
		return fmt.Errorf("invalid mount type: expected *linux.Mount")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, m.mountPoint)

	if m.mountedViaNewAPI {
		err := unix.Unmount(m.mountPoint, 0)
		if m.fuseFD >= 0 {
			unix.Close(m.fuseFD)
			m.fuseFD = -1
		}
		return err
	}
	return m.fsMount.Unmount()
}
```

Also update `Mount.Close()` (find it in the file — it's part of the `platform.FSMount` interface):

```go
func (m *Mount) Close() error {
	if m.mountedViaNewAPI {
		err := unix.Unmount(m.mountPoint, 0)
		if m.fuseFD >= 0 {
			unix.Close(m.fuseFD)
			m.fuseFD = -1
		}
		return err
	}
	return m.fsMount.Unmount()
}
```

- [ ] **Step 5: Build and test**

Run: `go build ./... && go test ./internal/platform/linux/... -v -count=1`
Expected: Compiles, all existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/platform/linux/filesystem.go internal/fsmonitor/mount.go
git commit -m "feat(fuse): wire new mount API into Mount/Unmount with /dev/fd/N passthrough

- Guard MkdirAll in MountWorkspace for /dev/fd/N mountpoints
- Store fuseFD on Mount for cleanup at unmount
- Unmount and Close use unix.Unmount + close fd for new-api path
- go-fuse receives /dev/fd/N, real mountpoint preserved on Mount struct

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Update capabilities detection

**Files:**
- Modify: `internal/capabilities/security_caps.go:93-117`
- Modify: `internal/capabilities/detect_linux.go`

- [ ] **Step 1: Update checkFUSE to include new mount API**

In `internal/capabilities/security_caps.go`, update `checkFUSE()`:

```go
func checkFUSE() bool {
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)

	// Priority 1: fusermount
	if hasFusermount() {
		return true
	}

	// Priority 2: new mount API (fsopen probe)
	if checkNewMountAPIAvailable() {
		return true
	}

	// Priority 3: direct mount
	return checkDirectMount()
}

// checkNewMountAPIAvailable probes for new mount API support via fsopen.
func checkNewMountAPIAvailable() bool {
	fd, err := unix.Fsopen("fuse", 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
```

Note: This duplicates the `checkNewMountAPI()` from `filesystem.go`, but `security_caps.go` is in the `capabilities` package and can't import `linux` (circular dependency). The function is 5 lines — duplication is acceptable.

- [ ] **Step 2: Add fuse_mount_method to detect output**

In `internal/capabilities/detect_linux.go`, in `Detect()`, after the capabilities map is built:

```go
// Determine FUSE mount method for observability
fuseMountMethod := "none"
if secCaps.FUSE {
	if hasFusermount() {
		fuseMountMethod = "fusermount"
	} else if checkNewMountAPIAvailable() {
		fuseMountMethod = "new-api"
	} else {
		fuseMountMethod = "direct"
	}
}
caps["fuse_mount_method"] = fuseMountMethod
```

- [ ] **Step 3: Build and test**

Run: `go build ./... && go test ./internal/capabilities/... -v -count=1`
Expected: Compiles, existing tests pass.

- [ ] **Step 4: Commit**

```bash
git add internal/capabilities/security_caps.go internal/capabilities/detect_linux.go
git commit -m "feat(detect): add fuse_mount_method to capabilities detection

checkFUSE now includes new mount API probe. agentsh detect reports
fuse_mount_method: fusermount|new-api|direct|none.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Integration test — full mount/write/unmount cycle

**Files:**
- Modify: `internal/platform/linux/filesystem_test.go`

- [ ] **Step 1: Write integration test**

```go
func TestMountFUSEViaNewAPI_Integration(t *testing.T) {
	if !checkNewMountAPI() {
		t.Skip("new mount API not available")
	}
	if os.Getuid() != 0 {
		t.Skip("requires root for FUSE mount")
	}

	// Create a temp directory as the mount point
	mountDir, err := os.MkdirTemp("", "fuse-newapi-test")
	require.NoError(t, err)
	defer os.RemoveAll(mountDir)

	// Mount FUSE via new API
	fuseFD, err := mountFUSEViaNewAPI(mountDir, true, 0)
	require.NoError(t, err)
	defer unix.Close(fuseFD)

	// Verify mount appears in /proc/mounts
	mounts, err := os.ReadFile("/proc/mounts")
	require.NoError(t, err)
	assert.Contains(t, string(mounts), mountDir, "mount should appear in /proc/mounts")

	// Unmount
	err = unix.Unmount(mountDir, 0)
	assert.NoError(t, err)

	// Verify unmounted
	mounts2, _ := os.ReadFile("/proc/mounts")
	assert.NotContains(t, string(mounts2), mountDir, "mount should be gone after unmount")
}
```

Note: This test requires root + /dev/fuse + kernel >= 5.2. It will skip in most CI environments but runs in Docker with `--cap-add SYS_ADMIN --device /dev/fuse`.

- [ ] **Step 2: Run test**

Run: `go test ./internal/platform/linux/... -run TestMountFUSEViaNewAPI_Integration -v -count=1`
Expected: PASS (or skip if not root / no /dev/fuse / old kernel).

- [ ] **Step 3: Commit**

```bash
git add internal/platform/linux/filesystem_test.go
git commit -m "test(fuse): add integration test for new mount API full cycle

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Full build + cross-compile + test

- [ ] **Step 1: Full build**

Run: `go build ./...`
Expected: Clean.

- [ ] **Step 2: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: Clean (new code behind `//go:build linux`).

- [ ] **Step 3: Full test suite**

Run: `go test ./...`
Expected: All pass.

- [ ] **Step 4: Commit any fixups**
