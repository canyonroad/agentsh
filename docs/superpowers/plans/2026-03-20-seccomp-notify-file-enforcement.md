# Seccomp-Notify File Enforcement Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a seccomp user-notify file enforcement backend that eliminates TOCTOU races for openat via AddFD emulation and intercepts metadata syscalls, providing kernel-enforced file_rules when neither FUSE nor Landlock is available.

**Architecture:** Extend the existing seccomp file monitoring path (FileHandler + handleFileNotification) with an emulation mode. When emulateOpen is true, the supervisor opens files itself and injects fds via SECCOMP_IOCTL_NOTIF_ADDFD. Non-fd-returning syscalls use CONTINUE with ID validation bracketing. Backend selection is auto-detected at runtime.

**Tech Stack:** Go, libseccomp-golang (CGO), Linux seccomp user notification, golang.org/x/sys/unix

**Spec:** `docs/superpowers/specs/2026-03-20-seccomp-notify-file-enforcement-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/config/config.go` | Modify | Add 3 new fields to SandboxSeccompFileMonitorConfig, defaults |
| `internal/netmonitor/unix/seccomp_linux.go` | Modify | Add FilterConfig fields, metadata syscalls to BPF, io_uring blocking |
| `internal/netmonitor/unix/file_syscalls.go` | Modify | Add 5 new syscalls to isFileSyscall, extractFileArgs, syscallToOperation |
| `internal/netmonitor/unix/file_syscalls_test.go` | Modify | Tests for new syscalls |
| `internal/netmonitor/unix/addfd_linux.go` | Modify | Add NotifIDValid helper |
| `internal/netmonitor/unix/addfd_linux_test.go` | Modify | Tests for NotifIDValid |
| `internal/netmonitor/unix/file_handler.go` | Modify | Add emulateOpen field, resolveProcFD, /proc/self/fd/N interception |
| `internal/netmonitor/unix/file_handler_test.go` | Modify | Tests for procfd resolution, emulation mode |
| `internal/netmonitor/unix/handler.go` | Modify | Add handleFileNotificationEmulated, execve file_rules, ID validation |
| `internal/netmonitor/unix/handler_test.go` | Modify | Tests for routing new syscalls, execve+file_rules |
| `internal/api/file_monitor_linux.go` | Modify | Wire emulateOpen based on capabilities |
| `internal/api/core.go` | Modify | Bridge new config fields to seccompWrapperConfig + FilterConfig |
| `internal/capabilities/detect_linux.go` | Modify | Add detectFileEnforcementBackend |
| `internal/capabilities/security_caps.go` | Modify | Add FileEnforcement field |
| `internal/cli/detect.go` | Modify | Render file_enforcement in output |
| `cmd/agentsh-unixwrap/config.go` | Modify | Add new fields to WrapperConfig |
| `internal/netmonitor/unix/file_syscalls_legacy_amd64.go` | Modify | Add isLegacyOpenSyscallNr |
| `internal/netmonitor/unix/file_syscalls_legacy_other.go` | Modify | Add isLegacyOpenSyscallNr stub |
| `internal/netmonitor/unix/mount_registry.go` | Modify | Add HasAnyMounts method |

---

### Task 1: Config — Add new SandboxSeccompFileMonitorConfig fields

**Files:**
- Modify: `internal/config/config.go:490-494`

- [ ] **Step 1: Add three new fields to the config struct**

In `internal/config/config.go`, find the struct at line 491 and add:

```go
type SandboxSeccompFileMonitorConfig struct {
	Enabled            bool  `yaml:"enabled"`
	EnforceWithoutFUSE bool  `yaml:"enforce_without_fuse"`
	InterceptMetadata  *bool `yaml:"intercept_metadata"`
	OpenatEmulation    *bool `yaml:"openat_emulation"`
	BlockIOUring       *bool `yaml:"block_io_uring"`
}
```

Add helper for reading these pointer fields with defaults:

```go
// fileMonitorBoolWithDefault returns the value of a *bool field, or defaultVal if nil.
func fileMonitorBoolWithDefault(v *bool, defaultVal bool) bool {
	if v != nil {
		return *v
	}
	return defaultVal
}
```

- [ ] **Step 2: Add defaults in applyDefaultsWithSource**

In `internal/config/config.go`, find `applyDefaultsWithSource`. The defaults are applied at read-time, not at load-time, since `*bool` distinguishes nil (unset) from `false` (explicit). No changes needed in `applyDefaultsWithSource` — the `fileMonitorBoolWithDefault` helper is called at the point of use (e.g., when building FilterConfig or creating the FileHandler).

The default logic:
- When `enforce_without_fuse` is true: defaults are `true` (enforcement mode)
- When `enforce_without_fuse` is false: defaults are `false` (audit mode)

Callers use:
```go
defaultVal := cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE
interceptMetadata := fileMonitorBoolWithDefault(cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata, defaultVal)
```

- [ ] **Step 3: Build to verify**

Run: `go build ./internal/config/...`
Expected: Compiles cleanly.

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add seccomp file monitor enforcement fields

Add intercept_metadata, openat_emulation, block_io_uring to
SandboxSeccompFileMonitorConfig. All default to true when
enforce_without_fuse is enabled."
```

---

### Task 2: Config bridge — WrapperConfig + FilterConfig

**Files:**
- Modify: `cmd/agentsh-unixwrap/config.go`
- Modify: `internal/netmonitor/unix/seccomp_linux.go:173-186`
- Modify: `internal/api/core.go` (setupSeccompWrapper)

- [ ] **Step 1: Add fields to WrapperConfig**

In `cmd/agentsh-unixwrap/config.go`, add to `WrapperConfig`:

```go
InterceptMetadata bool `json:"intercept_metadata,omitempty"`
BlockIOUring      bool `json:"block_io_uring,omitempty"`
```

Note: `OpenatEmulation` is NOT passed to the wrapper — it controls supervisor-side behavior in `createFileHandler`, not the child-side BPF filter.

- [ ] **Step 2: Add fields to FilterConfig**

In `internal/netmonitor/unix/seccomp_linux.go`, add to `FilterConfig` (line 173):

```go
type FilterConfig struct {
	UnixSocketEnabled  bool
	ExecveEnabled      bool
	FileMonitorEnabled bool
	InterceptMetadata  bool // statx, newfstatat, faccessat2, readlinkat
	BlockIOUring       bool // io_uring_setup/enter/register → EPERM
	BlockedSyscalls    []int
}
```

- [ ] **Step 3: Add fields to seccompWrapperConfig and bridge config**

In `internal/api/core.go`, first add fields to the `seccompWrapperConfig` struct:

```go
type seccompWrapperConfig struct {
	// ... existing fields ...
	InterceptMetadata bool `json:"intercept_metadata,omitempty"`
	BlockIOUring      bool `json:"block_io_uring,omitempty"`
}
```

Then in `setupSeccompWrapper`, where `seccompCfg` is built (around line 171), add:

```go
defaultVal := a.cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE
seccompCfg.InterceptMetadata = fileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata, defaultVal)
seccompCfg.BlockIOUring = fileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.BlockIOUring, defaultVal)
```

Also bridge in `cmd/agentsh-unixwrap/main.go` where `FilterConfig` is constructed:

```go
filterCfg := unixmon.FilterConfig{
	// ... existing fields ...
	InterceptMetadata: cfg.InterceptMetadata,
	BlockIOUring:      cfg.BlockIOUring,
}
```

- [ ] **Step 4: Build to verify**

Run: `go build ./...`
Expected: Compiles cleanly.

- [ ] **Step 5: Commit**

```bash
git add cmd/agentsh-unixwrap/config.go internal/netmonitor/unix/seccomp_linux.go internal/api/core.go cmd/agentsh-unixwrap/main.go
git commit -m "feat(seccomp): bridge new config fields to FilterConfig and WrapperConfig"
```

---

### Task 3: BPF filter — Metadata syscalls + io_uring blocking

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go:188-277`
- Modify: `internal/netmonitor/unix/seccomp_linux_test.go` (if exists, or handler_test.go)

- [ ] **Step 1: Add metadata syscalls to InstallFilterWithConfig**

In `internal/netmonitor/unix/seccomp_linux.go`, after the existing `fileRules` block in `InstallFilterWithConfig` (line 232), add a conditional block:

```go
// Metadata syscalls via user-notify (when intercept_metadata is enabled)
if cfg.InterceptMetadata {
	metadataRules := []seccomp.ScmpSyscall{
		seccomp.ScmpSyscall(unix.SYS_STATX),
		seccomp.ScmpSyscall(unix.SYS_NEWFSTATAT),
		seccomp.ScmpSyscall(unix.SYS_FACCESSAT2),
		seccomp.ScmpSyscall(unix.SYS_READLINKAT),
	}
	for _, sc := range metadataRules {
		if err := filt.AddRule(sc, trap); err != nil {
			return nil, fmt.Errorf("add metadata rule %v: %w", sc, err)
		}
	}
}

// mknodat is always included with file monitoring (create-category)
if cfg.FileMonitorEnabled {
	if err := filt.AddRule(seccomp.ScmpSyscall(unix.SYS_MKNODAT), trap); err != nil {
		return nil, fmt.Errorf("add mknodat rule: %w", err)
	}
}
```

- [ ] **Step 2: Add io_uring blocking**

After the blocked syscalls section (line 258), add:

```go
// Block io_uring to prevent seccomp bypass
if cfg.BlockIOUring {
	ioUringBlock := seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))
	ioUringSyscalls := []seccomp.ScmpSyscall{
		seccomp.ScmpSyscall(425), // io_uring_setup
		seccomp.ScmpSyscall(426), // io_uring_enter
		seccomp.ScmpSyscall(427), // io_uring_register
	}
	for _, sc := range ioUringSyscalls {
		if err := filt.AddRule(sc, ioUringBlock); err != nil {
			return nil, fmt.Errorf("add io_uring block rule %v: %w", sc, err)
		}
	}
}
```

- [ ] **Step 3: Build to verify**

Run: `go build ./internal/netmonitor/unix/...`
Expected: Compiles cleanly.

- [ ] **Step 4: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go
git commit -m "feat(seccomp): add metadata syscalls and io_uring blocking to BPF filter

Add statx, newfstatat, faccessat2, readlinkat when intercept_metadata
is enabled. Add mknodat when file_monitor is enabled. Block
io_uring_setup/enter/register with EPERM when block_io_uring is enabled."
```

---

### Task 4: Syscall routing — New syscalls in isFileSyscall, extractFileArgs, syscallToOperation

**Files:**
- Modify: `internal/netmonitor/unix/file_syscalls.go:14-25, 44-131, 157-190`
- Modify: `internal/netmonitor/unix/file_syscalls_test.go`

- [ ] **Step 1: Write failing tests for new syscalls**

In `internal/netmonitor/unix/file_syscalls_test.go`, add to `TestIsFileSyscall`'s `fileSyscalls` slice:

```go
unix.SYS_STATX,
unix.SYS_NEWFSTATAT,
439, // SYS_FACCESSAT2 (may not have a constant in older x/sys/unix)
unix.SYS_READLINKAT,
unix.SYS_MKNODAT,
```

Add to `TestSyscallToOperation`'s `tests` slice:

```go
// Metadata operations
{"statx", unix.SYS_STATX, 0, "stat"},
{"newfstatat", unix.SYS_NEWFSTATAT, 0, "stat"},
{"faccessat2", 439, 0, "access"},
{"readlinkat", unix.SYS_READLINKAT, 0, "readlink"},
{"mknodat", unix.SYS_MKNODAT, 0, "mknod"},
```

Add new `TestExtractFileArgs_*` test functions:

```go
func TestExtractFileArgs_Statx(t *testing.T) {
	// statx(dirfd, path, flags, mask, statxbuf)
	args := SyscallArgs{
		Nr:   unix.SYS_STATX,
		Arg0: fdcwdUint64(),
		Arg1: 0x7fff2000,
		Arg2: 0, // flags
	}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff2000), fa.PathPtr)
}

func TestExtractFileArgs_Newfstatat(t *testing.T) {
	// newfstatat(dirfd, path, statbuf, flags)
	args := SyscallArgs{
		Nr:   unix.SYS_NEWFSTATAT,
		Arg0: fdcwdUint64(),
		Arg1: 0x7fff3000,
		Arg3: uint64(unix.AT_SYMLINK_NOFOLLOW),
	}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff3000), fa.PathPtr)
	assert.Equal(t, uint32(unix.AT_SYMLINK_NOFOLLOW), fa.Flags)
}

func TestExtractFileArgs_Faccessat2(t *testing.T) {
	// faccessat2(dirfd, path, mode, flags)
	args := SyscallArgs{
		Nr:   439, // SYS_FACCESSAT2
		Arg0: fdcwdUint64(),
		Arg1: 0x7fff4000,
	}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff4000), fa.PathPtr)
}

func TestExtractFileArgs_Readlinkat(t *testing.T) {
	// readlinkat(dirfd, path, buf, bufsiz)
	args := SyscallArgs{
		Nr:   unix.SYS_READLINKAT,
		Arg0: fdcwdUint64(),
		Arg1: 0x7fff5000,
	}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff5000), fa.PathPtr)
}

func TestExtractFileArgs_Mknodat(t *testing.T) {
	// mknodat(dirfd, path, mode, dev)
	args := SyscallArgs{
		Nr:   unix.SYS_MKNODAT,
		Arg0: fdcwdUint64(),
		Arg1: 0x7fff6000,
		Arg2: 0o100644, // mode
	}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff6000), fa.PathPtr)
	assert.Equal(t, uint32(0o100644), fa.Mode)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/netmonitor/unix/ -run "TestIsFileSyscall|TestSyscallToOperation|TestExtractFileArgs_Statx|TestExtractFileArgs_Newfstatat|TestExtractFileArgs_Faccessat2|TestExtractFileArgs_Readlinkat|TestExtractFileArgs_Mknodat" -v -tags "linux,cgo"`
Expected: FAIL — new syscalls not recognized.

- [ ] **Step 3: Implement isFileSyscall additions**

In `internal/netmonitor/unix/file_syscalls.go`, add to the `isFileSyscall` switch (line 17):

```go
case unix.SYS_OPENAT, unix.SYS_OPENAT2,
	unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
	unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
	unix.SYS_FCHMODAT, unix.SYS_FCHOWNAT,
	unix.SYS_STATX, unix.SYS_NEWFSTATAT, 439, // faccessat2
	unix.SYS_READLINKAT, unix.SYS_MKNODAT:
	return true
```

- [ ] **Step 4: Implement extractFileArgs additions**

In `internal/netmonitor/unix/file_syscalls.go`, add new cases before the `default:` in `extractFileArgs`:

```go
case unix.SYS_STATX:
	// statx(dirfd, path, flags, mask, statxbuf)
	return FileArgs{
		Dirfd:   int32(args.Arg0),
		PathPtr: args.Arg1,
		Flags:   uint32(args.Arg2),
	}

case unix.SYS_NEWFSTATAT:
	// newfstatat(dirfd, path, statbuf, flags)
	return FileArgs{
		Dirfd:   int32(args.Arg0),
		PathPtr: args.Arg1,
		Flags:   uint32(args.Arg3),
	}

case 439: // SYS_FACCESSAT2
	// faccessat2(dirfd, path, mode, flags)
	return FileArgs{
		Dirfd:   int32(args.Arg0),
		PathPtr: args.Arg1,
		Flags:   uint32(args.Arg3),
	}

case unix.SYS_READLINKAT:
	// readlinkat(dirfd, path, buf, bufsiz)
	return FileArgs{
		Dirfd:   int32(args.Arg0),
		PathPtr: args.Arg1,
	}

case unix.SYS_MKNODAT:
	// mknodat(dirfd, path, mode, dev)
	return FileArgs{
		Dirfd:   int32(args.Arg0),
		PathPtr: args.Arg1,
		Mode:    uint32(args.Arg2),
	}
```

- [ ] **Step 5: Implement syscallToOperation additions**

In `internal/netmonitor/unix/file_syscalls.go`, add before the `default:` in `syscallToOperation`:

```go
case unix.SYS_STATX, unix.SYS_NEWFSTATAT:
	return "stat"
case 439: // SYS_FACCESSAT2
	return "access"
case unix.SYS_READLINKAT:
	return "readlink"
case unix.SYS_MKNODAT:
	return "mknod"
```

Also add to `fileSyscallName`:

```go
case unix.SYS_STATX:
	return "statx"
case unix.SYS_NEWFSTATAT:
	return "newfstatat"
case 439:
	return "faccessat2"
case unix.SYS_READLINKAT:
	return "readlinkat"
case unix.SYS_MKNODAT:
	return "mknodat"
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/netmonitor/unix/ -run "TestIsFileSyscall|TestSyscallToOperation|TestExtractFileArgs_Statx|TestExtractFileArgs_Newfstatat|TestExtractFileArgs_Faccessat2|TestExtractFileArgs_Readlinkat|TestExtractFileArgs_Mknodat" -v -tags "linux,cgo"`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/netmonitor/unix/file_syscalls.go internal/netmonitor/unix/file_syscalls_test.go
git commit -m "feat(seccomp): add metadata + mknodat syscall routing

Add statx, newfstatat, faccessat2, readlinkat, mknodat to
isFileSyscall, extractFileArgs, syscallToOperation, fileSyscallName."
```

---

### Task 5: NotifIDValid helper

**Files:**
- Modify: `internal/netmonitor/unix/addfd_linux.go`
- Modify: `internal/netmonitor/unix/addfd_linux_test.go`

- [ ] **Step 1: Write failing tests**

In `internal/netmonitor/unix/addfd_linux_test.go`, add:

```go
func TestNotifIDValid_Constants(t *testing.T) {
	// Verify both ioctl values are defined.
	require.Equal(t, uintptr(0xC0082102), uintptr(ioctlNotifIDValidNew),
		"new ioctl should be 0xC0082102 (kernel 5.17+)")
	require.Equal(t, uintptr(0x40082102), uintptr(ioctlNotifIDValidOld),
		"old ioctl should be 0x40082102 (pre-5.17)")
}

func TestNotifIDValid_InvalidFD(t *testing.T) {
	err := NotifIDValid(-1, 0)
	require.Error(t, err, "NotifIDValid with invalid fd should fail")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/netmonitor/unix/ -run "TestNotifIDValid" -v -tags "linux,cgo"`
Expected: FAIL — `NotifIDValid`, `ioctlNotifIDValidNew`, `ioctlNotifIDValidOld` not defined.

- [ ] **Step 3: Implement NotifIDValid**

In `internal/netmonitor/unix/addfd_linux.go`, add:

```go
// ioctlNotifIDValid ioctl numbers for SECCOMP_IOCTL_NOTIF_ID_VALID.
// The kernel changed from _IOW to _IOWR in 5.17 (commit 47e33c05f9f07).
const (
	ioctlNotifIDValidNew = 0xC0082102 // _IOWR('!', 2, __u64) — kernel 5.17+
	ioctlNotifIDValidOld = 0x40082102 // _IOW('!', 2, __u64) — pre-5.17
)

// NotifIDValid checks whether a seccomp notification ID is still valid
// (the target process/thread hasn't exited or been killed since the
// notification was received). Returns nil if valid, ENOENT if stale.
//
// Tries the 5.17+ ioctl first, falls back to pre-5.17 on ENOTTY.
func NotifIDValid(notifFD int, notifID uint64) error {
	id := notifID
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifFD),
		uintptr(ioctlNotifIDValidNew),
		uintptr(unsafe.Pointer(&id)),
	)
	if errno == unix.ENOTTY {
		// Fallback for pre-5.17 kernels.
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(notifFD),
			uintptr(ioctlNotifIDValidOld),
			uintptr(unsafe.Pointer(&id)),
		)
	}
	if errno != 0 {
		return errno
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/netmonitor/unix/ -run "TestNotifIDValid" -v -tags "linux,cgo"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/addfd_linux.go internal/netmonitor/unix/addfd_linux_test.go
git commit -m "feat(seccomp): add NotifIDValid helper for TOCTOU bracketing

Implements SECCOMP_IOCTL_NOTIF_ID_VALID with dual-ioctl fallback
for pre-5.17 and 5.17+ kernels."
```

---

### Task 6: resolveProcFD helper

**Files:**
- Modify: `internal/netmonitor/unix/file_syscalls.go`
- Modify: `internal/netmonitor/unix/file_syscalls_test.go`

- [ ] **Step 1: Write failing tests**

In `internal/netmonitor/unix/file_syscalls_test.go`, add:

```go
func TestResolveProcFD(t *testing.T) {
	pid := os.Getpid()

	tests := []struct {
		name       string
		path       string
		wasProcFD  bool
	}{
		{"proc self fd", fmt.Sprintf("/proc/self/fd/0"), true},
		{"proc pid fd", fmt.Sprintf("/proc/%d/fd/0", pid), true},
		{"dev fd", "/dev/fd/0", true},
		{"normal path", "/tmp/foo", false},
		{"proc but not fd", "/proc/self/status", false},
		{"proc other pid fd", "/proc/1/fd/0", false}, // PID 1 != our PID
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, wasProcFD := resolveProcFD(pid, tt.path)
			assert.Equal(t, tt.wasProcFD, wasProcFD, "wasProcFD mismatch for %s", tt.path)
			if wasProcFD {
				// Should resolve to the actual target, not the procfs path
				assert.NotContains(t, resolved, "/proc/")
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/netmonitor/unix/ -run "TestResolveProcFD" -v -tags "linux,cgo"`
Expected: FAIL — `resolveProcFD` not defined.

- [ ] **Step 3: Implement resolveProcFD**

In `internal/netmonitor/unix/file_syscalls.go`, add:

```go
// resolveProcFD detects and resolves /proc/self/fd/N, /proc/<pid>/fd/N,
// and /dev/fd/N paths to their actual targets. This prevents policy bypass
// by re-deriving paths from file descriptors.
//
// Returns the resolved target path and true if the path was a procfs fd
// reference, or the original path and false otherwise.
func resolveProcFD(pid int, path string) (string, bool) {
	var fdStr string

	// Match /proc/self/fd/<N>
	if strings.HasPrefix(path, "/proc/self/fd/") {
		fdStr = path[len("/proc/self/fd/"):]
	} else if strings.HasPrefix(path, "/dev/fd/") {
		fdStr = path[len("/dev/fd/"):]
	} else {
		// Match /proc/<pid>/fd/<N> where pid matches the requesting process
		prefix := fmt.Sprintf("/proc/%d/fd/", pid)
		if strings.HasPrefix(path, prefix) {
			fdStr = path[len(prefix):]
		} else {
			return path, false
		}
	}

	// Validate fd is a number
	if _, err := strconv.Atoi(fdStr); err != nil {
		return path, false
	}

	// Resolve the actual target
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fdStr))
	if err != nil {
		return path, false
	}
	return target, true
}
```

Add `"strconv"` to the imports if not already present.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/netmonitor/unix/ -run "TestResolveProcFD" -v -tags "linux,cgo"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/file_syscalls.go internal/netmonitor/unix/file_syscalls_test.go
git commit -m "feat(seccomp): add resolveProcFD to detect /proc/self/fd/N bypass

Resolves /proc/self/fd/N, /proc/<pid>/fd/N, and /dev/fd/N to their
actual targets for policy evaluation against the real path."
```

---

### Task 7: FileHandler — emulateOpen field + /proc/self/fd/N interception

**Files:**
- Modify: `internal/netmonitor/unix/file_handler.go`
- Modify: `internal/netmonitor/unix/file_handler_test.go`

- [ ] **Step 1: Write failing tests**

In `internal/netmonitor/unix/file_handler_test.go`, add:

```go
func TestFileHandler_ProcSelfFD_ResolvesToTarget(t *testing.T) {
	// Policy denies /root/.ssh/id_rsa but allows /proc/self/fd/*
	// The handler should resolve /proc/self/fd/N to the target and evaluate
	// policy against the target, not the procfs path.
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/root/.ssh/id_rsa": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_ssh_keys",
				Message:           "access denied",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true)

	// Create a temp file and get its fd path
	tmpFile, err := os.CreateTemp("", "procfd-test")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Simulate a request for /proc/self/fd/<N> where N points to the temp file
	// For this unit test, we test the resolution logic directly
	pid := os.Getpid()
	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, tmpFile.Fd())
	req := FileRequest{
		PID:       pid,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      procPath,
		Operation: "open",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)
	// The handler should resolve the procfs path and evaluate against the temp file path.
	// Since the temp file path is not in the deny list, it should be allowed.
	assert.Equal(t, ActionContinue, result.Action)
}

func TestFileHandler_EmulateOpen_Field(t *testing.T) {
	handler := NewFileHandler(nil, nil, nil, true)
	assert.False(t, handler.emulateOpen, "emulateOpen should default to false")

	handler.SetEmulateOpen(true)
	assert.True(t, handler.emulateOpen)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/netmonitor/unix/ -run "TestFileHandler_ProcSelfFD|TestFileHandler_EmulateOpen" -v -tags "linux,cgo"`
Expected: FAIL — `SetEmulateOpen` not defined, procfd resolution not wired in Handle.

- [ ] **Step 3: Add emulateOpen field and SetEmulateOpen**

In `internal/netmonitor/unix/file_handler.go`, modify the struct and constructor:

```go
type FileHandler struct {
	policy      FilePolicyChecker
	registry    *MountRegistry
	emitter     Emitter
	enforce     bool
	emulateOpen bool // When true, supervisor emulates openat via AddFD
}

// SetEmulateOpen enables or disables openat AddFD emulation.
func (h *FileHandler) SetEmulateOpen(v bool) {
	h.emulateOpen = v
}

// EmulateOpen returns whether AddFD emulation is active.
func (h *FileHandler) EmulateOpen() bool {
	return h.emulateOpen
}
```

- [ ] **Step 4: Add /proc/self/fd/N resolution to Handle**

In `internal/netmonitor/unix/file_handler.go`, at the start of `Handle()`, after the nil policy check (line 71) and before the FUSE mount check (line 84), add:

```go
// Resolve /proc/self/fd/N, /proc/<pid>/fd/N, /dev/fd/N to actual target.
// This prevents policy bypass by re-deriving paths from file descriptors.
if resolved, wasProcFD := resolveProcFD(req.PID, req.Path); wasProcFD {
	req.Path = resolved
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/netmonitor/unix/ -run "TestFileHandler_ProcSelfFD|TestFileHandler_EmulateOpen" -v -tags "linux,cgo"`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/unix/file_handler.go internal/netmonitor/unix/file_handler_test.go
git commit -m "feat(seccomp): add emulateOpen field and /proc/self/fd/N resolution

FileHandler.Handle() now resolves /proc/self/fd/N paths to their actual
targets before policy evaluation. Add SetEmulateOpen for AddFD mode."
```

---

### Task 8: handleFileNotificationEmulated — AddFD emulation + ID validation

**Files:**
- Modify: `internal/netmonitor/unix/handler.go`
- Modify: `internal/netmonitor/unix/file_syscalls.go`
- Modify: `internal/netmonitor/unix/file_syscalls_legacy_amd64.go`
- Modify: `internal/netmonitor/unix/file_syscalls_legacy_other.go`
- Modify: `internal/netmonitor/unix/file_handler_test.go`

This is the core task. It modifies `handleFileNotification` to branch based on `emulateOpen`.

- [ ] **Step 0: Write tests for emulation mode branches**

In `internal/netmonitor/unix/file_handler_test.go`, add tests covering emulation decisions:

```go
func TestIsOpenSyscall(t *testing.T) {
	assert.True(t, isOpenSyscall(unix.SYS_OPENAT))
	assert.True(t, isOpenSyscall(unix.SYS_OPENAT2))
	assert.False(t, isOpenSyscall(unix.SYS_UNLINKAT))
	assert.False(t, isOpenSyscall(unix.SYS_STATX))
	assert.False(t, isOpenSyscall(unix.SYS_MKNODAT))
}

func TestShouldFallbackToContinue(t *testing.T) {
	// Normal openat — should NOT fallback
	assert.False(t, shouldFallbackToContinue(unix.SYS_OPENAT, unix.O_RDONLY, 0))

	// O_TMPFILE — should fallback
	assert.True(t, shouldFallbackToContinue(unix.SYS_OPENAT, unix.O_TMPFILE, 0))

	// openat2 with RESOLVE_* flags — should fallback
	assert.True(t, shouldFallbackToContinue(unix.SYS_OPENAT2, unix.O_RDONLY, 0x01)) // RESOLVE_NO_XDEV

	// openat2 without RESOLVE_* — should NOT fallback
	assert.False(t, shouldFallbackToContinue(unix.SYS_OPENAT2, unix.O_RDONLY, 0))
}

func TestFileHandler_EmulateOpen_DenyReturnsEACCES(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/etc/shadow": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_shadow",
			},
		},
	}
	emitter := &mockFileEmitter{}
	handler := NewFileHandler(policy, NewMountRegistry(), emitter, true)
	handler.SetEmulateOpen(true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/etc/shadow",
		Operation: "open",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, int32(unix.EACCES), result.Errno)
}
```

Run: `go test ./internal/netmonitor/unix/ -run "TestIsOpenSyscall|TestShouldFallbackToContinue|TestFileHandler_EmulateOpen_Deny" -v -tags "linux,cgo"`
Expected: FAIL — `isOpenSyscall`, `shouldFallbackToContinue` not defined.

- [ ] **Step 1: Add isOpenSyscall helper**

In `internal/netmonitor/unix/file_syscalls.go`, add:

```go
// isOpenSyscall returns true if the syscall returns a file descriptor
// (openat, openat2, and legacy open/creat on amd64).
func isOpenSyscall(nr int32) bool {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
		return true
	default:
		return isLegacyOpenSyscallNr(nr)
	}
}
```

Also add `isLegacyOpenSyscallNr` in `file_syscalls_legacy_amd64.go`:

```go
func isLegacyOpenSyscallNr(nr int32) bool {
	return nr == unix.SYS_OPEN || nr == unix.SYS_CREAT
}
```

And the stub in `file_syscalls_legacy_other.go`:

```go
func isLegacyOpenSyscallNr(nr int32) bool {
	return false
}
```

- [ ] **Step 2: Add shouldFallbackToContinue helper**

In `internal/netmonitor/unix/file_syscalls.go`, add:

```go
// shouldFallbackToContinue returns true if an open syscall should use
// CONTINUE instead of AddFD emulation (openat2 RESOLVE_* flags, O_TMPFILE).
func shouldFallbackToContinue(nr int32, flags uint32, resolveFlags uint64) bool {
	if resolveFlags != 0 {
		return true // openat2 with RESOLVE_* — can't replicate from supervisor
	}
	if flags&unix.O_TMPFILE == unix.O_TMPFILE {
		return true // O_TMPFILE — may hit wrong filesystem
	}
	return false
}
```

- [ ] **Step 3: Implement handleFileNotificationEmulated**

In `internal/netmonitor/unix/handler.go`, add the new function:

```go
// handleFileNotificationEmulated processes a file syscall with AddFD emulation for opens
// and ID validation bracketing for non-fd-returning syscalls.
func handleFileNotificationEmulated(goCtx context.Context, fd seccomp.ScmpFd, req *seccomp.ScmpNotifReq, h *FileHandler, sessID string) {
	args := SyscallArgs{
		Nr:   int32(req.Data.Syscall),
		Arg0: req.Data.Args[0],
		Arg1: req.Data.Args[1],
		Arg2: req.Data.Args[2],
		Arg3: req.Data.Args[3],
		Arg4: req.Data.Args[4],
		Arg5: req.Data.Args[5],
	}

	pid := int(req.Pid)
	notifFD := int(fd)
	fileArgs := extractFileArgs(args)

	// For openat2, resolve actual flags from the open_how struct.
	var resolveFlags uint64
	if args.Nr == unix.SYS_OPENAT2 && fileArgs.HowPtr != 0 {
		howFlags, howMode, err := readOpenHow(pid, fileArgs.HowPtr)
		if err != nil {
			slog.Debug("emulated file handler: failed to read open_how, denying", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		fileArgs.Flags = uint32(howFlags)
		fileArgs.Mode = uint32(howMode)
		// readOpenHow only returns flags and mode — read resolve separately.
		resolveFlags = readOpenHowResolve(pid, fileArgs.HowPtr)
	}

	// Resolve primary path — fail-secure in emulation mode.
	path, err := resolvePathAt(pid, fileArgs.Dirfd, fileArgs.PathPtr)
	if err != nil {
		slog.Debug("emulated file handler: failed to resolve path, denying", "pid", pid, "error", err)
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}

	// Resolve second path for rename/link.
	var path2 string
	if fileArgs.HasSecondPath {
		p2, err := resolvePathAt(pid, fileArgs.Dirfd2, fileArgs.PathPtr2)
		if err != nil {
			slog.Debug("emulated file handler: failed to resolve second path, denying", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		path2 = p2
	}

	operation := syscallToOperation(args.Nr, fileArgs.Flags)

	frequest := FileRequest{
		PID:       pid,
		Syscall:   args.Nr,
		Path:      path,
		Path2:     path2,
		Operation: operation,
		Flags:     fileArgs.Flags,
		Mode:      fileArgs.Mode,
		SessionID: sessID,
	}

	// For non-emulated syscalls (CONTINUE path), do first ID validation
	// check now — after reading path but before policy evaluation.
	needsContinue := !isOpenSyscall(args.Nr) || shouldFallbackToContinue(args.Nr, fileArgs.Flags, resolveFlags)
	if needsContinue {
		if err := NotifIDValid(notifFD, req.ID); err != nil {
			slog.Debug("emulated file handler: notification stale before policy check", "pid", pid)
			return
		}
	}

	result := h.Handle(frequest)

	// Branch: is this an open syscall that we should emulate?
	if !needsContinue {
		if result.Action == ActionDeny {
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -result.Errno}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		// Emulate: supervisor opens the file and injects fd.
		emulateOpenat(fd, req, pid, path, fileArgs.Flags, fileArgs.Mode)
		return
	}

	// Non-open or fallback: use CONTINUE with ID validation bracketing.
	// First check was done above (before policy evaluation).
	if result.Action == ActionDeny {
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -result.Errno}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}

	// Second ID validation check after policy evaluation.
	if err := NotifIDValid(notifFD, req.ID); err != nil {
		slog.Debug("emulated file handler: notification stale after policy check", "pid", pid)
		return
	}
	resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
	_ = seccomp.NotifRespond(fd, &resp)
}

// emulateOpenat opens the file from the supervisor and injects the fd into the tracee.
func emulateOpenat(fd seccomp.ScmpFd, req *seccomp.ScmpNotifReq, pid int, path string, flags uint32, mode uint32) {
	// Build the open path through /proc/<pid>/root for mount namespace correctness.
	procPath := fmt.Sprintf("/proc/%d/root%s", pid, path)

	// Filter flags: only forward safe open flags to the supervisor's open call.
	// Strip internal kernel flags and keep only user-visible ones.
	openFlags := int(flags) & (unix.O_RDONLY | unix.O_WRONLY | unix.O_RDWR |
		unix.O_APPEND | unix.O_TRUNC | unix.O_CREAT | unix.O_EXCL |
		unix.O_NOFOLLOW | unix.O_DIRECTORY | unix.O_PATH | unix.O_NOCTTY |
		unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_SYNC | unix.O_DSYNC)

	supervisorFD, err := unix.Open(procPath, openFlags, uint32(mode))
	if err != nil {
		// Return the supervisor's errno to the tracee (e.g., ENOENT, EACCES).
		errno, ok := err.(unix.Errno)
		if !ok {
			errno = unix.EIO
		}
		slog.Debug("emulateOpenat: supervisor open failed", "pid", pid, "path", path, "error", err)
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(errno)}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}

	// Inject fd into tracee atomically with SEND flag (also completes the response).
	_, err = NotifAddFD(int(fd), req.ID, supervisorFD, 0, SECCOMP_ADDFD_FLAG_SEND)
	_ = unix.Close(supervisorFD) // Always close our copy.
	if err != nil {
		slog.Error("emulateOpenat: AddFD failed", "pid", pid, "path", path, "error", err)
		// AddFD with SEND already responded on success. On failure, the notification
		// may still be pending — respond with EIO.
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EIO)}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}
	// SECCOMP_ADDFD_FLAG_SEND completed the notification response atomically.
}
```

- [ ] **Step 4: Add readOpenHowResolve helper**

In `internal/netmonitor/unix/file_syscalls.go`, add:

```go
// readOpenHowResolve reads only the resolve field (offset 16) from open_how in tracee memory.
func readOpenHowResolve(pid int, howPtr uint64) uint64 {
	if howPtr == 0 {
		return 0
	}
	var buf [8]byte
	liov := unix.Iovec{Base: &buf[0], Len: 8}
	riov := unix.RemoteIovec{Base: uintptr(howPtr + 16), Len: 8}
	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err != nil {
		return 0
	}
	return *(*uint64)(unsafe.Pointer(&buf[0]))
}
```

- [ ] **Step 5: Wire emulated handler in ServeNotifyWithExecve**

In `internal/netmonitor/unix/handler.go`, in `ServeNotifyWithExecve` (line 192), change the file syscall routing:

```go
// Route file syscalls to file handler
if isFileSyscall(syscallNr) && fileHandler != nil {
	slog.Debug("ServeNotifyWithExecve: routing to file handler", "session_id", sessID, "pid", req.Pid, "syscall", syscallNr)
	if fileHandler.EmulateOpen() {
		handleFileNotificationEmulated(ctx, scmpFD, req, fileHandler, sessID)
	} else {
		handleFileNotification(ctx, scmpFD, req, fileHandler, sessID)
	}
	continue
}
```

- [ ] **Step 6: Build to verify**

Run: `go build ./internal/netmonitor/unix/...`
Expected: Compiles cleanly.

- [ ] **Step 7: Commit**

```bash
git add internal/netmonitor/unix/handler.go internal/netmonitor/unix/file_syscalls.go internal/netmonitor/unix/file_syscalls_legacy_amd64.go internal/netmonitor/unix/file_syscalls_legacy_other.go
git commit -m "feat(seccomp): add openat AddFD emulation and ID validation bracketing

handleFileNotificationEmulated emulates openat by supervisor-opening
the file and injecting the fd via SECCOMP_ADDFD_FLAG_SEND. Falls back
to CONTINUE+ID validation for openat2 RESOLVE_* and O_TMPFILE.
Non-fd-returning syscalls use CONTINUE with ID validation bracketing."
```

---

### Task 9: execve file_rules evaluation

**Files:**
- Modify: `internal/netmonitor/unix/handler.go`
- Modify: `internal/netmonitor/unix/handler_test.go`

- [ ] **Step 1: Write failing test**

In `internal/netmonitor/unix/handler_test.go`, add:

```go
func TestServeNotify_RoutesNewFileSyscalls(t *testing.T) {
	assert.True(t, isFileSyscall(unix.SYS_STATX))
	assert.True(t, isFileSyscall(unix.SYS_NEWFSTATAT))
	assert.True(t, isFileSyscall(439)) // faccessat2
	assert.True(t, isFileSyscall(unix.SYS_READLINKAT))
	assert.True(t, isFileSyscall(unix.SYS_MKNODAT))
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/netmonitor/unix/ -run "TestServeNotify_RoutesNewFileSyscalls|TestIsOpenSyscall" -v -tags "linux,cgo"`
Expected: PASS (these test code already written in previous tasks).

- [ ] **Step 3: Modify handleExecveNotification to accept fileHandler and sessID**

In `internal/netmonitor/unix/handler.go`, change the signature of `handleExecveNotification`:

```go
func handleExecveNotification(goCtx context.Context, fd seccomp.ScmpFd, req *seccomp.ScmpNotifReq, h *ExecveHandler, fileHandler *FileHandler, sessID string) {
```

After the existing `result := h.Handle(goCtx, ectx)` and before `switch result.Action`, add:

```go
// Evaluate file_rules on the binary path (in addition to command_rules).
if result.Action == ActionContinue && fileHandler != nil {
	fileResult := fileHandler.Handle(FileRequest{
		PID:       pid,
		Syscall:   int32(req.Data.Syscall),
		Path:      filename,
		Operation: "execute",
		SessionID: sessID,
	})
	if fileResult.Action == ActionDeny {
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -fileResult.Errno}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}
}
```

- [ ] **Step 4: Update the call site in ServeNotifyWithExecve**

Change line 187:

```go
handleExecveNotification(ctx, scmpFD, req, execveHandler, fileHandler, sessID)
```

- [ ] **Step 5: Build to verify**

Run: `go build ./internal/netmonitor/unix/...`
Expected: Compiles cleanly.

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/unix/handler.go internal/netmonitor/unix/handler_test.go
git commit -m "feat(seccomp): evaluate file_rules on execve binary paths

handleExecveNotification now checks file_rules after command_rules.
If command_rules allows but file_rules denies, the execve is blocked."
```

---

### Task 10: Backend detection + detect output

**Files:**
- Modify: `internal/capabilities/security_caps.go`
- Modify: `internal/capabilities/detect_linux.go`
- Modify: `internal/cli/detect.go`

- [ ] **Step 1: Add FileEnforcement to SecurityCapabilities**

In `internal/capabilities/security_caps.go`, add to the struct:

```go
type SecurityCapabilities struct {
	// ... existing fields ...
	FileEnforcement string // "landlock", "fuse", "seccomp-notify", "none"
}
```

If `security_caps.go` has a `//go:build linux` tag and there is a corresponding `security_caps_other.go` for non-Linux platforms, add the `FileEnforcement` field there too. Check with `GOOS=windows go build ./internal/capabilities/...` to verify.

- [ ] **Step 2: Add detectFileEnforcementBackend**

In `internal/capabilities/detect_linux.go`, add:

```go
// detectFileEnforcementBackend returns the best available file enforcement backend.
func detectFileEnforcementBackend(caps *SecurityCapabilities) string {
	if caps.Landlock {
		return "landlock"
	}
	if caps.FUSE {
		return "fuse"
	}
	if caps.Seccomp {
		return "seccomp-notify"
	}
	return "none"
}
```

- [ ] **Step 3: Wire into Detect function**

In `internal/capabilities/detect_linux.go`, in `Detect()`, add after the capabilities map is built:

```go
caps["file_enforcement"] = detectFileEnforcementBackend(secCaps)
```

Also set it on secCaps:

```go
secCaps.FileEnforcement = detectFileEnforcementBackend(secCaps)
```

(Call `detectFileEnforcementBackend` after `DetectSecurityCapabilities` returns.)

- [ ] **Step 4: Render in detect CLI output**

In `internal/cli/detect.go`, add `file_enforcement` to the table/json/yaml output. Find where capabilities are rendered and add the new field. The exact location depends on the rendering code — look for where other capabilities like `seccomp` or `landlock` are printed and add `file_enforcement` alongside them.

- [ ] **Step 5: Build + test detect command**

Run: `go build ./cmd/agentsh/... && go test ./internal/capabilities/... -v`
Expected: Compiles cleanly, existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/capabilities/security_caps.go internal/capabilities/detect_linux.go internal/cli/detect.go
git commit -m "feat(detect): add file_enforcement backend to detect output

Shows which file enforcement backend is active: landlock, fuse,
seccomp-notify, or none."
```

---

### Task 11: Wire emulateOpen in createFileHandler

**Files:**
- Modify: `internal/api/file_monitor_linux.go`
- Modify: `internal/netmonitor/unix/mount_registry.go`

- [ ] **Step 0: Add HasAnyMounts to MountRegistry**

In `internal/netmonitor/unix/mount_registry.go`, add:

```go
// HasAnyMounts returns true if any FUSE mounts are registered across all sessions.
func (r *MountRegistry) HasAnyMounts() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.mounts) > 0
}
```

- [ ] **Step 1: Update createFileHandler to set emulateOpen**

In `internal/api/file_monitor_linux.go`, first add the import:

```go
import (
	// ... existing imports ...
	"github.com/agentsh/agentsh/internal/capabilities"
)
```

Then modify `createFileHandler`:

```go
func createFileHandler(cfg config.SandboxSeccompFileMonitorConfig, pol *policy.Engine, emitter unixmon.Emitter) *unixmon.FileHandler {
	if !cfg.Enabled {
		return nil
	}

	var policyChecker unixmon.FilePolicyChecker
	if pol != nil {
		policyChecker = &filePolicyEngineWrapper{engine: pol}
	}

	registry := getMountRegistry()
	enforce := cfg.EnforceWithoutFUSE
	handler := unixmon.NewFileHandler(policyChecker, registry, emitter, enforce)

	// Enable AddFD emulation when configured and no other backend is primary.
	defaultVal := cfg.EnforceWithoutFUSE
	openatEmulation := fileMonitorBoolWithDefault(cfg.OpenatEmulation, defaultVal)
	if openatEmulation && enforce {
		// Check if FUSE or Landlock is available — if so, they handle enforcement.
		fuseAvailable := registry.HasAnyMounts()
		landlockAvailable := capabilities.DetectLandlock().Available
		if !fuseAvailable && !landlockAvailable {
			handler.SetEmulateOpen(true)
		}
	}

	return handler
}
```

Note: `fileMonitorBoolWithDefault` was added to `internal/config/config.go` in Task 1.

- [ ] **Step 2: Build to verify**

Run: `go build ./internal/api/...`
Expected: Compiles cleanly.

- [ ] **Step 3: Commit**

```bash
git add internal/api/file_monitor_linux.go
git commit -m "feat(api): wire emulateOpen based on runtime capability detection

createFileHandler enables AddFD emulation when openat_emulation is
configured and neither FUSE nor Landlock is available."
```

---

### Task 12: Full build + test suite

- [ ] **Step 1: Run full build**

Run: `go build ./...`
Expected: Compiles cleanly.

- [ ] **Step 2: Cross-compile for Windows**

Run: `GOOS=windows go build ./...`
Expected: Compiles cleanly (Linux-only code behind build tags).

- [ ] **Step 3: Run full test suite**

Run: `go test ./...`
Expected: All tests pass.

- [ ] **Step 4: Run the seccomp-specific tests**

Run: `go test ./internal/netmonitor/unix/... -v -tags "linux,cgo" -count=1`
Expected: All tests pass, including the new ones from tasks 4-9.

- [ ] **Step 5: Commit any fixups if needed**

---

### Task 13: Integration tests

**Files:**
- Modify: `internal/netmonitor/unix/file_integration_test.go`

- [ ] **Step 1: Add integration test for AddFD emulation**

In `internal/netmonitor/unix/file_integration_test.go`, add a test that:
1. Creates a seccomp filter with `FileMonitorEnabled: true, InterceptMetadata: true, BlockIOUring: true`
2. Forks a child process
3. In the child: attempts `openat` on a test file
4. In the parent: runs the notify loop with `emulateOpen: true`, policy allows the open
5. Verifies the child gets a valid fd and can read the file contents

Follow the existing integration test patterns in this file.

- [ ] **Step 2: Add integration test for denied openat**

Same setup but policy denies the path. Verify child gets `EACCES`.

- [ ] **Step 3: Add integration test for io_uring blocking**

Verify `io_uring_setup` returns `EPERM` when `BlockIOUring` is true.

- [ ] **Step 4: Run integration tests**

Run: `go test ./internal/netmonitor/unix/ -run "Integration" -v -tags "linux,cgo" -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/file_integration_test.go
git commit -m "test(seccomp): add integration tests for AddFD emulation and io_uring blocking"
```

---

### Deferred: End-to-end Deno test suite

The spec (section 9, item 6) calls for compiling a small C binary inside the Deno Deploy sandbox that makes raw syscalls (openat, statx, unlinkat) to verify kernel-level enforcement independent of the exec API. This requires the Deno test infrastructure (`test-template.ts`) and a Firecracker sandbox environment, which is out of scope for this Go-side implementation plan. Track this as a separate follow-up task in the Deno test suite.
