# Windows WinFsp Filesystem Implementation Design

**Date:** 2026-01-02
**Status:** Implemented

## Summary

Implement WinFsp-based filesystem mounting for Windows to enable soft-delete and path redirection. Uses a shared `fuse/` package with cgofuse that works for both macOS (FUSE-T) and Windows (WinFsp).

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| FUSE library | cgofuse (shared) | Cross-platform: works with FUSE-T and WinFsp |
| Code organization | Shared `fuse/` package | Avoid duplication between darwin and windows |
| Mount style | Directory mount | Matches macOS behavior, integrates naturally |
| Minifilter coexistence | Exclude agentsh process | Clean separation: WinFsp handles files, minifilter handles registry |
| Fallback behavior | Configurable hard fail | Require WinFsp when enabled; skip when disabled in config |

## Architecture

```
internal/platform/
├── fuse/                           # Shared cgofuse implementation
│   ├── fuse.go                     # Types, Config, Mount/Available/Implementation
│   ├── mount_cgo.go                # //go:build cgo - Mount/Unmount via cgofuse
│   ├── mount_nocgo.go              # //go:build !cgo - Returns "CGO required" error
│   ├── ops.go                      # Shared FUSE operations (Open, Read, Write, etc.)
│   ├── ops_unix.go                 # //go:build unix - Chown, Unix stat fields
│   ├── ops_windows.go              # //go:build windows - Windows adaptations
│   ├── policy.go                   # Policy checking, soft-delete, redirection
│   └── fuse_test.go                # Unit tests
├── darwin/
│   ├── filesystem.go               # Detection (FUSE-T), delegates to fuse.Mount()
│   └── filesystem_test.go
└── windows/
    ├── filesystem.go               # Detection (WinFsp), delegates to fuse.Mount()
    ├── filesystem_test.go
    └── ... (existing minifilter, registry, network code)
```

## Core Types

```go
// internal/platform/fuse/fuse.go

package fuse

import "github.com/agentsh/agentsh/internal/platform"

// Config holds FUSE mount configuration
type Config struct {
    platform.FSConfig

    // VolumeName is the display name (shown in file managers)
    VolumeName string

    // ReadOnly mounts the filesystem read-only
    ReadOnly bool

    // Debug enables verbose FUSE logging
    Debug bool
}

// Mount creates a FUSE mount using cgofuse.
// On macOS: requires FUSE-T
// On Windows: requires WinFsp
// Returns error if CGO unavailable or FUSE not installed.
func Mount(cfg Config) (platform.FSMount, error)

// Available checks if FUSE is available on this platform.
func Available() bool

// Implementation returns "fuse-t" on macOS, "winfsp" on Windows.
func Implementation() string

// InstallInstructions returns platform-specific install help.
func InstallInstructions() string
```

## FUSE Operations

```go
// internal/platform/fuse/ops.go
// //go:build cgo

package fuse

// fuseFS implements fuse.FileSystemInterface with policy enforcement
type fuseFS struct {
    fuse.FileSystemBase
    realRoot  string              // Real filesystem path being proxied
    cfg       Config
    openFiles sync.Map            // fh -> *openFile
    nextFh    atomic.Uint64
    stats     statsCollector
}

// Core pattern for all operations:
func (f *fuseFS) Unlink(path string) int {
    virtPath := f.virtPath(path)
    realPath := f.realPath(path)

    // 1. Check policy
    decision := f.checkPolicy(virtPath, platform.FileOpDelete)

    // 2. Handle soft-delete
    if decision == platform.DecisionSoftDelete {
        return f.softDelete(realPath, virtPath)
    }

    // 3. Deny if not allowed
    if decision == platform.DecisionDeny {
        f.emitEvent("file_delete", virtPath, decision, true)
        return -fuse.EACCES
    }

    // 4. Perform real operation
    if err := os.Remove(realPath); err != nil {
        return toErrno(err)
    }

    f.emitEvent("file_delete", virtPath, decision, false)
    return 0
}
```

### Platform-Specific Adaptations

```go
// internal/platform/fuse/ops_unix.go
// //go:build unix

func (f *fuseFS) Chown(path string, uid uint32, gid uint32) int {
    realPath := f.realPath(path)
    if err := os.Chown(realPath, int(uid), int(gid)); err != nil {
        return toErrno(err)
    }
    return 0
}

func fillStatPlatform(stat *fuse.Stat_t, sys any) {
    if s, ok := sys.(*syscall.Stat_t); ok {
        stat.Uid = s.Uid
        stat.Gid = s.Gid
        stat.Atim = fuse.NewTimespec(time.Unix(s.Atimespec.Sec, s.Atimespec.Nsec))
        stat.Ctim = fuse.NewTimespec(time.Unix(s.Ctimespec.Sec, s.Ctimespec.Nsec))
    }
}
```

```go
// internal/platform/fuse/ops_windows.go
// //go:build windows

func (f *fuseFS) Chown(path string, uid uint32, gid uint32) int {
    // Windows doesn't support Unix-style ownership
    // ACLs are managed separately
    return 0
}

func fillStatPlatform(stat *fuse.Stat_t, sys any) {
    if s, ok := sys.(*syscall.Win32FileAttributeData); ok {
        stat.Atim = fuse.NewTimespec(filetimeToTime(s.LastAccessTime))
        stat.Ctim = fuse.NewTimespec(filetimeToTime(s.CreationTime))
    }
    // Windows: UID/GID not meaningful, leave as 0
}
```

## Soft-Delete & Redirection

```go
// internal/platform/fuse/policy.go

// softDelete moves a file to trash instead of deleting
func (f *fuseFS) softDelete(realPath, virtPath string) int {
    if f.cfg.TrashConfig == nil || !f.cfg.TrashConfig.Enabled {
        return -fuse.EACCES
    }

    // Generate unique trash path
    trashPath := f.trashPath(realPath)

    // Optionally hash file before moving
    var hash string
    if f.cfg.TrashConfig.HashFiles {
        hash = f.hashFile(realPath)
    }

    // Move to trash
    if err := os.Rename(realPath, trashPath); err != nil {
        return toErrno(err)
    }

    // Generate restore token
    token := f.generateRestoreToken(virtPath, trashPath, hash)

    // Notify callback
    if f.cfg.NotifySoftDelete != nil {
        f.cfg.NotifySoftDelete(virtPath, token)
    }

    f.emitEvent("file_soft_delete", virtPath, platform.DecisionSoftDelete, false)
    return 0
}

// handleRedirect rewrites the real path for redirected operations
func (f *fuseFS) handleRedirect(decision platform.Decision, realPath string) string {
    if decision.Redirect == nil {
        return realPath
    }
    relPath, _ := filepath.Rel(f.realRoot, realPath)
    return filepath.Join(decision.Redirect.Target, relPath)
}
```

## Minifilter Exclusion

To avoid double-interception when WinFsp is active, the minifilter excludes the agentsh process.

### Driver Changes

```c
// drivers/windows/agentsh-minifilter/src/filesystem.c

FLT_PREOP_CALLBACK_STATUS
AgentshPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    ULONG processId = HandleToULong(PsGetCurrentProcessId());

    // Skip if this is the agentsh process itself
    if (AgentshIsExcludedProcess(processId)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // ... rest of existing logic
}
```

```c
// drivers/windows/agentsh-minifilter/src/process.c

static volatile ULONG gExcludedProcessId = 0;

BOOLEAN AgentshIsExcludedProcess(ULONG ProcessId) {
    return ProcessId == gExcludedProcessId;
}

void AgentshSetExcludedProcess(ULONG ProcessId) {
    InterlockedExchange(&gExcludedProcessId, ProcessId);
}
```

### User-Mode Integration

```go
// internal/platform/windows/driver_client.go

// ExcludeSelf tells the minifilter to skip file operations from this process
func (c *DriverClient) ExcludeSelf() error {
    pid := uint32(os.Getpid())
    return c.sendMessage(MsgExcludeProcess, pid)
}
```

## Configuration

```go
type FilesystemMode string

const (
    FSModeDisabled FilesystemMode = "disabled"  // No FUSE mount, skip entirely
    FSModeFuse     FilesystemMode = "fuse"      // Require WinFsp/FUSE-T, fail if missing
    FSModeMonitor  FilesystemMode = "monitor"   // Minifilter/FSEvents only (no soft-delete)
)
```

When `FSModeFuse` is set but WinFsp/FUSE-T isn't installed, mount fails with install instructions.
When `FSModeDisabled`, no mount is attempted.

## Migration Plan

1. Create `internal/platform/fuse/` package
2. Move `darwin/fuse_ops.go` → `fuse/ops.go` (extract unix-specific to `ops_unix.go`)
3. Move mount logic from `darwin/filesystem_cgo.go` → `fuse/mount_cgo.go`
4. Simplify `darwin/filesystem.go` to delegate to `fuse.Mount()`
5. Add `fuse/ops_windows.go` with Windows adaptations
6. Update `windows/filesystem.go` to use `fuse.Mount()`
7. Add minifilter exclusion (driver + user-mode)
8. Verify macOS still works (no behavior change)
9. Test Windows implementation

## Testing Strategy

### Unit Tests (no FUSE required)

```go
// internal/platform/fuse/fuse_test.go

func TestPolicyEnforcement(t *testing.T) {
    // Mock PolicyEngine, test checkPolicy returns correct decisions
}

func TestSoftDelete(t *testing.T) {
    // Test file moves to trash, token generated, callback invoked
}

func TestPathConversion(t *testing.T) {
    // Test virtPath/realPath on both Unix and Windows path formats
}
```

### Integration Tests (require FUSE installed)

```go
// internal/platform/fuse/integration_test.go
// //go:build integration && cgo

func TestMount(t *testing.T) {
    if !Available() {
        t.Skip("FUSE not installed")
    }
    // Actually mount, perform operations, verify policy enforcement
}
```

### CI Matrix

| OS | CGO | FUSE Installed | Tests Run |
|----|-----|----------------|-----------|
| Linux | Yes | No | Unit only (fuse package not used on Linux) |
| macOS | Yes | Yes (FUSE-T) | Unit + Integration |
| macOS | No | - | Stub tests only |
| Windows | Yes | Yes (WinFsp) | Unit + Integration |
| Windows | No | - | Stub tests only |

### CI Configuration

```yaml
# .github/workflows/test.yml
jobs:
  test-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install FUSE-T
        run: brew install fuse-t
      - name: Test
        run: go test -tags integration ./internal/platform/...

  test-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install WinFsp
        run: winget install --id WinFsp.WinFsp --accept-source-agreements
      - name: Test
        run: go test -tags integration ./internal/platform/...
```

## Platform Differences Summary

| Aspect | macOS | Windows |
|--------|-------|---------|
| FUSE provider | FUSE-T | WinFsp |
| Install command | `brew install fuse-t` | `winget install WinFsp.WinFsp` |
| Path format | `/path/to/file` | `C:\path\to\file` |
| Mount style | Directory | Directory |
| Chown | Works | No-op |
| Stat fields | `Atimespec`, `Ctimespec` | `Win32FileAttributeData` |
| Symlinks | Standard | Requires privileges |
| Coexistence | FSEvents fallback | Minifilter exclusion |
