# macOS FUSE-T Implementation Design

**Date:** 2025-12-31
**Status:** Implemented

## Summary

Implement FUSE-T filesystem mounting for macOS to enable file policy enforcement. Uses cgofuse library with graceful fallback to FSEvents observation-only mode when CGO is unavailable or FUSE-T is not installed.

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| FUSE library | cgofuse for macOS, keep go-fuse for Linux | cgofuse has FUSE-T support (v1.6.0+), go-fuse doesn't |
| CGO handling | Graceful fallback | Build with CGO when available, FSEvents fallback otherwise |
| Code location | Platform abstraction layer | Fits existing `internal/platform/darwin/` architecture |
| Build structure | Separate files with build tags | Clean separation, matches codebase patterns |
| Operation coverage | Full parity with Linux | All operations that Linux enforces |

## Architecture

```
internal/platform/darwin/
├── filesystem.go           # Shared types, Available(), Implementation()
├── filesystem_cgo.go       # //go:build darwin && cgo
│                           # cgofuse-based FUSE-T mounting
├── filesystem_nocgo.go     # //go:build darwin && !cgo
│                           # Returns error, defers to FSEvents
├── fsevents.go             # Observation-only fallback (exists)
├── fuse_node.go            # //go:build darwin && cgo
│                           # Policy-enforcing filesystem implementation
└── fuse_filehandle.go      # //go:build darwin && cgo
                            # Read/Write interception
```

### How It Works

1. When `Filesystem.Mount()` is called:
   - **With CGO**: `filesystem_cgo.go` creates a cgofuse `FileSystemHost`, mounts at the specified path, and returns a `FuseMount` that wraps the cgofuse handle
   - **Without CGO**: `filesystem_nocgo.go` returns an error indicating FUSE is unavailable; caller falls back to FSEvents observation mode

2. The cgofuse filesystem implements `fuse.FileSystemInterface` and delegates to a loopback of the real directory, intercepting each operation to:
   - Check policy via `PolicyEngine.CheckFile()`
   - Handle approvals via `ApprovalManager`
   - Emit events via `Emitter`
   - Return `EACCES` on deny, proceed on allow

3. Runtime detection: Even with CGO, we check if FUSE-T is actually installed before attempting mount. If not installed, return helpful error.

## cgofuse Integration

**Dependency:**
```go
import "github.com/winfsp/cgofuse/fuse"
```

**API Mapping (cgofuse → policy operations):**

| cgofuse Method | Policy Operation | Notes |
|----------------|------------------|-------|
| `Open(path, flags)` | `open`, `read`, `write` | Check flags for R/W |
| `Create(path, flags, mode)` | `create` | New file |
| `Unlink(path)` | `delete` | Remove file |
| `Rmdir(path)` | `rmdir` | Remove directory |
| `Rename(oldpath, newpath)` | `rename` | Check both paths |
| `Mkdir(path, mode)` | `mkdir` | Create directory |
| `Chmod(path, mode)` | `chmod` | Change permissions |
| `Read(path, buff, ofst, fh)` | `read` | File content read |
| `Write(path, buff, ofst, fh)` | `write` | File content write |
| `Symlink(target, newpath)` | `create` | Create symlink |
| `Link(oldpath, newpath)` | `create` | Create hard link |
| `Readlink(path)` | `readlink` | Read symlink target |
| `Truncate(path, size)` | `write` | Resize file |

**Core struct:**

```go
// fuse_node.go
type fuseFS struct {
    fuse.FileSystemBase  // Embed for default implementations
    realRoot    string
    hooks       *FuseHooks
    openFiles   sync.Map  // fh -> *openFile for Read/Write tracking
    nextHandle  uint64
}

type FuseHooks struct {
    Policy    PolicyEngine
    Approvals ApprovalManager
    Emitter   EventEmitter
    SessionID string
}
```

The `FileSystemBase` provides safe defaults (return `-ENOSYS`) for unimplemented operations, so we only override what we need.

## Mount Lifecycle

**Mount flow:**

```go
// filesystem_cgo.go
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
    // 1. Check FUSE-T is installed
    if !fs.Available() {
        return nil, fmt.Errorf("FUSE-T not installed: brew install fuse-t")
    }

    // 2. Verify source path exists
    if _, err := os.Stat(cfg.SourcePath); err != nil {
        return nil, fmt.Errorf("source path: %w", err)
    }

    // 3. Create mount point if needed
    if err := os.MkdirAll(cfg.MountPoint, 0755); err != nil {
        return nil, fmt.Errorf("create mount point: %w", err)
    }

    // 4. Create filesystem with hooks
    fuseFS := newFuseFS(cfg.SourcePath, &FuseHooks{
        Policy:    cfg.PolicyEngine,
        Approvals: cfg.Approvals,
        Emitter:   cfg.EventChannel,
        SessionID: cfg.SessionID,
    })

    // 5. Create and start host
    host := fuse.NewFileSystemHost(fuseFS)

    // 6. Mount in background goroutine
    mounted := make(chan error, 1)
    go func() {
        ok := host.Mount(cfg.MountPoint, nil)  // nil = default options
        if !ok {
            mounted <- fmt.Errorf("cgofuse mount failed")
        }
        close(mounted)
    }()

    // 7. Wait for mount or timeout
    select {
    case err := <-mounted:
        if err != nil {
            return nil, err
        }
    case <-time.After(5 * time.Second):
        host.Unmount()
        return nil, fmt.Errorf("mount timeout")
    }

    return &FuseMount{host: host, path: cfg.MountPoint, source: cfg.SourcePath}, nil
}
```

**Unmount:**
```go
func (m *FuseMount) Close() error {
    m.host.Unmount()
    return nil
}
```

## Policy Enforcement

**Core pattern for each operation:**

```go
func (f *fuseFS) Unlink(path string) int {
    // 1. Resolve to virtual path (what agent sees)
    virtPath := filepath.Join("/workspace", path)

    // 2. Check policy
    dec := f.hooks.Policy.CheckFile(virtPath, "delete")

    // 3. Handle approval if needed
    if dec.PolicyDecision == types.DecisionApprove {
        dec = f.handleApproval(virtPath, "delete", dec)
    }

    // 4. Emit event (before action, includes decision)
    f.emitFileEvent("file_delete", virtPath, "delete", dec, dec.EffectiveDecision == types.DecisionDeny)

    // 5. Deny if not allowed
    if dec.EffectiveDecision == types.DecisionDeny {
        return -fuse.EACCES
    }

    // 6. Handle soft-delete redirect
    if dec.PolicyDecision == types.DecisionSoftDelete {
        return f.softDelete(path, virtPath)
    }

    // 7. Perform actual operation on real filesystem
    realPath := filepath.Join(f.realRoot, path)
    if err := os.Remove(realPath); err != nil {
        return f.toErrno(err)
    }

    return 0
}
```

**Decision handling:**

| Decision | Behavior |
|----------|----------|
| `allow` | Proceed with operation |
| `deny` | Return `-EACCES`, emit blocked event |
| `approve` | Block until approval received or timeout |
| `soft_delete` | Move to trash instead of delete |
| `redirect` | Rewrite path to redirect target |
| `audit` | Allow + emit enhanced audit event |

## Build Configuration

**go.mod addition:**
```go
require (
    github.com/winfsp/cgofuse v1.6.0  // FUSE-T support
)
```

**Build tags:**

```go
// filesystem_cgo.go
//go:build darwin && cgo

// filesystem_nocgo.go
//go:build darwin && !cgo
```

**Build commands:**
```bash
# With FUSE-T support (default on macOS with Xcode tools)
go build ./...

# Explicitly disable CGO (FSEvents fallback only)
CGO_ENABLED=0 go build ./...

# Cross-compile from Linux (no CGO, fallback mode)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build ./...
```

## Testing Strategy

| Test Type | Location | Approach |
|-----------|----------|----------|
| Unit tests | `filesystem_cgo_test.go` | Mock cgofuse, test policy logic |
| Integration | `internal/integration/` | Real FUSE mount (requires FUSE-T) |
| CI (Linux) | GitHub Actions | Skip darwin CGO tests |
| CI (macOS) | GitHub Actions macos-latest | Install FUSE-T, run full tests |

**CI setup for macOS:**
```yaml
- name: Install FUSE-T
  if: runner.os == 'macOS'
  run: brew install fuse-t

- name: Test with FUSE
  if: runner.os == 'macOS'
  run: go test -v ./internal/platform/darwin/...
```

## Implementation Plan

1. Add cgofuse dependency to go.mod
2. Create `filesystem_nocgo.go` with stub returning error
3. Create `filesystem_cgo.go` with Mount/Unmount logic
4. Create `fuse_node.go` with fuseFS implementing FileSystemInterface
5. Implement each operation with policy enforcement
6. Add unit tests for policy logic
7. Update SECURITY.md to reflect new capabilities
8. Test on macOS with FUSE-T installed
