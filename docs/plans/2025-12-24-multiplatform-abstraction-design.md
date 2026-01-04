# Multi-Platform Abstraction Layer Design

**Date:** 2025-12-24
**Status:** Implemented
**Spec Reference:** `docs/agent-multiplatform-spec.md`

## Summary

Create a platform abstraction layer that enables cross-platform support for agentsh. Start by refactoring the existing Linux implementation to use the new abstractions, validating the interface design with working code, then add macOS and Windows implementations.

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Implementation approach | Interface + Linux refactor first | Validates abstractions with real code |
| FUSE library strategy | Abstract at higher level | `FilesystemInterceptor` hides FUSE; each platform chooses best approach |
| Component priority | Filesystem first | Most mature Linux code; establishes pattern for others |
| Directory structure | `internal/platform/` | Matches existing pattern; can promote to `pkg/` later |
| Interception model | Include hold/redirect/approve from start | Avoids retrofitting later |
| Refactor approach | New structure, then migrate | Doesn't break existing functionality |
| Testing strategy | Port existing tests | Ensures feature parity |

## Directory Structure

```
internal/platform/
├── interfaces.go          # Core interfaces
├── types.go               # Shared types (Capabilities, Decision, etc.)
├── factory.go             # Platform detection and instantiation
├── linux/
│   ├── platform.go        # LinuxPlatform implementation
│   ├── filesystem.go      # FUSE-based FilesystemInterceptor
│   ├── filesystem_test.go # Ported tests from fsmonitor
│   ├── interception.go    # InterceptionManager implementation
│   ├── network.go         # (phase 2)
│   ├── sandbox.go         # (phase 2)
│   └── resources.go       # (phase 2)
├── darwin/
│   ├── platform.go        # Stub platform
│   └── filesystem.go      # Stub filesystem
└── windows/
    ├── platform.go        # Stub platform
    └── filesystem.go      # Stub filesystem
```

## Core Interfaces

```go
// internal/platform/interfaces.go

type Platform interface {
    Name() string
    Capabilities() Capabilities

    Filesystem() FilesystemInterceptor
    Network() NetworkInterceptor      // phase 2
    Sandbox() SandboxManager          // phase 2
    Resources() ResourceLimiter       // phase 2

    Initialize(ctx context.Context, config Config) error
    Shutdown(ctx context.Context) error
}

type FilesystemInterceptor interface {
    Mount(config FSConfig) (FSMount, error)
    Unmount(mount FSMount) error
    Available() bool
    Implementation() string  // "fuse3", "fuse-t", "winfsp", etc.
}

type FSMount interface {
    Path() string
    Stats() FSStats
    Close() error
}

type FSConfig struct {
    SourcePath   string
    MountPoint   string
    PolicyEngine PolicyEngine
    EventChannel chan<- IOEvent
    Interceptor  InterceptionManager
    Options      map[string]string
}

type InterceptionManager interface {
    Intercept(ctx context.Context, op *InterceptedOperation) DecisionResponse
    Approve(opID string, approved bool, redirect *RedirectTarget) error
}
```

## Migration Path

**Before (current):**
```go
import "agentsh/internal/fsmonitor"
mount, err := fsmonitor.Mount(workspace, policy, eventChan)
```

**After (new):**
```go
import "agentsh/internal/platform"
plat, err := platform.New()
mount, err := plat.Filesystem().Mount(platform.FSConfig{...})
```

## Implementation Phases

### Phase 1: Foundation (Filesystem) - Current Focus

1. **Directory & Interface Setup**
   - Create `internal/platform/` directory structure
   - Write `interfaces.go` with Platform, FilesystemInterceptor, FSMount, InterceptionManager
   - Write `types.go` with Capabilities, Decision, DecisionResponse, IsolationLevel
   - Write `factory.go` with `New()` and `NewWithMode()` functions

2. **Linux Implementation**
   - Create `internal/platform/linux/` directory
   - `platform.go` - LinuxPlatform struct, capability detection
   - `filesystem.go` - LinuxFilesystem wrapping go-fuse
   - `interception.go` - InterceptionManager implementation

3. **FUSE Code Migration**
   - Adapt `fsmonitor/fuse.go` core logic to new structure
   - Integrate InterceptionManager for hold/redirect/approve
   - Wire up PolicyEngine and event emission
   - Handle soft-delete/trash integration

4. **Testing**
   - Port `fsmonitor/*_test.go` to `internal/platform/linux/`
   - Ensure all existing test cases pass
   - Add interface-level tests

5. **Stubs**
   - `internal/platform/darwin/` - stub platform and filesystem
   - `internal/platform/windows/` - stub platform and filesystem

6. **Caller Migration**
   - Update `internal/api/core.go` to use `platform.New()`
   - Update other direct fsmonitor users
   - Run smoke tests to validate end-to-end

### Phase 2: Network Interception
- Apply same pattern to `NetworkInterceptor`
- Port from `netmonitor/` (proxy, DNS, eBPF)
- Linux implementation, stubs for others

### Phase 3: Sandbox & Resources
- `SandboxManager` - namespaces, seccomp
- `ResourceLimiter` - cgroups v2
- Port from `limits/` and namespace code

### Phase 4: Environment Protection
- Integrate `InterceptionManager` for env vars
- LD_PRELOAD shim integration
- Spawn-time filtering in platform layer

### Phase 5: Mac/Windows Implementations
- Implement on actual macOS machine (FUSE-T, pf)
- Implement on Windows machine (WinFsp, WinDivert)
- Platform-specific tests

## Platform Stubs

Darwin and Windows stubs compile but return "not available":

```go
//go:build darwin

type DarwinFilesystem struct{}

func (fs *DarwinFilesystem) Available() bool {
    return false
}

func (fs *DarwinFilesystem) Mount(config FSConfig) (FSMount, error) {
    return nil, fmt.Errorf("filesystem interception not yet implemented on macOS")
}
```

Capabilities reporting reflects actual availability:
```go
func (p *DarwinPlatform) Capabilities() Capabilities {
    return Capabilities{
        HasFUSE:             false,
        HasNetworkIntercept: false,
        IsolationLevel:      IsolationNone,
    }
}
```

## Testing Notes

- Linux can be fully tested on current machine
- macOS/Windows implementations will be tested when moved to those platforms
- Interface-level tests should be platform-agnostic where possible
- Smoke tests validate end-to-end after caller migration

## Future Considerations

- May migrate Linux from go-fuse to cgofuse for consistency
- Platform interfaces in `internal/` can promote to `pkg/` if external use needed
- InterceptionManager is shared infrastructure for all interceptor types
