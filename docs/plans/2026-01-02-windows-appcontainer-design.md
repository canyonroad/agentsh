# Windows AppContainer Sandbox Implementation Design

**Date:** 2026-01-02
**Status:** Implemented

## Summary

Implement AppContainer-based process isolation for Windows to provide defense-in-depth sandboxing. Works alongside the existing minifilter driver for maximum security, with configurable layers for different use cases.

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Primary isolation | AppContainer | Kernel-enforced capability isolation, closest to Linux namespaces |
| Secondary layer | Minifilter integration | Policy-based rules on top of capability isolation |
| Path access | Configurable via AllowedPaths | Matches Linux sandbox behavior |
| Network access | Configurable capabilities | Fine-grained control (none/outbound/local/full) |
| Fallback behavior | Fail hard by default | Secure by default, explicit opt-out for lower security |
| Both layers | Configurable | Users choose security/performance tradeoff |

## Configuration Model

Extended `SandboxConfig` with Windows-specific options:

```go
// SandboxConfig (extended for Windows)
type SandboxConfig struct {
    // Existing fields
    Name          string
    WorkspacePath string
    AllowedPaths  []string
    Capabilities  []string
    Environment   map[string]string

    // New Windows-specific fields (ignored on other platforms)
    WindowsOptions *WindowsSandboxOptions
}

type WindowsSandboxOptions struct {
    // Isolation mechanism
    UseAppContainer  bool  // Default: true (most secure)
    UseMinifilter    bool  // Default: true (policy enforcement)

    // Network capabilities (only if UseAppContainer)
    NetworkAccess    NetworkAccessLevel

    // Fallback behavior
    FailOnAppContainerError bool  // Default: true (fail hard)
}

type NetworkAccessLevel int
const (
    NetworkNone        NetworkAccessLevel = iota  // No network
    NetworkOutbound                               // Internet client only
    NetworkLocal                                  // Private network only
    NetworkFull                                   // All network access
)
```

### Security Levels

| UseAppContainer | UseMinifilter | Security | Use Case |
|-----------------|---------------|----------|----------|
| ✓ | ✓ | Maximum | AI agent execution |
| ✓ | ✗ | High | Isolated dev environment |
| ✗ | ✓ | Medium | Policy enforcement only |
| ✗ | ✗ | None | Unsandboxed (legacy) |

## AppContainer vs Minifilter

| Aspect | AppContainer | Minifilter |
|--------|--------------|------------|
| **Enforcement** | Kernel capability check | Filter driver intercept |
| **Bypass risk** | Very low (kernel boundary) | Low (requires driver bug) |
| **Granularity** | Path-based capabilities | Policy rule-based |
| **Registry** | Isolated by default | Rule-based allow/deny |
| **Network** | Capability flags | Not applicable |
| **Overhead** | Process startup cost | Per-operation cost |
| **Requires** | Windows 8+, admin for setup | Driver loaded |

**Why both?** Defense in depth. AppContainer provides kernel-level isolation that cannot be bypassed even if minifilter has bugs. Minifilter adds fine-grained policy rules. Two independent failures required for an attack to succeed.

## Implementation

### AppContainer Lifecycle

```go
// Lifecycle for AppContainer sandbox:

1. CreateAppContainerProfile()
   - Creates a named container with a unique SID
   - Container name: "agentsh-sandbox-{id}"
   - Persists in registry until deleted

2. Grant capabilities to container SID:
   - Translate AllowedPaths → Object capabilities
   - SetNamedSecurityInfo() to add container SID to each path's ACL
   - Add network capabilities if configured

3. CreateProcess() with SECURITY_CAPABILITIES:
   - Token includes AppContainer SID
   - Process runs at Low integrity level
   - Kernel enforces capability restrictions

4. Cleanup on sandbox Close():
   - Terminate child processes
   - DeleteAppContainerProfile()
   - Remove granted ACLs from paths
```

### Path Translation

```go
// AllowedPaths: ["C:\Users\dev\workspace", "C:\Go\bin"]
//
// Translates to:
// 1. Add container SID to C:\Users\dev\workspace ACL (full access)
// 2. Add container SID to C:\Go\bin ACL (read/execute)
// 3. Inherit to subdirectories
```

### Minifilter Integration

```go
// Before CreateProcess:
if opts.UseMinifilter && driverClient.Connected() {
    // Register sandbox PID for additional policy enforcement
    driverClient.RegisterSandboxProcess(pid, sessionToken)
}

// On Close:
driverClient.UnregisterSandboxProcess(pid)
```

## Code Structure

```
internal/platform/windows/
├── sandbox.go              # Existing - update with new implementation
├── appcontainer.go         # NEW - AppContainer API wrappers
├── appcontainer_test.go    # NEW - Unit tests
└── sandbox_test.go         # Existing - extend with integration tests
```

### Key Types

```go
// appContainer wraps Windows AppContainer APIs
type appContainer struct {
    name        string           // "agentsh-sandbox-{id}"
    sid         *windows.SID     // Container security identifier
    profile     windows.Handle   // Profile handle
    grantedACLs []string         // Paths we modified (for cleanup)
}

// createAppContainer creates a new container profile
func createAppContainer(name string) (*appContainer, error)

// grantPathAccess adds container SID to path's ACL
func (c *appContainer) grantPathAccess(path string, accessMode AccessMode) error

// setNetworkCapabilities enables network access
func (c *appContainer) setNetworkCapabilities(level NetworkAccessLevel) error

// createProcess spawns process inside container
func (c *appContainer) createProcess(ctx context.Context, cmd string, args []string, env []string, workDir string) (*os.Process, error)

// cleanup removes profile and reverts ACLs
func (c *appContainer) cleanup() error
```

### Updated Sandbox Struct

```go
type Sandbox struct {
    id            string
    config        platform.SandboxConfig
    mu            sync.Mutex
    closed        bool

    // New fields
    container     *appContainer        // nil if UseAppContainer=false
    driverClient  *DriverClient        // For minifilter integration
    childPIDs     []uint32             // Track for cleanup
}
```

## Error Handling

```go
func (s *Sandbox) Execute(ctx context.Context, cmd string, args ...string) (*platform.ExecResult, error) {
    opts := s.config.WindowsOptions
    if opts == nil {
        opts = defaultWindowsOptions() // UseAppContainer=true, UseMinifilter=true
    }

    // Try AppContainer if enabled
    if opts.UseAppContainer {
        result, err := s.executeInAppContainer(ctx, cmd, args)
        if err == nil {
            return result, nil
        }

        // AppContainer failed - check fallback policy
        if opts.FailOnAppContainerError {
            return nil, fmt.Errorf("AppContainer execution failed: %w", err)
        }

        // Log warning and fall through to restricted token
        log.Warn("AppContainer failed, falling back to restricted token",
            "error", err)
    }

    // Fallback: restricted token (or no isolation if both disabled)
    if opts.UseMinifilter {
        return s.executeWithMinifilterOnly(ctx, cmd, args)
    }

    return s.executeUnsandboxed(ctx, cmd, args)
}
```

### Failure Scenarios

| Error | Cause | Behavior (default) |
|-------|-------|-------------------|
| `ERROR_ACCESS_DENIED` | No admin rights for profile creation | Fail with clear message |
| `ERROR_ALREADY_EXISTS` | Container name collision | Generate new unique name, retry |
| `ERROR_NOT_SUPPORTED` | Windows 7 or older | Fail, suggest WSL2 |
| Path ACL failed | Permission denied on AllowedPath | Fail, list which path failed |
| Minifilter not connected | Driver not loaded | Continue without minifilter layer |

### Cleanup on Failure

```go
func (c *appContainer) cleanup() error {
    var errs []error

    // 1. Revert ACLs we modified
    for _, path := range c.grantedACLs {
        if err := c.revokePathAccess(path); err != nil {
            errs = append(errs, err)
        }
    }

    // 2. Delete container profile
    if err := deleteAppContainerProfile(c.name); err != nil {
        errs = append(errs, err)
    }

    return errors.Join(errs...)
}
```

## Testing Strategy

### Unit Tests (no Windows required)

```go
// appcontainer_test.go

func TestPathToCapability(t *testing.T) {
    // Test path translation logic
}

func TestNetworkCapabilities(t *testing.T) {
    // Test capability flag generation
}

func TestConfigDefaults(t *testing.T) {
    // Verify secure defaults
    opts := defaultWindowsOptions()
    assert.True(t, opts.UseAppContainer)
    assert.True(t, opts.UseMinifilter)
    assert.True(t, opts.FailOnAppContainerError)
    assert.Equal(t, NetworkNone, opts.NetworkAccess)
}
```

### Integration Tests (require Windows + admin)

```go
// sandbox_test.go
//go:build windows && integration

func TestAppContainerIsolation(t *testing.T) {
    // Test that processes cannot access paths outside AllowedPaths
}

func TestMinifilterIntegration(t *testing.T) {
    // Test that sandboxed process PIDs are registered with minifilter
}
```

### CI Configuration

```yaml
test-windows-sandbox:
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
    - name: Run unit tests
      run: go test ./internal/platform/windows/... -v
    - name: Run integration tests (admin)
      run: go test -tags=integration ./internal/platform/windows/... -v
```

## Documentation Updates

### platform-comparison.md

Add sandbox configuration comparison table and AppContainer vs Minifilter comparison.

### windows-driver-deployment.md

Add sandbox integration section showing how to configure `WindowsSandboxOptions`.

## Performance Expectations

| Configuration | Startup Overhead | Per-Operation Overhead |
|---------------|------------------|------------------------|
| AppContainer + Minifilter | ~5-10ms | ~1-5µs (cached) |
| AppContainer only | ~3-5ms | None |
| Minifilter only | <1ms | ~1-5µs (cached) |
| Neither | Baseline | Baseline |

## Security Score Impact

This implementation raises Windows Native security score:
- Before: 75% (Partial isolation via minifilter)
- After: 85% (AppContainer + minifilter defense-in-depth)

Remaining gap vs Linux (100%):
- No syscall filtering (no seccomp equivalent)
- No full namespace isolation (AppContainer is capability-based, not namespace-based)
