# Runtime Capability Checks Design

## Problem

Agentsh has sandbox features (seccomp, ptrace, eBPF, cgroups) that can be enabled in config but may not work in certain environments like Firecracker VMs, containers, or systems with older kernels. Currently this causes silent failures or mysterious timeouts instead of clear errors.

## Solution

Add runtime capability checks at daemon startup. If a feature is enabled in config but not available in the environment, exit immediately with a clear error message explaining what's wrong and how to fix it.

## Behavior

- **Hard fail**: Exit with code 1 and clear message (no soft/warning mode)
- **Startup only**: Check once when daemon starts, not on every command
- **Self-contained errors**: Error message includes the fix, no need to search docs

## Architecture

```
internal/capabilities/
├── check.go          # Main CheckAll() function + types
├── seccomp.go        # Seccomp user-notify check
├── ptrace.go         # Ptrace stopped mode check
├── cgroups.go        # Cgroups v2 check
├── ebpf.go           # eBPF check
└── check_test.go     # Tests with build tags
```

### Core Types

```go
type CheckResult struct {
    Feature     string   // e.g., "seccomp-user-notify"
    ConfigKey   string   // e.g., "sandbox.unix_sockets.enabled"
    Available   bool
    Error       error
    Suggestion  string   // e.g., "Set sandbox.unix_sockets.enabled: false"
}
```

### Error Message Format

```
agentsh: capability check failed

  Feature:     seccomp-user-notify
  Config:      sandbox.unix_sockets.enabled = true
  Error:       kernel does not support SECCOMP_RET_USER_NOTIF (requires 5.0+)

  To fix: Set 'sandbox.unix_sockets.enabled: false' in your config
          or upgrade to a kernel that supports this feature.
```

## Capability Checks

### 1. Seccomp User-Notify (`seccomp.go`)

- **Triggered by**: `sandbox.unix_sockets.enabled: true` or `sandbox.seccomp.enabled: true`
- **How**: Install minimal seccomp filter with `SECCOMP_RET_USER_NOTIF`
- **Failure**: Kernel returns `EINVAL` (requires kernel 5.0+, `CONFIG_SECCOMP_FILTER`)
- **Cleanup**: Remove filter after test

### 2. Ptrace Stopped Mode (`ptrace.go`)

- **Triggered by**: `sandbox.cgroups.enabled: true` (cgroup hooks use ptrace)
- **How**: Fork child with `PTRACE_TRACEME`, parent waits and detaches
- **Failure**: Blocked by Yama LSM, seccomp policy, or VM restrictions
- **Note**: Most likely to fail in Firecracker VMs

### 3. Cgroups v2 (`cgroups.go`)

- **Triggered by**: `sandbox.cgroups.enabled: true`
- **How**: Check `/sys/fs/cgroup/cgroup.controllers` exists
- **Failure**: Cgroups v2 not mounted or not available
- **Optional**: Test write permission by creating temp cgroup

### 4. eBPF (`ebpf.go`)

- **Triggered by**: Network monitoring features enabled
- **How**: Load minimal BPF program (trivial socket filter)
- **Failure**: `EPERM` (missing capabilities) or `EINVAL` (unsupported)
- **Requires**: `CAP_BPF` (kernel 5.8+) or `CAP_SYS_ADMIN`

## Config to Check Mapping

| Config Key | Checks Run |
|------------|------------|
| `sandbox.unix_sockets.enabled: true` | Seccomp user-notify |
| `sandbox.cgroups.enabled: true` | Cgroups v2, Ptrace |
| `sandbox.seccomp.enabled: true` | Seccomp user-notify |
| Network monitoring enabled | eBPF |

## Integration

Checks run in `NewApp()` after config load, before HTTP server starts:

```go
func NewApp(cfg *config.Config) (*App, error) {
    // Load config...

    // Check capabilities before proceeding
    if err := capabilities.CheckAll(cfg); err != nil {
        return nil, err
    }

    // Continue with server setup...
}
```

## Testing Strategy

### Build Tags

```go
//go:build capability_tests

func TestSeccompUserNotify(t *testing.T) {
    // Only runs when explicitly requested
}
```

### Mock-Friendly Design

```go
var (
    checkSeccomp = realCheckSeccomp
    checkPtrace  = realCheckPtrace
)

// Tests can swap these out
```

### Test Scenarios

1. All features disabled → No checks run, no errors
2. Feature enabled + available → Check passes, daemon starts
3. Feature enabled + unavailable → Check fails, clear error, exit 1
4. Multiple failures → All failures reported together

### CI

- Run capability tests on Linux runners only
- Skip on macOS/Windows (features are Linux-only)
- Each check has timeout and panic recovery

## Edge Cases

- **Check crashes**: Each check runs with timeout and recovers from panics
- **Multiple failures**: All failures collected and reported together
- **Partial support**: Some features may work partially; checks test the specific functionality agentsh needs
