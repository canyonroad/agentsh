# macOS RLIMIT_AS Enforcement via Wrapper Binary

**Date:** 2026-01-30
**Status:** Draft
**Author:** Claude + Eran

## Overview

Implement memory limiting on macOS using RLIMIT_AS via a wrapper binary approach. Since macOS lacks `prlimit()` and Go's `exec.Cmd` doesn't support setting rlimits in `SysProcAttr`, we use a wrapper binary that sets rlimits on itself before exec'ing the target command.

## Why a Wrapper Binary?

| Approach | Viable? | Why |
|----------|---------|-----|
| Go SysProcAttr | ❌ | No rlimit fields on darwin |
| prlimit() from parent | ❌ | Doesn't exist on macOS |
| setrlimit() from parent | ❌ | Only affects calling process |
| Post-fork hook | ❌ | Runs in parent, not child |
| **Wrapper binary** | ✅ | Sets limit on self, then exec's target |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Execution Flow                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  agentsh server                                              │
│       │                                                      │
│       ▼                                                      │
│  ExecuteWithResources(rh, "bash", "-c", "cmd")              │
│       │                                                      │
│       ▼                                                      │
│  Check rh.GetRlimits() → has RLIMIT_AS?                     │
│       │                                                      │
│       ▼ yes                                                  │
│  Wrap command:                                               │
│    env AGENTSH_RLIMIT_AS=268435456 \                        │
│    agentsh-rlimit-exec bash -c "cmd"                        │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────────────────────────────────┐                │
│  │       agentsh-rlimit-exec               │                │
│  │  1. Parse AGENTSH_RLIMIT_AS             │                │
│  │  2. setrlimit(RLIMIT_AS, 256MB)         │                │
│  │  3. exec("bash", "-c", "cmd")           │                │
│  └─────────────────────────────────────────┘                │
│                      │                                       │
│                      ▼                                       │
│  ┌─────────────────────────────────────────┐                │
│  │            bash -c "cmd"                 │                │
│  │      (inherits 256MB rlimit)            │                │
│  └─────────────────────────────────────────┘                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Wrapper Binary

### Usage

```bash
# Via environment variable
AGENTSH_RLIMIT_AS=268435456 agentsh-rlimit-exec bash -c "command"

# Limit is in bytes (256MB = 268435456)
```

### Implementation

```go
// cmd/agentsh-rlimit-exec/main.go
package main

import (
    "fmt"
    "os"
    "strconv"

    "golang.org/x/sys/unix"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Fprintln(os.Stderr, "usage: agentsh-rlimit-exec <command> [args...]")
        os.Exit(1)
    }

    // Apply RLIMIT_AS if set
    if limitStr := os.Getenv("AGENTSH_RLIMIT_AS"); limitStr != "" {
        limit, err := strconv.ParseUint(limitStr, 10, 64)
        if err != nil {
            fmt.Fprintf(os.Stderr, "invalid AGENTSH_RLIMIT_AS: %v\n", err)
            os.Exit(1)
        }
        rlimit := unix.Rlimit{Cur: limit, Max: limit}
        if err := unix.Setrlimit(unix.RLIMIT_AS, &rlimit); err != nil {
            fmt.Fprintf(os.Stderr, "setrlimit failed: %v\n", err)
            os.Exit(1)
        }
    }

    // Exec the command (replaces this process)
    cmd := os.Args[1]
    args := os.Args[1:] // includes cmd as args[0]

    // Look up full path if needed
    path, err := exec.LookPath(cmd)
    if err != nil {
        fmt.Fprintf(os.Stderr, "command not found: %s\n", cmd)
        os.Exit(127)
    }

    // Exec - this replaces the current process
    if err := unix.Exec(path, args, os.Environ()); err != nil {
        fmt.Fprintf(os.Stderr, "exec failed: %v\n", err)
        os.Exit(126)
    }
}
```

## Integration

### sandbox_resources.go Changes

```go
func (s *Sandbox) ExecuteWithResources(ctx context.Context, rh *ResourceHandle, cmd string, args ...string) (*platform.ExecResult, error) {
    // ... existing checks ...

    // Wrap command if memory limits are configured
    actualCmd := cmd
    actualArgs := args
    var extraEnv []string

    if rh != nil {
        rlimits := rh.GetRlimits()
        for _, rl := range rlimits {
            if rl.Resource == unix.RLIMIT_AS && rl.Cur > 0 {
                // Prepend wrapper
                actualCmd = "agentsh-rlimit-exec"
                actualArgs = append([]string{cmd}, args...)
                extraEnv = append(extraEnv, fmt.Sprintf("AGENTSH_RLIMIT_AS=%d", rl.Cur))
                break
            }
        }
    }

    // ... rest of execution with actualCmd, actualArgs, extraEnv ...
}
```

### resources.go Changes

Re-add `ResourceMemory` to supported limits:

```go
func NewResourceLimiter() *ResourceLimiter {
    return &ResourceLimiter{
        available: true,
        supportedLimits: []platform.ResourceType{
            platform.ResourceMemory,  // Now supported via wrapper
            platform.ResourceCPU,
        },
        handles: make(map[string]*ResourceHandle),
    }
}
```

Remove the error for MaxMemoryMB in Apply():

```go
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
    // Remove this check - memory is now supported:
    // if config.MaxMemoryMB > 0 {
    //     return nil, fmt.Errorf("memory limits not yet implemented...")
    // }

    // ... rest unchanged ...
}
```

## Testing

1. **Unit test wrapper binary** - verify rlimit is set correctly
2. **Integration test** - spawn process with memory limit, verify it's enforced
3. **Failure test** - process exceeding limit gets ENOMEM

## Files to Create/Modify

| File | Change |
|------|--------|
| `cmd/agentsh-rlimit-exec/main.go` | New wrapper binary |
| `internal/platform/darwin/sandbox_resources.go` | Use wrapper when rlimits configured |
| `internal/platform/darwin/resources.go` | Re-add ResourceMemory support |
| `internal/platform/darwin/resources_test.go` | Update tests for memory support |

## Limitations

1. **RLIMIT_AS limits virtual address space**, not RSS
2. Child processes inherit the limit (desired behavior)
3. Wrapper must be in PATH or use absolute path
