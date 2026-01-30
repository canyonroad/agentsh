# macOS Resource Control Design

**Date:** 2026-01-30
**Status:** Approved
**Author:** Claude + Eran

## Overview

macOS lacks kernel-level resource control equivalent to Linux cgroups or Windows Job Objects. This design implements a hybrid approach: kernel-enforced memory limits via `setrlimit()` plus userspace CPU monitoring with SIGSTOP/SIGCONT throttling.

## Feature Matrix

| Resource | Linux | macOS | Windows |
|----------|:-----:|:-----:|:-------:|
| Memory | cgroups | RLIMIT_AS | Job Objects |
| CPU | cgroups | Monitor+throttle | Job Objects |
| Process count | cgroups | **Not supported** | Job Objects |
| Disk I/O | cgroups | **Not supported** | Not supported |
| CPU affinity | cgroups | **Not supported** | Job Objects |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  ResourceLimiter                     │
│  - Available() → true                               │
│  - SupportedLimits() → [Memory, CPU]                │
│  - Apply(config) → ResourceHandle                   │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                  ResourceHandle                      │
│  - AssignProcess(pid)                               │
│    1. setrlimit(RLIMIT_AS, maxMemory) on child      │
│    2. Start cpuMonitor goroutine                    │
│  - Stats() → ResourceStats                          │
│  - Release() → stops monitor, cleanup               │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                   cpuMonitor                         │
│  - Polls proc_pid_rusage() every 500ms              │
│  - Calculates CPU% from delta of cpu_time           │
│  - If CPU% > limit for sustained period:            │
│      SIGSTOP → wait → SIGCONT (throttle)            │
│  - Stops when process exits or Release() called     │
└─────────────────────────────────────────────────────┘
```

## Memory Limiting

### Mechanism

Uses `setrlimit(RLIMIT_AS, ...)` to limit virtual address space. Applied in child process after fork() but before exec().

### Implementation

```go
// In AssignProcess, before the process executes user code:
if h.config.MaxMemoryMB > 0 {
    var limit syscall.Rlimit
    limit.Cur = h.config.MaxMemoryMB * 1024 * 1024
    limit.Max = h.config.MaxMemoryMB * 1024 * 1024
    // Applied via syscall.Setrlimit in the child process setup
}
```

### Sandbox Integration

Since macOS lacks `prlimit()`, the sandbox's process spawning code queries ResourceHandle for rlimits to apply in the child:

```go
// ResourceHandle method for sandbox integration
func (h *ResourceHandle) GetRlimits() []RlimitConfig {
    var limits []RlimitConfig
    if h.rlimitAS > 0 {
        limits = append(limits, RlimitConfig{
            Resource: syscall.RLIMIT_AS,
            Cur:      h.rlimitAS,
            Max:      h.rlimitAS,
        })
    }
    return limits
}
```

### Failure Behavior

When process exceeds RLIMIT_AS, allocations fail with ENOMEM. Most programs crash or exit gracefully. Matches Windows Job Object behavior.

## CPU Monitoring & Throttling

### CPU Usage Calculation

Uses `proc_pid_rusage()` to get CPU time, calculates percentage from delta:

```go
type cpuMonitor struct {
    pid           int
    limitPercent  uint32        // e.g., 50 = 50% of one core
    interval      time.Duration // 500ms
    lastCPUTime   uint64        // nanoseconds from proc_pid_rusage
    lastSample    time.Time
    stopCh        chan struct{}
}

func (m *cpuMonitor) calculateCPUPercent() float64 {
    rusage := getProcPidRusage(m.pid)
    currentCPUTime := rusage.ri_user_time + rusage.ri_system_time

    elapsed := time.Since(m.lastSample)
    cpuDelta := currentCPUTime - m.lastCPUTime

    // CPU% = (cpu time used / wall time elapsed) * 100
    percent := (float64(cpuDelta) / float64(elapsed.Nanoseconds())) * 100

    m.lastCPUTime = currentCPUTime
    m.lastSample = time.Now()
    return percent
}
```

### Throttling Logic

When CPU exceeds limit, uses SIGSTOP/SIGCONT to throttle (matches Linux/Windows behavior):

```go
func (m *cpuMonitor) run() {
    ticker := time.NewTicker(m.interval)
    defer ticker.Stop()

    for {
        select {
        case <-m.stopCh:
            return
        case <-ticker.C:
            if !m.processAlive() {
                return
            }
            cpuPct := m.calculateCPUPercent()
            if cpuPct > float64(m.limitPercent) {
                syscall.Kill(m.pid, syscall.SIGSTOP)
                time.Sleep(m.calculateThrottleDuration(cpuPct))
                syscall.Kill(m.pid, syscall.SIGCONT)
            }
        }
    }
}
```

Throttle duration is proportional to how much the limit was exceeded for smooth throttling.

### Design Decisions

- **500ms polling interval**: Balanced between responsiveness and overhead
- **SIGSTOP/SIGCONT**: Matches Linux cgroups and Windows Job Objects throttling behavior
- **proc_pid_rusage()**: macOS-native API, efficient, provides exactly what we need

## Interface Implementation

### ResourceLimiter

```go
type ResourceLimiter struct {
    available       bool
    supportedLimits []platform.ResourceType
    mu              sync.Mutex
    handles         map[string]*ResourceHandle
}

func NewResourceLimiter() *ResourceLimiter {
    return &ResourceLimiter{
        available: true,
        supportedLimits: []platform.ResourceType{
            platform.ResourceMemory,
            platform.ResourceCPU,
        },
        handles: make(map[string]*ResourceHandle),
    }
}
```

### ResourceHandle

```go
type ResourceHandle struct {
    name       string
    config     platform.ResourceConfig
    mu         sync.Mutex

    // Memory limiting
    rlimitAS   uint64  // RLIMIT_AS value in bytes (0 = no limit)

    // CPU monitoring
    monitor    *cpuMonitor
    pids       []int   // processes assigned to this handle
}
```

### Unsupported Limits

Return clear errors for unsupported resource types:

```go
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
    if config.MaxProcesses > 0 {
        return nil, fmt.Errorf("process count limits not supported on macOS")
    }
    if config.MaxDiskReadMBps > 0 || config.MaxDiskWriteMBps > 0 {
        return nil, fmt.Errorf("disk I/O limits not supported on macOS")
    }
    if len(config.CPUAffinity) > 0 {
        return nil, fmt.Errorf("CPU affinity not supported on macOS")
    }
    // ... create handle with memory + CPU config
}
```

## Lifecycle

1. `Apply()` → creates ResourceHandle with config
2. Sandbox calls `GetRlimits()` → applies in child before exec
3. `AssignProcess(pid)` → starts CPU monitor goroutine
4. Process runs, monitor throttles if needed
5. Process exits → monitor detects and stops
6. `Release()` → cleanup, stop any remaining monitors

## Edge Cases

| Case | Handling |
|------|----------|
| Process exits during SIGSTOP | Monitor checks `processAlive()` before SIGCONT, gracefully exits |
| Process forks children | Children inherit RLIMIT_AS; CPU monitor only tracks assigned PIDs |
| Multiple PIDs assigned | Each gets its own monitor goroutine |
| Release() called while throttled | Send SIGCONT before stopping monitor |
| proc_pid_rusage fails | Log warning, skip throttle cycle, retry next interval |
| Zero CPU limit configured | Skip CPU monitoring entirely |

## Stats Collection

```go
func (h *ResourceHandle) Stats() platform.ResourceStats {
    h.mu.Lock()
    defer h.mu.Unlock()

    stats := platform.ResourceStats{}

    for _, pid := range h.pids {
        if rusage, err := getProcPidRusage(pid); err == nil {
            stats.MemoryMB += rusage.ri_resident_size / (1024 * 1024)
        }
    }

    if h.monitor != nil {
        stats.CPUPercent = h.monitor.lastCPUPercent
    }

    return stats
}
```

## Files to Modify/Create

| File | Change |
|------|--------|
| `internal/platform/darwin/resources.go` | Replace stub with full implementation |
| `internal/platform/darwin/resources_test.go` | Add unit tests |
| `internal/platform/darwin/cpu_monitor.go` | New file: CPU monitoring logic |
| `internal/platform/darwin/cpu_monitor_test.go` | New file: monitor tests |
| `internal/platform/darwin/rusage_darwin.go` | New file: proc_pid_rusage wrapper (cgo) |
| `internal/platform/darwin/sandbox.go` | Integrate rlimit application in spawn path |

## Dependencies

- Uses cgo for `proc_pid_rusage()` (libproc.h)
- No external dependencies

## Testing Approach

- Unit tests with mock process stats
- Integration test that spawns a CPU-intensive process and verifies throttling
- Test memory limit with allocation that exceeds limit

## Why Not Supported

### Process Count (RLIMIT_NPROC)
macOS `RLIMIT_NPROC` is per-user, not per-process-tree. Using it could affect the parent process and other user processes. Memory and CPU limits provide indirect fork bomb protection.

### Disk I/O
macOS has no kernel-level I/O throttling. Userspace monitoring is expensive and imprecise. FUSE-level throttling would only partially work.

### CPU Affinity
macOS `thread_policy_set()` with `THREAD_AFFINITY_POLICY` is only advisory - kernel can ignore it. A flaky implementation is worse than none.
