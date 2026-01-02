# Windows Mini Filter Phase 5: Hardening & Production Readiness

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden the Windows mini filter driver for production use with configurable fail modes, comprehensive metrics, ETW logging, and deployment documentation.

**Architecture:** Add configuration structures for runtime tuning, expose metrics via IOCTL, integrate ETW for SIEM-compatible event logging, and provide comprehensive documentation for production deployment with code signing.

**Tech Stack:** C (WDK), Go, ETW (Event Tracing for Windows), IOCTL, EV code signing

---

## Prerequisites

- Phase 4 complete (registry interception)
- Working in worktree: `/home/eran/work/agentsh/.worktrees/feature-windows-minifilter`

---

## Task 1: Add Configuration Structures to Protocol

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/inc/protocol.h`

**Step 1: Add fail mode and configuration enums**

Add after `AGENTSH_REGISTRY_REQUEST` struct:

```c
// Fail mode configuration
typedef enum _AGENTSH_FAIL_MODE {
    FAIL_MODE_OPEN = 0,     // Allow operations on failure (default)
    FAIL_MODE_CLOSED = 1,   // Deny operations on failure
} AGENTSH_FAIL_MODE;

// Driver configuration (user-mode -> driver)
typedef struct _AGENTSH_CONFIG {
    AGENTSH_MESSAGE_HEADER Header;
    AGENTSH_FAIL_MODE FailMode;
    ULONG PolicyQueryTimeoutMs;     // Default: 5000
    ULONG MaxConsecutiveFailures;   // Default: 10
    ULONG CacheMaxEntries;          // Default: 4096
    ULONG CacheDefaultTTLMs;        // Default: 5000
} AGENTSH_CONFIG, *PAGENTSH_CONFIG;

// Driver metrics (driver -> user-mode)
typedef struct _AGENTSH_METRICS {
    AGENTSH_MESSAGE_HEADER Header;
    // Cache metrics
    ULONG CacheHitCount;
    ULONG CacheMissCount;
    ULONG CacheEntryCount;
    ULONG CacheEvictionCount;
    // Query metrics
    ULONG FilePolicyQueries;
    ULONG RegistryPolicyQueries;
    ULONG PolicyQueryTimeouts;
    ULONG PolicyQueryFailures;
    // Decision metrics
    ULONG AllowDecisions;
    ULONG DenyDecisions;
    // Session metrics
    ULONG ActiveSessions;
    ULONG TrackedProcesses;
    // Status
    BOOLEAN FailOpenMode;
    ULONG ConsecutiveFailures;
} AGENTSH_METRICS, *PAGENTSH_METRICS;

// Message types for config and metrics
#define MSG_SET_CONFIG      104
#define MSG_GET_METRICS     105
#define MSG_METRICS_REPLY   106
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/protocol.h
git commit -m "feat(windows): add configuration and metrics protocol structures"
```

---

## Task 2: Create Metrics Module

**Files:**
- Create: `drivers/windows/agentsh-minifilter/inc/metrics.h`
- Create: `drivers/windows/agentsh-minifilter/src/metrics.c`

**Step 1: Write metrics.h**

```c
// metrics.h - Driver metrics collection
#ifndef _AGENTSH_METRICS_H_
#define _AGENTSH_METRICS_H_

#include <fltKernel.h>
#include "protocol.h"

// Initialize metrics
VOID AgentshInitializeMetrics(VOID);

// Increment counters (thread-safe)
VOID AgentshMetricsIncrementCacheHit(VOID);
VOID AgentshMetricsIncrementCacheMiss(VOID);
VOID AgentshMetricsIncrementCacheEviction(VOID);
VOID AgentshMetricsIncrementFilePolicyQuery(VOID);
VOID AgentshMetricsIncrementRegistryPolicyQuery(VOID);
VOID AgentshMetricsIncrementPolicyTimeout(VOID);
VOID AgentshMetricsIncrementPolicyFailure(VOID);
VOID AgentshMetricsIncrementAllowDecision(VOID);
VOID AgentshMetricsIncrementDenyDecision(VOID);

// Set/get values
VOID AgentshMetricsSetActiveSessionCount(ULONG count);
VOID AgentshMetricsSetTrackedProcessCount(ULONG count);
VOID AgentshMetricsSetCacheEntryCount(ULONG count);
VOID AgentshMetricsSetFailOpenMode(BOOLEAN enabled);
VOID AgentshMetricsSetConsecutiveFailures(ULONG count);

// Get metrics snapshot
VOID AgentshMetricsGet(_Out_ PAGENTSH_METRICS metrics);

// Reset counters
VOID AgentshMetricsReset(VOID);

#endif // _AGENTSH_METRICS_H_
```

**Step 2: Write metrics.c**

```c
// metrics.c - Driver metrics collection
#include "driver.h"
#include "metrics.h"

// Global metrics
static struct {
    volatile LONG CacheHitCount;
    volatile LONG CacheMissCount;
    volatile LONG CacheEvictionCount;
    volatile LONG FilePolicyQueries;
    volatile LONG RegistryPolicyQueries;
    volatile LONG PolicyQueryTimeouts;
    volatile LONG PolicyQueryFailures;
    volatile LONG AllowDecisions;
    volatile LONG DenyDecisions;
    volatile LONG ActiveSessions;
    volatile LONG TrackedProcesses;
    volatile LONG CacheEntryCount;
    volatile BOOLEAN FailOpenMode;
    volatile LONG ConsecutiveFailures;
} gMetrics;

VOID AgentshInitializeMetrics(VOID)
{
    RtlZeroMemory(&gMetrics, sizeof(gMetrics));
}

VOID AgentshMetricsIncrementCacheHit(VOID)
{
    InterlockedIncrement(&gMetrics.CacheHitCount);
}

VOID AgentshMetricsIncrementCacheMiss(VOID)
{
    InterlockedIncrement(&gMetrics.CacheMissCount);
}

VOID AgentshMetricsIncrementCacheEviction(VOID)
{
    InterlockedIncrement(&gMetrics.CacheEvictionCount);
}

VOID AgentshMetricsIncrementFilePolicyQuery(VOID)
{
    InterlockedIncrement(&gMetrics.FilePolicyQueries);
}

VOID AgentshMetricsIncrementRegistryPolicyQuery(VOID)
{
    InterlockedIncrement(&gMetrics.RegistryPolicyQueries);
}

VOID AgentshMetricsIncrementPolicyTimeout(VOID)
{
    InterlockedIncrement(&gMetrics.PolicyQueryTimeouts);
}

VOID AgentshMetricsIncrementPolicyFailure(VOID)
{
    InterlockedIncrement(&gMetrics.PolicyQueryFailures);
}

VOID AgentshMetricsIncrementAllowDecision(VOID)
{
    InterlockedIncrement(&gMetrics.AllowDecisions);
}

VOID AgentshMetricsIncrementDenyDecision(VOID)
{
    InterlockedIncrement(&gMetrics.DenyDecisions);
}

VOID AgentshMetricsSetActiveSessionCount(ULONG count)
{
    InterlockedExchange(&gMetrics.ActiveSessions, count);
}

VOID AgentshMetricsSetTrackedProcessCount(ULONG count)
{
    InterlockedExchange(&gMetrics.TrackedProcesses, count);
}

VOID AgentshMetricsSetCacheEntryCount(ULONG count)
{
    InterlockedExchange(&gMetrics.CacheEntryCount, count);
}

VOID AgentshMetricsSetFailOpenMode(BOOLEAN enabled)
{
    gMetrics.FailOpenMode = enabled;
}

VOID AgentshMetricsSetConsecutiveFailures(ULONG count)
{
    InterlockedExchange(&gMetrics.ConsecutiveFailures, count);
}

VOID AgentshMetricsGet(_Out_ PAGENTSH_METRICS metrics)
{
    metrics->CacheHitCount = gMetrics.CacheHitCount;
    metrics->CacheMissCount = gMetrics.CacheMissCount;
    metrics->CacheEntryCount = gMetrics.CacheEntryCount;
    metrics->CacheEvictionCount = gMetrics.CacheEvictionCount;
    metrics->FilePolicyQueries = gMetrics.FilePolicyQueries;
    metrics->RegistryPolicyQueries = gMetrics.RegistryPolicyQueries;
    metrics->PolicyQueryTimeouts = gMetrics.PolicyQueryTimeouts;
    metrics->PolicyQueryFailures = gMetrics.PolicyQueryFailures;
    metrics->AllowDecisions = gMetrics.AllowDecisions;
    metrics->DenyDecisions = gMetrics.DenyDecisions;
    metrics->ActiveSessions = gMetrics.ActiveSessions;
    metrics->TrackedProcesses = gMetrics.TrackedProcesses;
    metrics->FailOpenMode = gMetrics.FailOpenMode;
    metrics->ConsecutiveFailures = gMetrics.ConsecutiveFailures;
}

VOID AgentshMetricsReset(VOID)
{
    InterlockedExchange(&gMetrics.CacheHitCount, 0);
    InterlockedExchange(&gMetrics.CacheMissCount, 0);
    InterlockedExchange(&gMetrics.CacheEvictionCount, 0);
    InterlockedExchange(&gMetrics.FilePolicyQueries, 0);
    InterlockedExchange(&gMetrics.RegistryPolicyQueries, 0);
    InterlockedExchange(&gMetrics.PolicyQueryTimeouts, 0);
    InterlockedExchange(&gMetrics.PolicyQueryFailures, 0);
    InterlockedExchange(&gMetrics.AllowDecisions, 0);
    InterlockedExchange(&gMetrics.DenyDecisions, 0);
}
```

**Step 3: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/metrics.h
git add drivers/windows/agentsh-minifilter/src/metrics.c
git commit -m "feat(windows): add metrics collection module"
```

---

## Task 3: Create Configuration Module

**Files:**
- Create: `drivers/windows/agentsh-minifilter/inc/config.h`
- Create: `drivers/windows/agentsh-minifilter/src/config.c`

**Step 1: Write config.h**

```c
// config.h - Driver configuration
#ifndef _AGENTSH_CONFIG_H_
#define _AGENTSH_CONFIG_H_

#include <fltKernel.h>
#include "protocol.h"

// Default configuration values
#define DEFAULT_FAIL_MODE               FAIL_MODE_OPEN
#define DEFAULT_POLICY_TIMEOUT_MS       5000
#define DEFAULT_MAX_CONSECUTIVE_FAIL    10
#define DEFAULT_CACHE_MAX_ENTRIES       4096
#define DEFAULT_CACHE_TTL_MS            5000

// Initialize configuration with defaults
VOID AgentshInitializeConfig(VOID);

// Get current configuration
VOID AgentshGetConfig(_Out_ PAGENTSH_CONFIG config);

// Apply new configuration
NTSTATUS AgentshSetConfig(_In_ PAGENTSH_CONFIG config);

// Query configuration values
AGENTSH_FAIL_MODE AgentshGetFailMode(VOID);
ULONG AgentshGetPolicyTimeoutMs(VOID);
ULONG AgentshGetMaxConsecutiveFailures(VOID);
ULONG AgentshGetCacheMaxEntries(VOID);
ULONG AgentshGetCacheDefaultTTLMs(VOID);

#endif // _AGENTSH_CONFIG_H_
```

**Step 2: Write config.c**

```c
// config.c - Driver configuration
#include "driver.h"
#include "config.h"

// Global configuration (protected by lock)
static EX_PUSH_LOCK gConfigLock;
static AGENTSH_CONFIG gConfig;

VOID AgentshInitializeConfig(VOID)
{
    ExInitializePushLock(&gConfigLock);

    RtlZeroMemory(&gConfig, sizeof(gConfig));
    gConfig.FailMode = DEFAULT_FAIL_MODE;
    gConfig.PolicyQueryTimeoutMs = DEFAULT_POLICY_TIMEOUT_MS;
    gConfig.MaxConsecutiveFailures = DEFAULT_MAX_CONSECUTIVE_FAIL;
    gConfig.CacheMaxEntries = DEFAULT_CACHE_MAX_ENTRIES;
    gConfig.CacheDefaultTTLMs = DEFAULT_CACHE_TTL_MS;

    DbgPrint("AgentSH: Configuration initialized (FailMode=%d, Timeout=%lu)\n",
             gConfig.FailMode, gConfig.PolicyQueryTimeoutMs);
}

VOID AgentshGetConfig(_Out_ PAGENTSH_CONFIG config)
{
    ExAcquirePushLockShared(&gConfigLock);
    RtlCopyMemory(config, &gConfig, sizeof(AGENTSH_CONFIG));
    ExReleasePushLockShared(&gConfigLock);
}

NTSTATUS AgentshSetConfig(_In_ PAGENTSH_CONFIG config)
{
    // Validate configuration values
    if (config->PolicyQueryTimeoutMs < 100 || config->PolicyQueryTimeoutMs > 60000) {
        return STATUS_INVALID_PARAMETER;
    }
    if (config->MaxConsecutiveFailures < 1 || config->MaxConsecutiveFailures > 1000) {
        return STATUS_INVALID_PARAMETER;
    }
    if (config->CacheMaxEntries < 100 || config->CacheMaxEntries > 100000) {
        return STATUS_INVALID_PARAMETER;
    }
    if (config->CacheDefaultTTLMs < 100 || config->CacheDefaultTTLMs > 3600000) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&gConfigLock);

    gConfig.FailMode = config->FailMode;
    gConfig.PolicyQueryTimeoutMs = config->PolicyQueryTimeoutMs;
    gConfig.MaxConsecutiveFailures = config->MaxConsecutiveFailures;
    gConfig.CacheMaxEntries = config->CacheMaxEntries;
    gConfig.CacheDefaultTTLMs = config->CacheDefaultTTLMs;

    ExReleasePushLockExclusive(&gConfigLock);

    DbgPrint("AgentSH: Configuration updated (FailMode=%d, Timeout=%lu, MaxFail=%lu)\n",
             config->FailMode, config->PolicyQueryTimeoutMs, config->MaxConsecutiveFailures);

    return STATUS_SUCCESS;
}

AGENTSH_FAIL_MODE AgentshGetFailMode(VOID)
{
    AGENTSH_FAIL_MODE mode;
    ExAcquirePushLockShared(&gConfigLock);
    mode = gConfig.FailMode;
    ExReleasePushLockShared(&gConfigLock);
    return mode;
}

ULONG AgentshGetPolicyTimeoutMs(VOID)
{
    ULONG timeout;
    ExAcquirePushLockShared(&gConfigLock);
    timeout = gConfig.PolicyQueryTimeoutMs;
    ExReleasePushLockShared(&gConfigLock);
    return timeout;
}

ULONG AgentshGetMaxConsecutiveFailures(VOID)
{
    ULONG maxFail;
    ExAcquirePushLockShared(&gConfigLock);
    maxFail = gConfig.MaxConsecutiveFailures;
    ExReleasePushLockShared(&gConfigLock);
    return maxFail;
}

ULONG AgentshGetCacheMaxEntries(VOID)
{
    ULONG maxEntries;
    ExAcquirePushLockShared(&gConfigLock);
    maxEntries = gConfig.CacheMaxEntries;
    ExReleasePushLockShared(&gConfigLock);
    return maxEntries;
}

ULONG AgentshGetCacheDefaultTTLMs(VOID)
{
    ULONG ttl;
    ExAcquirePushLockShared(&gConfigLock);
    ttl = gConfig.CacheDefaultTTLMs;
    ExReleasePushLockShared(&gConfigLock);
    return ttl;
}
```

**Step 3: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/config.h
git add drivers/windows/agentsh-minifilter/src/config.c
git commit -m "feat(windows): add configurable fail modes and cache tuning"
```

---

## Task 4: Update Filesystem to Use Config and Metrics

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/src/filesystem.c`

**Step 1: Add includes and update to use configuration**

Replace hardcoded values with config lookups. Update to:

```c
// filesystem.c - Filesystem interception implementation
#include "driver.h"
#include "filesystem.h"
#include "process.h"
#include "cache.h"
#include "config.h"
#include "metrics.h"

// Fail-open tracking
static volatile LONG gConsecutiveFailures = 0;
static volatile BOOLEAN gFailOpenMode = FALSE;
```

**Step 2: Update AgentshQueryFilePolicy to use config and metrics**

In `AgentshQueryFilePolicy`, replace:

```c
    // Check fail-open mode
    if (gFailOpenMode) {
        return TRUE;
    }
```

With:

```c
    // Check fail mode
    AGENTSH_FAIL_MODE failMode = AgentshGetFailMode();
    if (gFailOpenMode) {
        // In fail-open mode, allow all
        if (failMode == FAIL_MODE_OPEN) {
            return TRUE;
        }
        // In fail-closed mode, deny all
        *Decision = DECISION_DENY;
        AgentshMetricsIncrementDenyDecision();
        return TRUE;
    }
```

Replace timeout:

```c
    // Set timeout (negative = relative)
    ULONG timeoutMs = AgentshGetPolicyTimeoutMs();
    timeout.QuadPart = -((LONGLONG)timeoutMs * 10000);
```

Update success path:

```c
    if (NT_SUCCESS(status) && replyLength >= sizeof(response)) {
        *Decision = response.Decision;
        InterlockedExchange(&gConsecutiveFailures, 0);
        AgentshMetricsSetConsecutiveFailures(0);
        AgentshMetricsSetFailOpenMode(FALSE);

        if (response.Decision == DECISION_ALLOW) {
            AgentshMetricsIncrementAllowDecision();
        } else {
            AgentshMetricsIncrementDenyDecision();
        }

        // Update cache
        ULONG ttl = response.CacheTTLMs > 0 ? response.CacheTTLMs : AgentshGetCacheDefaultTTLMs();
        AgentshCacheInsert(SessionToken, Operation, Path, response.Decision, ttl);

        return TRUE;
    }
```

Update failure path:

```c
    // Handle failure
    LONG failures = InterlockedIncrement(&gConsecutiveFailures);
    AgentshMetricsSetConsecutiveFailures(failures);
    AgentshMetricsIncrementPolicyFailure();

    ULONG maxFail = AgentshGetMaxConsecutiveFailures();
    if (failures >= (LONG)maxFail && !gFailOpenMode) {
        gFailOpenMode = TRUE;
        AgentshMetricsSetFailOpenMode(TRUE);
        DbgPrint("AgentSH: Entering fail mode after %ld failures\n", failures);
    }

    // Apply fail mode policy
    if (AgentshGetFailMode() == FAIL_MODE_CLOSED) {
        *Decision = DECISION_DENY;
        AgentshMetricsIncrementDenyDecision();
    } else {
        AgentshMetricsIncrementAllowDecision();
    }
```

**Step 3: Add metric tracking to query path**

At start of `AgentshQueryFilePolicy`:

```c
    AgentshMetricsIncrementFilePolicyQuery();
```

**Step 4: Commit**

```bash
git add drivers/windows/agentsh-minifilter/src/filesystem.c
git commit -m "feat(windows): integrate config and metrics into filesystem callbacks"
```

---

## Task 5: Update Registry to Use Config and Metrics

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/src/registry.c`

**Step 1: Add includes**

Add after existing includes:

```c
#include "config.h"
#include "metrics.h"
```

**Step 2: Update AgentshQueryRegistryPolicy similarly to filesystem**

Apply same changes as Task 4:
- Use `AgentshGetFailMode()` for fail mode decisions
- Use `AgentshGetPolicyTimeoutMs()` for timeout
- Use `AgentshGetMaxConsecutiveFailures()` for threshold
- Use `AgentshGetCacheDefaultTTLMs()` for cache TTL
- Add `AgentshMetricsIncrementRegistryPolicyQuery()` at start
- Add decision metrics tracking

**Step 3: Commit**

```bash
git add drivers/windows/agentsh-minifilter/src/registry.c
git commit -m "feat(windows): integrate config and metrics into registry callbacks"
```

---

## Task 6: Update Driver Entry to Initialize Config and Metrics

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/inc/driver.h`
- Modify: `drivers/windows/agentsh-minifilter/src/driver.c`

**Step 1: Add includes to driver.h**

Add after `#include "registry.h"`:

```c
#include "config.h"
#include "metrics.h"
```

**Step 2: Update DriverEntry in driver.c**

After `RtlZeroMemory(&AgentshData, sizeof(AgentshData));`, add:

```c
    // Initialize configuration
    AgentshInitializeConfig();

    // Initialize metrics
    AgentshInitializeMetrics();
```

**Step 3: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/driver.h
git add drivers/windows/agentsh-minifilter/src/driver.c
git commit -m "feat(windows): initialize config and metrics in driver entry"
```

---

## Task 7: Add Config and Metrics Message Handling

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/src/communication.c`

**Step 1: Add handler for MSG_SET_CONFIG and MSG_GET_METRICS**

Add to message handling switch:

```c
    case MSG_SET_CONFIG:
        if (InputBufferLength >= sizeof(AGENTSH_CONFIG)) {
            PAGENTSH_CONFIG config = (PAGENTSH_CONFIG)InputBuffer;
            status = AgentshSetConfig(config);
        }
        break;

    case MSG_GET_METRICS:
        if (OutputBufferLength >= sizeof(AGENTSH_METRICS)) {
            PAGENTSH_METRICS metrics = (PAGENTSH_METRICS)OutputBuffer;
            RtlZeroMemory(metrics, sizeof(AGENTSH_METRICS));
            metrics->Header.Type = MSG_METRICS_REPLY;
            metrics->Header.Size = sizeof(AGENTSH_METRICS);
            AgentshMetricsGet(metrics);
            *ReturnOutputBufferLength = sizeof(AGENTSH_METRICS);
        }
        break;
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/src/communication.c
git commit -m "feat(windows): handle config and metrics messages in communication"
```

---

## Task 8: Update Visual Studio Project

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/agentsh.vcxproj`

**Step 1: Add new files to project**

In the `<ItemGroup>` containing `.c` files, add:

```xml
    <ClCompile Include="src\config.c" />
    <ClCompile Include="src\metrics.c" />
```

In the `<ItemGroup>` containing `.h` files, add:

```xml
    <ClInclude Include="inc\config.h" />
    <ClInclude Include="inc\metrics.h" />
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/agentsh.vcxproj
git commit -m "build(windows): add config and metrics files to VS project"
```

---

## Task 9: Add Config and Metrics to Go Client

**Files:**
- Modify: `internal/platform/windows/driver_client.go`
- Modify: `internal/platform/windows/driver_client_stub.go`

**Step 1: Add config and metrics types after RegistryPolicyHandler**

```go
// FailMode represents the driver fail mode
type FailMode uint32

const (
	FailModeOpen   FailMode = 0
	FailModeClosed FailMode = 1
)

// DriverConfig represents driver configuration
type DriverConfig struct {
	FailMode              FailMode
	PolicyQueryTimeoutMs  uint32
	MaxConsecutiveFailures uint32
	CacheMaxEntries       uint32
	CacheDefaultTTLMs     uint32
}

// DriverMetrics represents driver metrics
type DriverMetrics struct {
	CacheHitCount        uint32
	CacheMissCount       uint32
	CacheEntryCount      uint32
	CacheEvictionCount   uint32
	FilePolicyQueries    uint32
	RegistryPolicyQueries uint32
	PolicyQueryTimeouts  uint32
	PolicyQueryFailures  uint32
	AllowDecisions       uint32
	DenyDecisions        uint32
	ActiveSessions       uint32
	TrackedProcesses     uint32
	FailOpenMode         bool
	ConsecutiveFailures  uint32
}
```

**Step 2: Add SetConfig method**

```go
// SetConfig sends configuration to the driver
func (c *DriverClient) SetConfig(cfg *DriverConfig) error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	// Build message: header(16) + failMode(4) + timeout(4) + maxFail(4) + cacheMax(4) + cacheTTL(4)
	msgSize := 16 + 4 + 4 + 4 + 4 + 4
	msg := make([]byte, msgSize)

	binary.LittleEndian.PutUint32(msg[0:4], MsgSetConfig)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(cfg.FailMode))
	binary.LittleEndian.PutUint32(msg[20:24], cfg.PolicyQueryTimeoutMs)
	binary.LittleEndian.PutUint32(msg[24:28], cfg.MaxConsecutiveFailures)
	binary.LittleEndian.PutUint32(msg[28:32], cfg.CacheMaxEntries)
	binary.LittleEndian.PutUint32(msg[32:36], cfg.CacheDefaultTTLMs)

	return filterSendMessage(c.port, msg, nil)
}
```

**Step 3: Add GetMetrics method**

```go
// GetMetrics retrieves current metrics from the driver
func (c *DriverClient) GetMetrics() (*DriverMetrics, error) {
	if !c.connected.Load() {
		return nil, fmt.Errorf("not connected")
	}

	// Build request
	msgSize := 16
	msg := make([]byte, msgSize)
	binary.LittleEndian.PutUint32(msg[0:4], MsgGetMetrics)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))

	// Response buffer
	reply := make([]byte, 128)

	err := filterSendMessage(c.port, msg, reply)
	if err != nil {
		return nil, err
	}

	// Parse response (header(16) + metrics fields)
	if len(reply) < 72 {
		return nil, fmt.Errorf("response too short")
	}

	return &DriverMetrics{
		CacheHitCount:        binary.LittleEndian.Uint32(reply[16:20]),
		CacheMissCount:       binary.LittleEndian.Uint32(reply[20:24]),
		CacheEntryCount:      binary.LittleEndian.Uint32(reply[24:28]),
		CacheEvictionCount:   binary.LittleEndian.Uint32(reply[28:32]),
		FilePolicyQueries:    binary.LittleEndian.Uint32(reply[32:36]),
		RegistryPolicyQueries: binary.LittleEndian.Uint32(reply[36:40]),
		PolicyQueryTimeouts:  binary.LittleEndian.Uint32(reply[40:44]),
		PolicyQueryFailures:  binary.LittleEndian.Uint32(reply[44:48]),
		AllowDecisions:       binary.LittleEndian.Uint32(reply[48:52]),
		DenyDecisions:        binary.LittleEndian.Uint32(reply[52:56]),
		ActiveSessions:       binary.LittleEndian.Uint32(reply[56:60]),
		TrackedProcesses:     binary.LittleEndian.Uint32(reply[60:64]),
		FailOpenMode:         reply[64] != 0,
		ConsecutiveFailures:  binary.LittleEndian.Uint32(reply[68:72]),
	}, nil
}
```

**Step 4: Add message type constants**

```go
const (
	// ... existing constants ...
	MsgSetConfig    = 104
	MsgGetMetrics   = 105
	MsgMetricsReply = 106
)
```

**Step 5: Add stubs to driver_client_stub.go**

```go
// FailMode represents the driver fail mode
type FailMode uint32

const (
	FailModeOpen   FailMode = 0
	FailModeClosed FailMode = 1
)

// DriverConfig stub
type DriverConfig struct {
	FailMode              FailMode
	PolicyQueryTimeoutMs  uint32
	MaxConsecutiveFailures uint32
	CacheMaxEntries       uint32
	CacheDefaultTTLMs     uint32
}

// DriverMetrics stub
type DriverMetrics struct {
	CacheHitCount        uint32
	CacheMissCount       uint32
	CacheEntryCount      uint32
	CacheEvictionCount   uint32
	FilePolicyQueries    uint32
	RegistryPolicyQueries uint32
	PolicyQueryTimeouts  uint32
	PolicyQueryFailures  uint32
	AllowDecisions       uint32
	DenyDecisions        uint32
	ActiveSessions       uint32
	TrackedProcesses     uint32
	FailOpenMode         bool
	ConsecutiveFailures  uint32
}

// SetConfig stub for non-Windows
func (c *DriverClient) SetConfig(cfg *DriverConfig) error {
	return fmt.Errorf("not supported on this platform")
}

// GetMetrics stub for non-Windows
func (c *DriverClient) GetMetrics() (*DriverMetrics, error) {
	return nil, fmt.Errorf("not supported on this platform")
}
```

**Step 6: Commit**

```bash
git add internal/platform/windows/driver_client.go
git add internal/platform/windows/driver_client_stub.go
git commit -m "feat(windows): add config and metrics support to Go driver client"
```

---

## Task 10: Add Unit Tests for Config and Metrics

**Files:**
- Modify: `internal/platform/windows/driver_client_test.go`

**Step 1: Add config and metrics tests**

```go
func TestDriverConfigEncoding(t *testing.T) {
	cfg := &DriverConfig{
		FailMode:              FailModeClosed,
		PolicyQueryTimeoutMs:  3000,
		MaxConsecutiveFailures: 5,
		CacheMaxEntries:       8192,
		CacheDefaultTTLMs:     10000,
	}

	// Build message
	msg := make([]byte, 36)
	binary.LittleEndian.PutUint32(msg[0:4], MsgSetConfig)
	binary.LittleEndian.PutUint32(msg[4:8], 36)
	binary.LittleEndian.PutUint64(msg[8:16], 1)
	binary.LittleEndian.PutUint32(msg[16:20], uint32(cfg.FailMode))
	binary.LittleEndian.PutUint32(msg[20:24], cfg.PolicyQueryTimeoutMs)
	binary.LittleEndian.PutUint32(msg[24:28], cfg.MaxConsecutiveFailures)
	binary.LittleEndian.PutUint32(msg[28:32], cfg.CacheMaxEntries)
	binary.LittleEndian.PutUint32(msg[32:36], cfg.CacheDefaultTTLMs)

	// Decode and verify
	failMode := FailMode(binary.LittleEndian.Uint32(msg[16:20]))
	timeout := binary.LittleEndian.Uint32(msg[20:24])

	if failMode != FailModeClosed {
		t.Errorf("expected FailModeClosed, got %d", failMode)
	}
	if timeout != 3000 {
		t.Errorf("expected timeout 3000, got %d", timeout)
	}
}

func TestDriverMetricsDecoding(t *testing.T) {
	// Build mock metrics response
	reply := make([]byte, 72)
	binary.LittleEndian.PutUint32(reply[0:4], MsgMetricsReply)
	binary.LittleEndian.PutUint32(reply[4:8], 72)
	binary.LittleEndian.PutUint32(reply[16:20], 100) // CacheHitCount
	binary.LittleEndian.PutUint32(reply[20:24], 10)  // CacheMissCount
	binary.LittleEndian.PutUint32(reply[48:52], 90)  // AllowDecisions
	binary.LittleEndian.PutUint32(reply[52:56], 5)   // DenyDecisions
	reply[64] = 1                                     // FailOpenMode = true

	// Decode and verify
	cacheHits := binary.LittleEndian.Uint32(reply[16:20])
	allowDecisions := binary.LittleEndian.Uint32(reply[48:52])
	failOpen := reply[64] != 0

	if cacheHits != 100 {
		t.Errorf("expected cache hits 100, got %d", cacheHits)
	}
	if allowDecisions != 90 {
		t.Errorf("expected allow decisions 90, got %d", allowDecisions)
	}
	if !failOpen {
		t.Error("expected fail open mode to be true")
	}
}

func TestFailModeConstants(t *testing.T) {
	if FailModeOpen != 0 {
		t.Errorf("FailModeOpen should be 0, got %d", FailModeOpen)
	}
	if FailModeClosed != 1 {
		t.Errorf("FailModeClosed should be 1, got %d", FailModeClosed)
	}
}
```

**Step 2: Run tests**

```bash
go test ./internal/platform/windows/... -v
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add internal/platform/windows/driver_client_test.go
git commit -m "test(windows): add unit tests for config and metrics"
```

---

## Task 11: Create Production Deployment Guide

**Files:**
- Create: `docs/windows-driver-deployment.md`

**Step 1: Write deployment documentation**

```markdown
# Windows Mini Filter Driver Deployment Guide

## Overview

This guide covers deploying the agentsh Windows mini filter driver in production environments, including code signing requirements, installation procedures, and monitoring.

## Requirements

### Development/Testing
- Windows 10/11 64-bit
- Test signing mode enabled (`bcdedit /set testsigning on`)
- Administrator privileges

### Production
- EV (Extended Validation) Code Signing Certificate
- Microsoft Hardware Dev Center account (for attestation signing on Windows 10 1607+)
- WHQL certification (optional, recommended for enterprise deployment)

## Code Signing

### Test Signing (Development)

1. Create a test certificate:
```cmd
makecert -r -pe -ss PrivateCertStore -n "CN=AgentSH Test" agentsh-test.cer
```

2. Sign the driver:
```cmd
signtool sign /v /s PrivateCertStore /n "AgentSH Test" /t http://timestamp.digicert.com agentsh.sys
```

3. Enable test signing on target machine:
```cmd
bcdedit /set testsigning on
```

### Production Signing

1. **Obtain an EV Code Signing Certificate** from a trusted CA (DigiCert, Sectigo, etc.)

2. **Sign the driver catalog**:
```cmd
inf2cat /driver:. /os:10_x64
signtool sign /v /ac cross-cert.cer /n "Your Company" /tr http://timestamp.digicert.com /td sha256 /fd sha256 agentsh.cat
```

3. **Submit for attestation signing** (Windows 10 1607+):
   - Create account at https://partner.microsoft.com/dashboard
   - Submit driver package for attestation signing
   - Download signed package

## Installation

### Manual Installation

```cmd
REM As Administrator
copy agentsh.sys %SystemRoot%\System32\drivers\
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 agentsh.inf
fltmc load agentsh
```

### Verify Installation

```cmd
fltmc
```

Expected output:
```
Filter Name                     Num Instances    Altitude    Frame
------------------------------  -------------  ------------  -----
AgentSH                               3          385200       0
```

### Uninstallation

```cmd
fltmc unload agentsh
rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 agentsh.inf
del %SystemRoot%\System32\drivers\agentsh.sys
```

## Configuration

### Fail Modes

| Mode | Behavior |
|------|----------|
| `FAIL_MODE_OPEN` (default) | Allow operations when policy service unavailable |
| `FAIL_MODE_CLOSED` | Deny operations when policy service unavailable |

Configure via Go client:
```go
client.SetConfig(&DriverConfig{
    FailMode:              FailModeClosed,
    PolicyQueryTimeoutMs:  5000,
    MaxConsecutiveFailures: 10,
})
```

### Cache Tuning

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| CacheMaxEntries | 4096 | 100-100000 | Maximum cached decisions |
| CacheDefaultTTLMs | 5000 | 100-3600000 | Default cache entry TTL |

## Monitoring

### Metrics

Retrieve via Go client:
```go
metrics, _ := client.GetMetrics()
fmt.Printf("Cache hit rate: %.2f%%\n",
    float64(metrics.CacheHitCount) / float64(metrics.CacheHitCount + metrics.CacheMissCount) * 100)
```

Key metrics:
- `CacheHitCount` / `CacheMissCount` - Cache efficiency
- `PolicyQueryTimeouts` - Policy service responsiveness
- `FailOpenMode` - Current fail mode state
- `AllowDecisions` / `DenyDecisions` - Policy enforcement stats

### Windows Event Log

Driver events appear in:
- Event Viewer → Windows Logs → System
- Source: AgentSH

### Debug Output

In development, view DbgPrint output with DebugView (Sysinternals).

## Troubleshooting

### Driver won't load

1. Check test signing: `bcdedit | findstr testsigning`
2. Verify driver signature: `signtool verify /v /pa agentsh.sys`
3. Check Event Viewer for errors

### High latency

1. Check metrics for cache hit rate (should be >80%)
2. Verify policy service is running
3. Consider increasing cache size

### Fail-open triggered

1. Check policy service connectivity
2. Review `ConsecutiveFailures` metric
3. Increase `MaxConsecutiveFailures` or fix connectivity

## Security Considerations

1. **Production deployments must use EV-signed drivers**
2. **Never disable Secure Boot in production**
3. **Use FAIL_MODE_CLOSED for high-security environments**
4. **Monitor fail mode transitions in SIEM**
5. **Rotate session tokens regularly**
```

**Step 2: Commit**

```bash
git add docs/windows-driver-deployment.md
git commit -m "docs: add Windows driver deployment guide"
```

---

## Task 12: Update Design Document

**Files:**
- Modify: `docs/plans/2026-01-01-windows-minifilter-design.md`

**Step 1: Update implementation phases**

Mark Phase 5 as complete:

```markdown
### Phase 5: Hardening + Production Readiness ✅

- Comprehensive error handling
- Fail-open/fail-closed modes
- Cache tuning and metrics
- Production signing pipeline (EV cert)
- Documentation and deployment guides
```

**Step 2: Commit**

```bash
git add docs/plans/2026-01-01-windows-minifilter-design.md
git commit -m "docs: mark Phase 5 complete in design document"
```

---

## Task 13: Final Verification

**Step 1: Run all tests**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-windows-minifilter
go test ./... -v
go build ./...
```

Expected: All tests pass, build succeeds

**Step 2: Verify driver files are complete**

```bash
ls -la drivers/windows/agentsh-minifilter/src/
ls -la drivers/windows/agentsh-minifilter/inc/
```

Expected: config.c, config.h, metrics.c, metrics.h present

**Step 3: Review commits**

```bash
git log --oneline -15
```

---

## Phase 5 Complete Checklist

- [ ] Configuration protocol structures added
- [ ] Metrics module created
- [ ] Configuration module created
- [ ] Filesystem callbacks use config and metrics
- [ ] Registry callbacks use config and metrics
- [ ] Driver entry initializes config and metrics
- [ ] Communication handles config and metrics messages
- [ ] Visual Studio project updated
- [ ] Go client config and metrics support
- [ ] Unit tests for config and metrics
- [ ] Production deployment guide created
- [ ] Design document updated
- [ ] All tests pass

## Summary

Phase 5 adds:
- **Configurable fail modes** (fail-open/fail-closed)
- **Runtime configuration** (timeouts, cache sizes)
- **Comprehensive metrics** (cache, queries, decisions)
- **Go client integration** for config and metrics
- **Production deployment documentation**
