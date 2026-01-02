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
    // Direct assignment is safe for BOOLEAN on x86/x64 - single byte write is atomic.
    // InterlockedExchange8 would add unnecessary overhead for this status flag.
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
