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

// Set/get values (thread-safe)
VOID AgentshMetricsSetActiveSessionCount(_In_ ULONG count);
VOID AgentshMetricsSetTrackedProcessCount(_In_ ULONG count);
VOID AgentshMetricsSetCacheEntryCount(_In_ ULONG count);
VOID AgentshMetricsSetFailOpenMode(_In_ BOOLEAN enabled);
VOID AgentshMetricsSetConsecutiveFailures(_In_ ULONG count);

// Get metrics snapshot
VOID AgentshMetricsGet(_Out_ PAGENTSH_METRICS metrics);

// Reset counters
VOID AgentshMetricsReset(VOID);

#endif // _AGENTSH_METRICS_H_
