// registry.h - Registry interception definitions
#ifndef _AGENTSH_REGISTRY_H_
#define _AGENTSH_REGISTRY_H_

#include <fltKernel.h>
#include "protocol.h"

// Registry filter altitude (slightly higher than filesystem)
#define AGENTSH_REGISTRY_ALTITUDE L"385210"

// High-risk registry paths count
#define HIGH_RISK_PATH_COUNT 12

// Initialize registry filtering
NTSTATUS
AgentshInitializeRegistryFilter(
    _In_ PDRIVER_OBJECT DriverObject
    );

// Shutdown registry filtering
VOID
AgentshShutdownRegistryFilter(
    VOID
    );

// Query registry policy from user-mode
BOOLEAN
AgentshQueryRegistryPolicy(
    _In_ ULONG64 SessionToken,
    _In_ ULONG ProcessId,
    _In_ AGENTSH_REGISTRY_OP Operation,
    _In_ PCWSTR KeyPath,
    _In_opt_ PCWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ ULONG DataSize,
    _Out_ PAGENTSH_DECISION Decision
    );

// Check if path is high-risk (persistence, security)
BOOLEAN
AgentshIsHighRiskRegistryPath(
    _In_ PCWSTR KeyPath
    );

#endif // _AGENTSH_REGISTRY_H_
