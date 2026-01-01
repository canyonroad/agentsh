// process.h - Process tracking definitions
#ifndef _AGENTSH_PROCESS_H_
#define _AGENTSH_PROCESS_H_

#include <fltKernel.h>
#include "protocol.h"

// Pool tag for process tracking allocations
#define AGENTSH_TAG_PROCESS 'rpGA'
#define AGENTSH_TAG_SESSION 'ssGA'

// Hash table size (must be power of 2)
#define PROCESS_TABLE_SIZE 256
#define PROCESS_TABLE_MASK (PROCESS_TABLE_SIZE - 1)

// Session process entry
typedef struct _SESSION_PROCESS {
    LIST_ENTRY ListEntry;           // Hash bucket chain
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONG64 SessionToken;
    LARGE_INTEGER CreateTime;
} SESSION_PROCESS, *PSESSION_PROCESS;

// Session info entry
typedef struct _SESSION_INFO {
    LIST_ENTRY ListEntry;           // Global session list
    ULONG64 SessionToken;
    HANDLE RootProcessId;
    UNICODE_STRING WorkspacePath;
    volatile LONG ProcessCount;
} SESSION_INFO, *PSESSION_INFO;

// Process hash table
typedef struct _PROCESS_TABLE {
    EX_PUSH_LOCK Lock;
    LIST_ENTRY Buckets[PROCESS_TABLE_SIZE];
    volatile LONG TotalCount;
} PROCESS_TABLE;

// Session list
typedef struct _SESSION_LIST {
    EX_PUSH_LOCK Lock;
    LIST_ENTRY Head;
    volatile LONG Count;
} SESSION_LIST;

// Initialize process tracking (call from DriverEntry)
NTSTATUS
AgentshInitializeProcessTracking(
    VOID
    );

// Shutdown process tracking (call from FilterUnload)
VOID
AgentshShutdownProcessTracking(
    VOID
    );

// Register a session (from user-mode message)
NTSTATUS
AgentshRegisterSession(
    _In_ ULONG64 SessionToken,
    _In_ HANDLE RootProcessId,
    _In_opt_ PCWSTR WorkspacePath
    );

// Unregister a session (from user-mode message)
NTSTATUS
AgentshUnregisterSession(
    _In_ ULONG64 SessionToken
    );

// Check if a process belongs to a session
BOOLEAN
AgentshIsSessionProcess(
    _In_ HANDLE ProcessId,
    _Out_ PULONG64 SessionToken
    );

// Get session info by token
PSESSION_INFO
AgentshGetSessionInfo(
    _In_ ULONG64 SessionToken
    );

// Internal: Add process to tracking table
NTSTATUS
AgentshAddSessionProcess(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_ ULONG64 SessionToken
    );

// Internal: Remove process from tracking table
BOOLEAN
AgentshRemoveSessionProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG64 SessionToken
    );

#endif // _AGENTSH_PROCESS_H_
