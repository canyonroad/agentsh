// filesystem.h - Filesystem interception definitions
#ifndef _AGENTSH_FILESYSTEM_H_
#define _AGENTSH_FILESYSTEM_H_

#include <fltKernel.h>
#include "protocol.h"

// Process exclusion (for WinFsp coexistence)
BOOLEAN AgentshIsExcludedProcess(ULONG ProcessId);
void AgentshSetExcludedProcess(ULONG ProcessId);

// Query policy from user-mode
BOOLEAN
AgentshQueryFilePolicy(
    _In_ ULONG64 SessionToken,
    _In_ ULONG ProcessId,
    _In_ AGENTSH_FILE_OP Operation,
    _In_ PCWSTR Path,
    _In_opt_ PCWSTR RenameDest,
    _In_ ULONG CreateDisposition,
    _In_ ULONG DesiredAccess,
    _Out_ PAGENTSH_DECISION Decision
    );

// IRP callbacks
FLT_PREOP_CALLBACK_STATUS
AgentshPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
AgentshPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
AgentshPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

#endif // _AGENTSH_FILESYSTEM_H_
