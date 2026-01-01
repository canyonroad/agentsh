// filesystem.c - Filesystem interception implementation
#include "driver.h"
#include "filesystem.h"
#include "process.h"
#include "cache.h"

// Query timeout (5 seconds)
#define POLICY_QUERY_TIMEOUT_MS 5000

// Fail-open tracking
static volatile LONG gConsecutiveFailures = 0;
static volatile BOOLEAN gFailOpenMode = FALSE;
#define MAX_CONSECUTIVE_FAILURES 10

// Get file path from callback data
static NTSTATUS
GetFilePath(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_writes_(PathSize) PWCHAR PathBuffer,
    _In_ ULONG PathSize
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    // Copy path (ensure null termination)
    if (nameInfo->Name.Length >= PathSize * sizeof(WCHAR)) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(PathBuffer, nameInfo->Name.Buffer, nameInfo->Name.Length);
    PathBuffer[nameInfo->Name.Length / sizeof(WCHAR)] = L'\0';

    FltReleaseFileNameInformation(nameInfo);
    return STATUS_SUCCESS;
}

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
    )
{
    NTSTATUS status;
    AGENTSH_FILE_REQUEST request = {0};
    AGENTSH_POLICY_RESPONSE response = {0};
    ULONG replyLength = sizeof(response);
    LARGE_INTEGER timeout;
    SIZE_T pathLen;

    // Default to allow on failure
    *Decision = DECISION_ALLOW;

    // Check fail-open mode
    if (gFailOpenMode) {
        return TRUE;
    }

    // Check if client is connected
    if (!AgentshData.ClientConnected) {
        return FALSE;
    }

    // Build request
    request.Header.Type = MSG_POLICY_CHECK_FILE;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = InterlockedIncrement(&AgentshData.MessageId);
    request.SessionToken = SessionToken;
    request.ProcessId = ProcessId;
    request.ThreadId = HandleToULong(PsGetCurrentThreadId());
    request.Operation = Operation;
    request.CreateDisposition = CreateDisposition;
    request.DesiredAccess = DesiredAccess;

    // Copy path
    pathLen = wcslen(Path);
    if (pathLen >= AGENTSH_MAX_PATH) {
        pathLen = AGENTSH_MAX_PATH - 1;
    }
    RtlCopyMemory(request.Path, Path, pathLen * sizeof(WCHAR));
    request.Path[pathLen] = L'\0';

    // Copy rename destination if provided
    if (RenameDest != NULL) {
        pathLen = wcslen(RenameDest);
        if (pathLen >= AGENTSH_MAX_PATH) {
            pathLen = AGENTSH_MAX_PATH - 1;
        }
        RtlCopyMemory(request.RenameDest, RenameDest, pathLen * sizeof(WCHAR));
        request.RenameDest[pathLen] = L'\0';
    }

    // Set timeout (negative = relative)
    timeout.QuadPart = -((LONGLONG)POLICY_QUERY_TIMEOUT_MS * 10000);

    // Send message to user-mode
    status = FltSendMessage(
        AgentshData.FilterHandle,
        &AgentshData.ClientPort,
        &request,
        sizeof(request),
        &response,
        &replyLength,
        &timeout
        );

    if (NT_SUCCESS(status) && replyLength >= sizeof(response)) {
        *Decision = response.Decision;
        InterlockedExchange(&gConsecutiveFailures, 0);

        // Update cache
        AgentshCacheInsert(
            SessionToken,
            Operation,
            Path,
            response.Decision,
            response.CacheTTLMs > 0 ? response.CacheTTLMs : CACHE_DEFAULT_TTL_MS
            );

        return TRUE;
    }

    // Handle failure
    LONG failures = InterlockedIncrement(&gConsecutiveFailures);
    if (failures >= MAX_CONSECUTIVE_FAILURES && !gFailOpenMode) {
        gFailOpenMode = TRUE;
        DbgPrint("AgentSH: Entering fail-open mode after %ld failures\n", failures);
    }

    return FALSE;
}

// Pre-create callback
FLT_PREOP_CALLBACK_STATUS
AgentshPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    ULONG64 sessionToken;
    AGENTSH_DECISION decision;
    WCHAR pathBuffer[AGENTSH_MAX_PATH];
    ULONG createDisposition;
    ULONG desiredAccess;
    AGENTSH_FILE_OP operation;

    UNREFERENCED_PARAMETER(CompletionContext);

    // Fast path: not a session process
    if (!AgentshIsSessionProcess(PsGetCurrentProcessId(), &sessionToken)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get file path
    status = GetFilePath(Data, FltObjects, pathBuffer, AGENTSH_MAX_PATH);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get create parameters
    createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

    // Determine operation type based on access flags
    if (desiredAccess & DELETE) {
        operation = FILE_OP_DELETE;
    } else if (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) {
        operation = FILE_OP_WRITE;
    } else if (createDisposition == FILE_CREATE || createDisposition == FILE_OVERWRITE ||
               createDisposition == FILE_OVERWRITE_IF || createDisposition == FILE_SUPERSEDE) {
        operation = FILE_OP_CREATE;
    } else {
        // Read-only open - allow without policy check for now
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check cache first
    if (AgentshCacheLookup(sessionToken, operation, pathBuffer, &decision)) {
        if (decision == DECISION_DENY) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Query policy
    if (AgentshQueryFilePolicy(
            sessionToken,
            HandleToULong(PsGetCurrentProcessId()),
            operation,
            pathBuffer,
            NULL,
            createDisposition,
            desiredAccess,
            &decision))
    {
        if (decision == DECISION_DENY) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }
    // Fail-open: allow if query fails

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Pre-write callback
FLT_PREOP_CALLBACK_STATUS
AgentshPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    ULONG64 sessionToken;
    AGENTSH_DECISION decision;
    WCHAR pathBuffer[AGENTSH_MAX_PATH];

    UNREFERENCED_PARAMETER(CompletionContext);

    // Fast path: not a session process
    if (!AgentshIsSessionProcess(PsGetCurrentProcessId(), &sessionToken)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get file path
    status = GetFilePath(Data, FltObjects, pathBuffer, AGENTSH_MAX_PATH);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check cache first
    if (AgentshCacheLookup(sessionToken, FILE_OP_WRITE, pathBuffer, &decision)) {
        if (decision == DECISION_DENY) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Query policy
    if (AgentshQueryFilePolicy(
            sessionToken,
            HandleToULong(PsGetCurrentProcessId()),
            FILE_OP_WRITE,
            pathBuffer,
            NULL,
            0,
            FILE_WRITE_DATA,
            &decision))
    {
        if (decision == DECISION_DENY) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Pre-set-information callback (delete, rename)
FLT_PREOP_CALLBACK_STATUS
AgentshPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    ULONG64 sessionToken;
    AGENTSH_DECISION decision;
    WCHAR pathBuffer[AGENTSH_MAX_PATH];
    FILE_INFORMATION_CLASS infoClass;
    AGENTSH_FILE_OP operation;

    UNREFERENCED_PARAMETER(CompletionContext);

    // Fast path: not a session process
    if (!AgentshIsSessionProcess(PsGetCurrentProcessId(), &sessionToken)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // Only handle delete and rename
    if (infoClass == FileDispositionInformation ||
        infoClass == FileDispositionInformationEx) {
        operation = FILE_OP_DELETE;
    } else if (infoClass == FileRenameInformation ||
               infoClass == FileRenameInformationEx) {
        operation = FILE_OP_RENAME;
    } else {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get file path
    status = GetFilePath(Data, FltObjects, pathBuffer, AGENTSH_MAX_PATH);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check cache first
    if (AgentshCacheLookup(sessionToken, operation, pathBuffer, &decision)) {
        if (decision == DECISION_DENY) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Query policy (rename destination handling is simplified here)
    if (AgentshQueryFilePolicy(
            sessionToken,
            HandleToULong(PsGetCurrentProcessId()),
            operation,
            pathBuffer,
            NULL,  // TODO: Extract rename destination
            0,
            operation == FILE_OP_DELETE ? DELETE : 0,
            &decision))
    {
        if (decision == DECISION_DENY) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
