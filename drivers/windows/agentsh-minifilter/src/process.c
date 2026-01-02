// process.c - Process tracking implementation
#include "driver.h"
#include "process.h"

// Global process table and session list
static PROCESS_TABLE gProcessTable;
static SESSION_LIST gSessionList;
static BOOLEAN gProcessCallbackRegistered = FALSE;

// Forward declaration
VOID
AgentshProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

// Hash function for PID
static __inline ULONG
HashProcessId(HANDLE ProcessId)
{
    return HandleToULong(ProcessId) & PROCESS_TABLE_MASK;
}

// Initialize process tracking
NTSTATUS
AgentshInitializeProcessTracking(
    VOID
    )
{
    NTSTATUS status;
    ULONG i;

    // Initialize process table
    ExInitializePushLock(&gProcessTable.Lock);
    for (i = 0; i < PROCESS_TABLE_SIZE; i++) {
        InitializeListHead(&gProcessTable.Buckets[i]);
    }
    gProcessTable.TotalCount = 0;

    // Initialize session list
    ExInitializePushLock(&gSessionList.Lock);
    InitializeListHead(&gSessionList.Head);
    gSessionList.Count = 0;

    // Register process notification callback
    status = PsSetCreateProcessNotifyRoutineEx(
        AgentshProcessNotifyCallback,
        FALSE   // Remove = FALSE (register)
        );

    if (NT_SUCCESS(status)) {
        gProcessCallbackRegistered = TRUE;
        DbgPrint("AgentSH: Process tracking initialized\n");
    } else {
        DbgPrint("AgentSH: Failed to register process callback: 0x%08X\n", status);
    }

    return status;
}

// Shutdown process tracking
VOID
AgentshShutdownProcessTracking(
    VOID
    )
{
    PLIST_ENTRY entry;
    PSESSION_PROCESS proc;
    PSESSION_INFO session;
    ULONG i;

    // Unregister callback first
    if (gProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(AgentshProcessNotifyCallback, TRUE);
        gProcessCallbackRegistered = FALSE;
    }

    // Free all process entries
    ExAcquirePushLockExclusive(&gProcessTable.Lock);
    for (i = 0; i < PROCESS_TABLE_SIZE; i++) {
        while (!IsListEmpty(&gProcessTable.Buckets[i])) {
            entry = RemoveHeadList(&gProcessTable.Buckets[i]);
            proc = CONTAINING_RECORD(entry, SESSION_PROCESS, ListEntry);
            ExFreePoolWithTag(proc, AGENTSH_TAG_PROCESS);
        }
    }
    gProcessTable.TotalCount = 0;
    ExReleasePushLockExclusive(&gProcessTable.Lock);

    // Free all session entries
    ExAcquirePushLockExclusive(&gSessionList.Lock);
    while (!IsListEmpty(&gSessionList.Head)) {
        entry = RemoveHeadList(&gSessionList.Head);
        session = CONTAINING_RECORD(entry, SESSION_INFO, ListEntry);
        if (session->WorkspacePath.Buffer != NULL) {
            ExFreePoolWithTag(session->WorkspacePath.Buffer, AGENTSH_TAG_SESSION);
        }
        ExFreePoolWithTag(session, AGENTSH_TAG_SESSION);
    }
    gSessionList.Count = 0;
    ExReleasePushLockExclusive(&gSessionList.Lock);

    DbgPrint("AgentSH: Process tracking shutdown\n");
}

// Register a session
NTSTATUS
AgentshRegisterSession(
    _In_ ULONG64 SessionToken,
    _In_ HANDLE RootProcessId,
    _In_opt_ PCWSTR WorkspacePath
    )
{
    PSESSION_INFO session;
    SIZE_T pathLen;
    NTSTATUS status;

    // Allocate session info
    session = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SESSION_INFO),
        AGENTSH_TAG_SESSION
        );

    if (session == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(session, sizeof(SESSION_INFO));
    session->SessionToken = SessionToken;
    session->RootProcessId = RootProcessId;
    session->ProcessCount = 0;

    // Copy workspace path if provided
    if (WorkspacePath != NULL) {
        pathLen = wcslen(WorkspacePath) * sizeof(WCHAR);
        session->WorkspacePath.Buffer = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            pathLen + sizeof(WCHAR),
            AGENTSH_TAG_SESSION
            );

        if (session->WorkspacePath.Buffer != NULL) {
            RtlCopyMemory(session->WorkspacePath.Buffer, WorkspacePath, pathLen);
            session->WorkspacePath.Buffer[pathLen / sizeof(WCHAR)] = L'\0';
            session->WorkspacePath.Length = (USHORT)pathLen;
            session->WorkspacePath.MaximumLength = (USHORT)(pathLen + sizeof(WCHAR));
        }
    }

    // Add to session list
    ExAcquirePushLockExclusive(&gSessionList.Lock);
    InsertTailList(&gSessionList.Head, &session->ListEntry);
    InterlockedIncrement(&gSessionList.Count);
    ExReleasePushLockExclusive(&gSessionList.Lock);

    // Add root process to tracking
    status = AgentshAddSessionProcess(RootProcessId, NULL, SessionToken);
    if (!NT_SUCCESS(status)) {
        // Remove session on failure
        ExAcquirePushLockExclusive(&gSessionList.Lock);
        RemoveEntryList(&session->ListEntry);
        InterlockedDecrement(&gSessionList.Count);
        ExReleasePushLockExclusive(&gSessionList.Lock);

        if (session->WorkspacePath.Buffer != NULL) {
            ExFreePoolWithTag(session->WorkspacePath.Buffer, AGENTSH_TAG_SESSION);
        }
        ExFreePoolWithTag(session, AGENTSH_TAG_SESSION);
        return status;
    }

    DbgPrint("AgentSH: Session registered (token=0x%llX, root=%u)\n",
             SessionToken, HandleToULong(RootProcessId));

    return STATUS_SUCCESS;
}

// Unregister a session
NTSTATUS
AgentshUnregisterSession(
    _In_ ULONG64 SessionToken
    )
{
    PLIST_ENTRY entry;
    PSESSION_INFO session = NULL;
    PSESSION_PROCESS proc;
    ULONG i;

    // Find and remove session
    ExAcquirePushLockExclusive(&gSessionList.Lock);
    for (entry = gSessionList.Head.Flink;
         entry != &gSessionList.Head;
         entry = entry->Flink)
    {
        PSESSION_INFO s = CONTAINING_RECORD(entry, SESSION_INFO, ListEntry);
        if (s->SessionToken == SessionToken) {
            RemoveEntryList(entry);
            InterlockedDecrement(&gSessionList.Count);
            session = s;
            break;
        }
    }
    ExReleasePushLockExclusive(&gSessionList.Lock);

    if (session == NULL) {
        return STATUS_NOT_FOUND;
    }

    // Remove all processes for this session
    ExAcquirePushLockExclusive(&gProcessTable.Lock);
    for (i = 0; i < PROCESS_TABLE_SIZE; i++) {
        entry = gProcessTable.Buckets[i].Flink;
        while (entry != &gProcessTable.Buckets[i]) {
            proc = CONTAINING_RECORD(entry, SESSION_PROCESS, ListEntry);
            entry = entry->Flink;  // Advance before potential removal

            if (proc->SessionToken == SessionToken) {
                RemoveEntryList(&proc->ListEntry);
                InterlockedDecrement(&gProcessTable.TotalCount);
                ExFreePoolWithTag(proc, AGENTSH_TAG_PROCESS);
            }
        }
    }
    ExReleasePushLockExclusive(&gProcessTable.Lock);

    // Free session
    if (session->WorkspacePath.Buffer != NULL) {
        ExFreePoolWithTag(session->WorkspacePath.Buffer, AGENTSH_TAG_SESSION);
    }
    ExFreePoolWithTag(session, AGENTSH_TAG_SESSION);

    DbgPrint("AgentSH: Session unregistered (token=0x%llX)\n", SessionToken);

    return STATUS_SUCCESS;
}

// Check if a process belongs to a session
BOOLEAN
AgentshIsSessionProcess(
    _In_ HANDLE ProcessId,
    _Out_ PULONG64 SessionToken
    )
{
    ULONG bucket = HashProcessId(ProcessId);
    PLIST_ENTRY entry;
    PSESSION_PROCESS proc;
    BOOLEAN found = FALSE;

    *SessionToken = 0;

    ExAcquirePushLockShared(&gProcessTable.Lock);

    for (entry = gProcessTable.Buckets[bucket].Flink;
         entry != &gProcessTable.Buckets[bucket];
         entry = entry->Flink)
    {
        proc = CONTAINING_RECORD(entry, SESSION_PROCESS, ListEntry);
        if (proc->ProcessId == ProcessId) {
            *SessionToken = proc->SessionToken;
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&gProcessTable.Lock);
    return found;
}

// Get session info by token
PSESSION_INFO
AgentshGetSessionInfo(
    _In_ ULONG64 SessionToken
    )
{
    PLIST_ENTRY entry;
    PSESSION_INFO session = NULL;

    ExAcquirePushLockShared(&gSessionList.Lock);

    for (entry = gSessionList.Head.Flink;
         entry != &gSessionList.Head;
         entry = entry->Flink)
    {
        PSESSION_INFO s = CONTAINING_RECORD(entry, SESSION_INFO, ListEntry);
        if (s->SessionToken == SessionToken) {
            session = s;
            break;
        }
    }

    ExReleasePushLockShared(&gSessionList.Lock);
    return session;
}

// Add process to tracking table
NTSTATUS
AgentshAddSessionProcess(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_ ULONG64 SessionToken
    )
{
    PSESSION_PROCESS proc;
    ULONG bucket;

    proc = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SESSION_PROCESS),
        AGENTSH_TAG_PROCESS
        );

    if (proc == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    proc->ProcessId = ProcessId;
    proc->ParentProcessId = ParentProcessId;
    proc->SessionToken = SessionToken;
    KeQuerySystemTimePrecise(&proc->CreateTime);

    bucket = HashProcessId(ProcessId);

    ExAcquirePushLockExclusive(&gProcessTable.Lock);
    InsertTailList(&gProcessTable.Buckets[bucket], &proc->ListEntry);
    InterlockedIncrement(&gProcessTable.TotalCount);
    ExReleasePushLockExclusive(&gProcessTable.Lock);

    // Increment session process count
    {
        PSESSION_INFO session = AgentshGetSessionInfo(SessionToken);
        if (session != NULL) {
            InterlockedIncrement(&session->ProcessCount);
        }
    }

    return STATUS_SUCCESS;
}

// Remove process from tracking table
BOOLEAN
AgentshRemoveSessionProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG64 SessionToken
    )
{
    ULONG bucket = HashProcessId(ProcessId);
    PLIST_ENTRY entry;
    PSESSION_PROCESS proc;
    BOOLEAN found = FALSE;
    ULONG64 token = 0;

    ExAcquirePushLockExclusive(&gProcessTable.Lock);

    for (entry = gProcessTable.Buckets[bucket].Flink;
         entry != &gProcessTable.Buckets[bucket];
         entry = entry->Flink)
    {
        proc = CONTAINING_RECORD(entry, SESSION_PROCESS, ListEntry);
        if (proc->ProcessId == ProcessId) {
            token = proc->SessionToken;
            RemoveEntryList(entry);
            InterlockedDecrement(&gProcessTable.TotalCount);
            ExFreePoolWithTag(proc, AGENTSH_TAG_PROCESS);
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockExclusive(&gProcessTable.Lock);

    if (found) {
        // Decrement session process count
        PSESSION_INFO session = AgentshGetSessionInfo(token);
        if (session != NULL) {
            InterlockedDecrement(&session->ProcessCount);
        }
    }

    if (SessionToken != NULL) {
        *SessionToken = token;
    }

    return found;
}

// Process creation/termination callback
VOID
AgentshProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    ULONG64 parentSession;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        // Process creation - check if parent is tracked
        if (AgentshIsSessionProcess(CreateInfo->ParentProcessId, &parentSession)) {
            // Add child to same session
            NTSTATUS status = AgentshAddSessionProcess(
                ProcessId,
                CreateInfo->ParentProcessId,
                parentSession
                );

            if (NT_SUCCESS(status)) {
                DbgPrint("AgentSH: Child process %u added to session 0x%llX (parent=%u)\n",
                         HandleToULong(ProcessId),
                         parentSession,
                         HandleToULong(CreateInfo->ParentProcessId));
            }
        }
    } else {
        // Process termination - remove if tracked
        ULONG64 sessionToken;
        if (AgentshRemoveSessionProcess(ProcessId, &sessionToken)) {
            DbgPrint("AgentSH: Process %u removed from session 0x%llX\n",
                     HandleToULong(ProcessId), sessionToken);
        }
    }
}
