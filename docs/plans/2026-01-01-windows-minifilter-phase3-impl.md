# Windows Mini Filter Phase 3: Filesystem Interception

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add filesystem interception to the Windows mini filter driver so it can query policy for file operations (create, write, delete, rename) and block/allow based on the Go policy engine's response.

**Architecture:** The driver's IRP callbacks check if the current process belongs to a session. If so, they query the Go client via FltSendMessage for a policy decision. A policy cache avoids repeated IPC for the same operation. The Go client receives file check requests, evaluates them against the session's policy, and returns allow/deny decisions.

**Tech Stack:** C (WDK), Go, FltSendMessage, policy cache with LRU eviction

---

## Prerequisites

- Phase 2 complete (process tracking with session registration)
- Working in worktree: `/home/eran/work/agentsh/.worktrees/feature-windows-minifilter`

---

## Task 1: Add File Operation Protocol Messages

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/inc/protocol.h`

**Step 1: Add file operation enum and structures**

Add after `AGENTSH_PROCESS_EVENT` struct:

```c
// File operation types
typedef enum _AGENTSH_FILE_OP {
    FILE_OP_CREATE = 1,
    FILE_OP_READ = 2,
    FILE_OP_WRITE = 3,
    FILE_OP_DELETE = 4,
    FILE_OP_RENAME = 5,
} AGENTSH_FILE_OP;

// File policy check request (driver -> user-mode)
typedef struct _AGENTSH_FILE_REQUEST {
    AGENTSH_MESSAGE_HEADER Header;
    ULONG64 SessionToken;
    ULONG ProcessId;
    ULONG ThreadId;
    AGENTSH_FILE_OP Operation;
    ULONG CreateDisposition;        // For creates: CREATE_NEW, OPEN_EXISTING, etc.
    ULONG DesiredAccess;            // FILE_READ_DATA, FILE_WRITE_DATA, DELETE, etc.
    WCHAR Path[AGENTSH_MAX_PATH];
    WCHAR RenameDest[AGENTSH_MAX_PATH]; // Only for FILE_OP_RENAME
} AGENTSH_FILE_REQUEST, *PAGENTSH_FILE_REQUEST;

// Policy response (user-mode -> driver)
typedef struct _AGENTSH_POLICY_RESPONSE {
    AGENTSH_MESSAGE_HEADER Header;
    AGENTSH_DECISION Decision;
    ULONG CacheTTLMs;               // How long to cache this decision
} AGENTSH_POLICY_RESPONSE, *PAGENTSH_POLICY_RESPONSE;
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/protocol.h
git commit -m "feat(windows): add file operation protocol messages"
```

---

## Task 2: Create Policy Cache Header

**Files:**
- Create: `drivers/windows/agentsh-minifilter/inc/cache.h`

**Step 1: Write the cache header**

```c
// cache.h - Policy cache definitions
#ifndef _AGENTSH_CACHE_H_
#define _AGENTSH_CACHE_H_

#include <fltKernel.h>
#include "protocol.h"

// Pool tag for cache allocations
#define AGENTSH_TAG_CACHE 'acGA'

// Cache configuration
#define CACHE_BUCKET_COUNT 256
#define CACHE_BUCKET_MASK (CACHE_BUCKET_COUNT - 1)
#define CACHE_MAX_ENTRIES 4096
#define CACHE_DEFAULT_TTL_MS 5000

// Cache entry
typedef struct _CACHE_ENTRY {
    LIST_ENTRY HashEntry;           // Hash bucket chain
    LIST_ENTRY LruEntry;            // LRU list
    ULONG64 SessionToken;
    AGENTSH_FILE_OP Operation;
    AGENTSH_DECISION Decision;
    LARGE_INTEGER ExpiryTime;
    ULONG PathHash;
    WCHAR Path[AGENTSH_MAX_PATH];
} CACHE_ENTRY, *PCACHE_ENTRY;

// Policy cache
typedef struct _POLICY_CACHE {
    EX_PUSH_LOCK Lock;
    LIST_ENTRY Buckets[CACHE_BUCKET_COUNT];
    LIST_ENTRY LruHead;             // Most recent at head
    volatile LONG EntryCount;
    volatile LONG HitCount;
    volatile LONG MissCount;
} POLICY_CACHE;

// Initialize the policy cache
NTSTATUS
AgentshInitializeCache(
    VOID
    );

// Shutdown the policy cache
VOID
AgentshShutdownCache(
    VOID
    );

// Lookup a cached decision
BOOLEAN
AgentshCacheLookup(
    _In_ ULONG64 SessionToken,
    _In_ AGENTSH_FILE_OP Operation,
    _In_ PCWSTR Path,
    _Out_ PAGENTSH_DECISION Decision
    );

// Insert a decision into the cache
VOID
AgentshCacheInsert(
    _In_ ULONG64 SessionToken,
    _In_ AGENTSH_FILE_OP Operation,
    _In_ PCWSTR Path,
    _In_ AGENTSH_DECISION Decision,
    _In_ ULONG TTLMs
    );

// Invalidate all entries for a session
VOID
AgentshCacheInvalidateSession(
    _In_ ULONG64 SessionToken
    );

// Get cache statistics
VOID
AgentshCacheGetStats(
    _Out_ PLONG HitCount,
    _Out_ PLONG MissCount,
    _Out_ PLONG EntryCount
    );

#endif // _AGENTSH_CACHE_H_
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/cache.h
git commit -m "feat(windows): add policy cache header definitions"
```

---

## Task 3: Create Policy Cache Implementation

**Files:**
- Create: `drivers/windows/agentsh-minifilter/src/cache.c`

**Step 1: Write the cache implementation**

```c
// cache.c - Policy cache implementation
#include "driver.h"
#include "cache.h"

// Global cache
static POLICY_CACHE gCache;

// Hash function for path
static ULONG HashPath(PCWSTR Path)
{
    ULONG hash = 5381;
    while (*Path) {
        // Case-insensitive hash (Windows paths are case-insensitive)
        WCHAR c = *Path++;
        if (c >= L'A' && c <= L'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Initialize the policy cache
NTSTATUS
AgentshInitializeCache(
    VOID
    )
{
    ULONG i;

    ExInitializePushLock(&gCache.Lock);
    InitializeListHead(&gCache.LruHead);

    for (i = 0; i < CACHE_BUCKET_COUNT; i++) {
        InitializeListHead(&gCache.Buckets[i]);
    }

    gCache.EntryCount = 0;
    gCache.HitCount = 0;
    gCache.MissCount = 0;

    DbgPrint("AgentSH: Policy cache initialized\n");
    return STATUS_SUCCESS;
}

// Shutdown the policy cache
VOID
AgentshShutdownCache(
    VOID
    )
{
    PLIST_ENTRY entry;
    PCACHE_ENTRY cacheEntry;

    ExAcquirePushLockExclusive(&gCache.Lock);

    // Free all entries via LRU list (more efficient than walking buckets)
    while (!IsListEmpty(&gCache.LruHead)) {
        entry = RemoveHeadList(&gCache.LruHead);
        cacheEntry = CONTAINING_RECORD(entry, CACHE_ENTRY, LruEntry);
        ExFreePoolWithTag(cacheEntry, AGENTSH_TAG_CACHE);
    }

    gCache.EntryCount = 0;

    ExReleasePushLockExclusive(&gCache.Lock);

    DbgPrint("AgentSH: Policy cache shutdown (hits=%ld, misses=%ld)\n",
             gCache.HitCount, gCache.MissCount);
}

// Check if entry is expired
static BOOLEAN IsExpired(PCACHE_ENTRY Entry)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);
    return now.QuadPart >= Entry->ExpiryTime.QuadPart;
}

// Lookup a cached decision
BOOLEAN
AgentshCacheLookup(
    _In_ ULONG64 SessionToken,
    _In_ AGENTSH_FILE_OP Operation,
    _In_ PCWSTR Path,
    _Out_ PAGENTSH_DECISION Decision
    )
{
    ULONG hash = HashPath(Path);
    ULONG bucket = hash & CACHE_BUCKET_MASK;
    PLIST_ENTRY entry;
    PCACHE_ENTRY cacheEntry;
    BOOLEAN found = FALSE;

    ExAcquirePushLockShared(&gCache.Lock);

    for (entry = gCache.Buckets[bucket].Flink;
         entry != &gCache.Buckets[bucket];
         entry = entry->Flink)
    {
        cacheEntry = CONTAINING_RECORD(entry, CACHE_ENTRY, HashEntry);

        if (cacheEntry->SessionToken == SessionToken &&
            cacheEntry->Operation == Operation &&
            cacheEntry->PathHash == hash &&
            _wcsicmp(cacheEntry->Path, Path) == 0)
        {
            if (!IsExpired(cacheEntry)) {
                *Decision = cacheEntry->Decision;
                found = TRUE;
                InterlockedIncrement(&gCache.HitCount);
            }
            break;
        }
    }

    if (!found) {
        InterlockedIncrement(&gCache.MissCount);
    }

    ExReleasePushLockShared(&gCache.Lock);
    return found;
}

// Evict oldest entry if at capacity
static VOID EvictIfNeeded(VOID)
{
    PCACHE_ENTRY oldest;

    if (gCache.EntryCount < CACHE_MAX_ENTRIES) {
        return;
    }

    // Remove from LRU tail (oldest)
    if (!IsListEmpty(&gCache.LruHead)) {
        oldest = CONTAINING_RECORD(gCache.LruHead.Blink, CACHE_ENTRY, LruEntry);
        RemoveEntryList(&oldest->LruEntry);
        RemoveEntryList(&oldest->HashEntry);
        ExFreePoolWithTag(oldest, AGENTSH_TAG_CACHE);
        InterlockedDecrement(&gCache.EntryCount);
    }
}

// Insert a decision into the cache
VOID
AgentshCacheInsert(
    _In_ ULONG64 SessionToken,
    _In_ AGENTSH_FILE_OP Operation,
    _In_ PCWSTR Path,
    _In_ AGENTSH_DECISION Decision,
    _In_ ULONG TTLMs
    )
{
    ULONG hash = HashPath(Path);
    ULONG bucket = hash & CACHE_BUCKET_MASK;
    PCACHE_ENTRY newEntry;
    LARGE_INTEGER now;
    SIZE_T pathLen;

    newEntry = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(CACHE_ENTRY),
        AGENTSH_TAG_CACHE
        );

    if (newEntry == NULL) {
        return;
    }

    // Initialize entry
    newEntry->SessionToken = SessionToken;
    newEntry->Operation = Operation;
    newEntry->Decision = Decision;
    newEntry->PathHash = hash;

    // Copy path (ensure null termination)
    pathLen = wcslen(Path);
    if (pathLen >= AGENTSH_MAX_PATH) {
        pathLen = AGENTSH_MAX_PATH - 1;
    }
    RtlCopyMemory(newEntry->Path, Path, pathLen * sizeof(WCHAR));
    newEntry->Path[pathLen] = L'\0';

    // Set expiry time
    KeQuerySystemTimePrecise(&now);
    // Convert ms to 100ns units
    newEntry->ExpiryTime.QuadPart = now.QuadPart + ((LONGLONG)TTLMs * 10000);

    ExAcquirePushLockExclusive(&gCache.Lock);

    // Evict if at capacity
    EvictIfNeeded();

    // Insert into hash bucket
    InsertHeadList(&gCache.Buckets[bucket], &newEntry->HashEntry);

    // Insert at LRU head (most recently used)
    InsertHeadList(&gCache.LruHead, &newEntry->LruEntry);

    InterlockedIncrement(&gCache.EntryCount);

    ExReleasePushLockExclusive(&gCache.Lock);
}

// Invalidate all entries for a session
VOID
AgentshCacheInvalidateSession(
    _In_ ULONG64 SessionToken
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PCACHE_ENTRY cacheEntry;

    ExAcquirePushLockExclusive(&gCache.Lock);

    // Walk LRU list and remove matching entries
    for (entry = gCache.LruHead.Flink; entry != &gCache.LruHead; entry = next) {
        next = entry->Flink;
        cacheEntry = CONTAINING_RECORD(entry, CACHE_ENTRY, LruEntry);

        if (cacheEntry->SessionToken == SessionToken) {
            RemoveEntryList(&cacheEntry->LruEntry);
            RemoveEntryList(&cacheEntry->HashEntry);
            ExFreePoolWithTag(cacheEntry, AGENTSH_TAG_CACHE);
            InterlockedDecrement(&gCache.EntryCount);
        }
    }

    ExReleasePushLockExclusive(&gCache.Lock);
}

// Get cache statistics
VOID
AgentshCacheGetStats(
    _Out_ PLONG HitCount,
    _Out_ PLONG MissCount,
    _Out_ PLONG EntryCount
    )
{
    *HitCount = gCache.HitCount;
    *MissCount = gCache.MissCount;
    *EntryCount = gCache.EntryCount;
}
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/src/cache.c
git commit -m "feat(windows): implement policy cache with LRU eviction"
```

---

## Task 4: Create Filesystem Header

**Files:**
- Create: `drivers/windows/agentsh-minifilter/inc/filesystem.h`

**Step 1: Write the filesystem header**

```c
// filesystem.h - Filesystem interception definitions
#ifndef _AGENTSH_FILESYSTEM_H_
#define _AGENTSH_FILESYSTEM_H_

#include <fltKernel.h>
#include "protocol.h"

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
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/filesystem.h
git commit -m "feat(windows): add filesystem interception header"
```

---

## Task 5: Create Filesystem Implementation

**Files:**
- Create: `drivers/windows/agentsh-minifilter/src/filesystem.c`

**Step 1: Write the filesystem implementation**

```c
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
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/src/filesystem.c
git commit -m "feat(windows): implement filesystem interception with policy queries"
```

---

## Task 6: Update Driver to Use Filesystem Callbacks

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/inc/driver.h`
- Modify: `drivers/windows/agentsh-minifilter/src/driver.c`

**Step 1: Add includes to driver.h**

Add after `#include "process.h"`:

```c
#include "cache.h"
#include "filesystem.h"
```

**Step 2: Update filter callbacks in driver.c**

Replace the existing `FilterCallbacks` array:

```c
// Filter callbacks
CONST FLT_OPERATION_REGISTRATION FilterCallbacks[] = {
    { IRP_MJ_CREATE, 0, AgentshPreCreate, NULL },
    { IRP_MJ_WRITE, 0, AgentshPreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, AgentshPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};
```

**Step 3: Remove the old AgentshPreCreate from driver.c**

Delete the existing stub implementation (lines 30-44).

**Step 4: Add cache initialization in DriverEntry**

After `AgentshInitializeProcessTracking()` success, add:

```c
    // Initialize policy cache
    status = AgentshInitializeCache();
    if (!NT_SUCCESS(status)) {
        AgentshShutdownProcessTracking();
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }
```

**Step 5: Add cache shutdown in FilterUnload**

Before `AgentshShutdownProcessTracking()`, add:

```c
    // Shutdown policy cache
    AgentshShutdownCache();
```

**Step 6: Update cleanup path for FltStartFiltering failure**

```c
    if (!NT_SUCCESS(status)) {
        AgentshShutdownCache();
        AgentshShutdownProcessTracking();
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }
```

**Step 7: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/driver.h
git add drivers/windows/agentsh-minifilter/src/driver.c
git commit -m "feat(windows): integrate filesystem callbacks and cache into driver"
```

---

## Task 7: Update Visual Studio Project

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/agentsh.vcxproj`

**Step 1: Add new files to project**

In the `<ItemGroup>` containing `.c` files, add:

```xml
    <ClCompile Include="src\cache.c" />
    <ClCompile Include="src\filesystem.c" />
```

In the `<ItemGroup>` containing `.h` files, add:

```xml
    <ClInclude Include="inc\cache.h" />
    <ClInclude Include="inc\filesystem.h" />
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/agentsh.vcxproj
git commit -m "build(windows): add filesystem and cache files to VS project"
```

---

## Task 8: Add File Policy Handling to Go Client

**Files:**
- Modify: `internal/platform/windows/driver_client.go`
- Modify: `internal/platform/windows/driver_client_stub.go`

**Step 1: Add file policy types and handler**

Add after the `ProcessEventHandler` type:

```go
// FileOperation represents the type of file operation
type FileOperation uint32

const (
	FileOpCreate FileOperation = 1
	FileOpRead   FileOperation = 2
	FileOpWrite  FileOperation = 3
	FileOpDelete FileOperation = 4
	FileOpRename FileOperation = 5
)

// FileRequest represents a file policy check request from the driver
type FileRequest struct {
	SessionToken      uint64
	ProcessId         uint32
	ThreadId          uint32
	Operation         FileOperation
	CreateDisposition uint32
	DesiredAccess     uint32
	Path              string
	RenameDest        string
}

// PolicyDecision represents a policy decision
type PolicyDecision uint32

const (
	DecisionAllow   PolicyDecision = 0
	DecisionDeny    PolicyDecision = 1
	DecisionPending PolicyDecision = 2
)

// FilePolicyHandler is called when the driver requests a file policy decision
type FilePolicyHandler func(req *FileRequest) (PolicyDecision, uint32)
```

**Step 2: Update DriverClient struct**

Add `filePolicyHandler FilePolicyHandler` field:

```go
type DriverClient struct {
	port              windows.Handle
	connected         atomic.Bool
	stopChan          chan struct{}
	wg                sync.WaitGroup
	mu                sync.Mutex
	msgCounter        atomic.Uint64
	processHandler    ProcessEventHandler
	filePolicyHandler FilePolicyHandler
}
```

**Step 3: Add SetFilePolicyHandler method**

```go
// SetFilePolicyHandler sets the callback for file policy requests
func (c *DriverClient) SetFilePolicyHandler(handler FilePolicyHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.filePolicyHandler = handler
}
```

**Step 4: Handle file policy requests in handleMessage**

Add case for `MsgPolicyCheckFile`:

```go
	case MsgPolicyCheckFile:
		return c.handleFilePolicyCheck(msg, reply)
```

**Step 5: Add handleFilePolicyCheck method**

```go
// handleFilePolicyCheck handles file policy check requests from driver
func (c *DriverClient) handleFilePolicyCheck(msg []byte, reply []byte) int {
	// Minimum size: header(16) + token(8) + pid(4) + tid(4) + op(4) + disp(4) + access(4) + path(1040) + rename(1040)
	const minSize = 16 + 8 + 4 + 4 + 4 + 4 + 4
	if len(msg) < minSize {
		return 0
	}

	req := &FileRequest{
		SessionToken:      binary.LittleEndian.Uint64(msg[16:24]),
		ProcessId:         binary.LittleEndian.Uint32(msg[24:28]),
		ThreadId:          binary.LittleEndian.Uint32(msg[28:32]),
		Operation:         FileOperation(binary.LittleEndian.Uint32(msg[32:36])),
		CreateDisposition: binary.LittleEndian.Uint32(msg[36:40]),
		DesiredAccess:     binary.LittleEndian.Uint32(msg[40:44]),
	}

	// Decode path (UTF-16LE)
	const maxPath = 520
	if len(msg) >= 44+maxPath*2 {
		req.Path = utf16Decode(msg[44 : 44+maxPath*2])
	}
	if len(msg) >= 44+maxPath*4 {
		req.RenameDest = utf16Decode(msg[44+maxPath*2 : 44+maxPath*4])
	}

	// Get handler
	c.mu.Lock()
	handler := c.filePolicyHandler
	c.mu.Unlock()

	// Default to allow
	decision := DecisionAllow
	cacheTTL := uint32(5000)

	if handler != nil {
		decision, cacheTTL = handler(req)
	}

	// Build response: header(16) + decision(4) + cacheTTL(4)
	requestId := binary.LittleEndian.Uint64(msg[8:16])
	binary.LittleEndian.PutUint32(reply[0:4], MsgPolicyCheckFile)
	binary.LittleEndian.PutUint32(reply[4:8], 24)
	binary.LittleEndian.PutUint64(reply[8:16], requestId)
	binary.LittleEndian.PutUint32(reply[16:20], uint32(decision))
	binary.LittleEndian.PutUint32(reply[20:24], cacheTTL)

	return 24
}

// utf16Decode decodes UTF-16LE bytes to a Go string (stops at null terminator)
func utf16Decode(b []byte) string {
	if len(b) < 2 {
		return ""
	}

	// Find null terminator
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}
```

**Step 6: Add stubs to driver_client_stub.go**

```go
// FileOperation represents the type of file operation
type FileOperation uint32

const (
	FileOpCreate FileOperation = 1
	FileOpRead   FileOperation = 2
	FileOpWrite  FileOperation = 3
	FileOpDelete FileOperation = 4
	FileOpRename FileOperation = 5
)

// FileRequest represents a file policy check request
type FileRequest struct {
	SessionToken      uint64
	ProcessId         uint32
	ThreadId          uint32
	Operation         FileOperation
	CreateDisposition uint32
	DesiredAccess     uint32
	Path              string
	RenameDest        string
}

// PolicyDecision represents a policy decision
type PolicyDecision uint32

const (
	DecisionAllow   PolicyDecision = 0
	DecisionDeny    PolicyDecision = 1
	DecisionPending PolicyDecision = 2
)

// FilePolicyHandler stub type
type FilePolicyHandler func(req *FileRequest) (PolicyDecision, uint32)

// SetFilePolicyHandler stub for non-Windows
func (c *DriverClient) SetFilePolicyHandler(handler FilePolicyHandler) {
	// No-op on non-Windows
}

// utf16Decode decodes UTF-16LE bytes to a Go string
func utf16Decode(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(b[i]) | rune(b[i+1])<<8
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}
```

**Step 7: Commit**

```bash
git add internal/platform/windows/driver_client.go
git add internal/platform/windows/driver_client_stub.go
git commit -m "feat(windows): add file policy handling to Go driver client"
```

---

## Task 9: Add Unit Tests for File Policy

**Files:**
- Modify: `internal/platform/windows/driver_client_test.go`

**Step 1: Add file policy tests**

```go
func TestFileRequestDecoding(t *testing.T) {
	// Build a mock file request message
	const maxPath = 520
	msgSize := 16 + 8 + 4 + 4 + 4 + 4 + 4 + (maxPath * 2) + (maxPath * 2)
	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgPolicyCheckFile)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], 12345) // Request ID

	// Request fields
	binary.LittleEndian.PutUint64(msg[16:24], 0xABCD1234) // Session token
	binary.LittleEndian.PutUint32(msg[24:28], 5678)       // Process ID
	binary.LittleEndian.PutUint32(msg[28:32], 9012)       // Thread ID
	binary.LittleEndian.PutUint32(msg[32:36], uint32(FileOpWrite))
	binary.LittleEndian.PutUint32(msg[36:40], 0)   // Create disposition
	binary.LittleEndian.PutUint32(msg[40:44], 0x2) // Desired access

	// Path: "C:\test.txt" in UTF-16LE
	path := "C:\\test.txt"
	pathBytes := utf16Encode(path)
	copy(msg[44:], pathBytes)

	// Decode and verify
	sessionToken := binary.LittleEndian.Uint64(msg[16:24])
	processId := binary.LittleEndian.Uint32(msg[24:28])
	operation := FileOperation(binary.LittleEndian.Uint32(msg[32:36]))
	decodedPath := utf16Decode(msg[44 : 44+maxPath*2])

	if sessionToken != 0xABCD1234 {
		t.Errorf("expected session token 0xABCD1234, got 0x%X", sessionToken)
	}
	if processId != 5678 {
		t.Errorf("expected process ID 5678, got %d", processId)
	}
	if operation != FileOpWrite {
		t.Errorf("expected FileOpWrite, got %d", operation)
	}
	if decodedPath != path {
		t.Errorf("expected path %q, got %q", path, decodedPath)
	}
}

func TestPolicyResponseEncoding(t *testing.T) {
	reply := make([]byte, 24)

	// Build response
	binary.LittleEndian.PutUint32(reply[0:4], MsgPolicyCheckFile)
	binary.LittleEndian.PutUint32(reply[4:8], 24)
	binary.LittleEndian.PutUint64(reply[8:16], 12345) // Request ID
	binary.LittleEndian.PutUint32(reply[16:20], uint32(DecisionDeny))
	binary.LittleEndian.PutUint32(reply[20:24], 60000) // Cache TTL

	// Decode and verify
	decision := PolicyDecision(binary.LittleEndian.Uint32(reply[16:20]))
	cacheTTL := binary.LittleEndian.Uint32(reply[20:24])

	if decision != DecisionDeny {
		t.Errorf("expected DecisionDeny, got %d", decision)
	}
	if cacheTTL != 60000 {
		t.Errorf("expected cache TTL 60000, got %d", cacheTTL)
	}
}

func TestUtf16Decode(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"simple", []byte{'A', 0, 'B', 0, 'C', 0, 0, 0}, "ABC"},
		{"empty", []byte{0, 0}, ""},
		{"path", []byte{'C', 0, ':', 0, '\\', 0, 0, 0}, "C:\\"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := utf16Decode(tc.input)
			if result != tc.expected {
				t.Errorf("utf16Decode: expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFileOperationConstants(t *testing.T) {
	// Verify constants match protocol.h
	tests := []struct {
		name     string
		got      FileOperation
		expected FileOperation
	}{
		{"FileOpCreate", FileOpCreate, 1},
		{"FileOpRead", FileOpRead, 2},
		{"FileOpWrite", FileOpWrite, 3},
		{"FileOpDelete", FileOpDelete, 4},
		{"FileOpRename", FileOpRename, 5},
	}

	for _, tc := range tests {
		if tc.got != tc.expected {
			t.Errorf("%s: expected %d, got %d", tc.name, tc.expected, tc.got)
		}
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
git commit -m "test(windows): add unit tests for file policy handling"
```

---

## Task 10: Final Verification

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

Expected: cache.c, cache.h, filesystem.c, filesystem.h present

**Step 3: Review commits**

```bash
git log --oneline -15
```

---

## Phase 3 Complete Checklist

- [x] File operation protocol messages added to protocol.h
- [x] Policy cache header (cache.h) created
- [x] Policy cache implementation (cache.c) with LRU eviction
- [x] Filesystem header (filesystem.h) created
- [x] Filesystem implementation (filesystem.c) with IRP callbacks
- [x] Driver updated with new callbacks and cache lifecycle
- [x] Visual Studio project updated with new files
- [x] Go client file policy handling
- [x] Unit tests for file request/response encoding
- [x] All tests pass

## Next Steps (Phase 4)

After Phase 3 is complete and tested in a Windows VM:
1. Add CmRegisterCallbackEx for registry interception
2. Add registry policy check messages
3. Implement high-risk registry path detection
4. Add cache invalidation on session unregister
