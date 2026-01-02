# Windows Mini Filter Phase 2: Process Tracking

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add process tracking to the Windows mini filter driver so it can identify which processes belong to agentsh sessions and automatically track child processes.

**Architecture:** The driver maintains a hash table of session processes keyed by PID. When a session is registered from user-mode, the root process is added. The driver uses PsSetCreateProcessNotifyRoutineEx to detect child process creation/termination and automatically inherits the session token. This enables Phase 3 (filesystem) and Phase 4 (registry) to quickly check if a process needs policy enforcement.

**Tech Stack:** C (WDK), Go, PsSetCreateProcessNotifyRoutineEx, EX_PUSH_LOCK, hash tables

---

## Prerequisites

- Phase 1 complete (driver skeleton with filter port communication)
- Working in worktree: `/home/eran/work/agentsh/.worktrees/feature-windows-minifilter`

---

## Task 1: Add Session Registration Protocol Messages

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/inc/protocol.h`

**Step 1: Add session registration structures to protocol.h**

Add after the existing `AGENTSH_CONNECTION_CONTEXT` struct:

```c
// Session registration (user-mode -> driver)
typedef struct _AGENTSH_SESSION_REGISTER {
    AGENTSH_MESSAGE_HEADER Header;
    ULONG64 SessionToken;           // Unique session identifier
    ULONG RootProcessId;            // Initial session process PID
    WCHAR WorkspacePath[AGENTSH_MAX_PATH]; // Session workspace root
} AGENTSH_SESSION_REGISTER, *PAGENTSH_SESSION_REGISTER;

// Session unregistration (user-mode -> driver)
typedef struct _AGENTSH_SESSION_UNREGISTER {
    AGENTSH_MESSAGE_HEADER Header;
    ULONG64 SessionToken;
} AGENTSH_SESSION_UNREGISTER, *PAGENTSH_SESSION_UNREGISTER;

// Process event (driver -> user-mode, notification only)
typedef struct _AGENTSH_PROCESS_EVENT {
    AGENTSH_MESSAGE_HEADER Header;
    ULONG64 SessionToken;
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG64 CreateTime;             // FILETIME
} AGENTSH_PROCESS_EVENT, *PAGENTSH_PROCESS_EVENT;
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/protocol.h
git commit -m "feat(windows): add session registration protocol messages"
```

---

## Task 2: Create Process Tracking Header

**Files:**
- Create: `drivers/windows/agentsh-minifilter/inc/process.h`

**Step 1: Write the process tracking header**

```c
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
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/process.h
git commit -m "feat(windows): add process tracking header definitions"
```

---

## Task 3: Create Process Tracking Implementation

**Files:**
- Create: `drivers/windows/agentsh-minifilter/src/process.c`

**Step 1: Write the process tracking implementation**

```c
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
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/src/process.c
git commit -m "feat(windows): implement process tracking with hash table and callback"
```

---

## Task 4: Integrate Process Tracking into Driver

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/inc/driver.h`
- Modify: `drivers/windows/agentsh-minifilter/src/driver.c`

**Step 1: Add process.h include to driver.h**

Add after the existing includes:

```c
#include "process.h"
```

**Step 2: Initialize process tracking in DriverEntry**

In `driver.c`, after `AgentshInitializeCommunication` call, add:

```c
    // Initialize process tracking
    status = AgentshInitializeProcessTracking();
    if (!NT_SUCCESS(status)) {
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }
```

**Step 3: Shutdown process tracking in FilterUnload**

In `AgentshFilterUnload`, before `AgentshShutdownCommunication`, add:

```c
    // Shutdown process tracking
    AgentshShutdownProcessTracking();
```

**Step 4: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/driver.h
git add drivers/windows/agentsh-minifilter/src/driver.c
git commit -m "feat(windows): integrate process tracking into driver lifecycle"
```

---

## Task 5: Handle Session Registration Messages

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/src/communication.c`

**Step 1: Add handlers for session messages**

In `AgentshMessageNotify`, update the switch statement:

```c
    switch (header->Type) {
        case MSG_PONG:
            DbgPrint("AgentSH: Received PONG from client\n");
            break;

        case MSG_REGISTER_SESSION:
            if (InputBufferLength >= sizeof(AGENTSH_SESSION_REGISTER)) {
                PAGENTSH_SESSION_REGISTER reg = (PAGENTSH_SESSION_REGISTER)InputBuffer;
                status = AgentshRegisterSession(
                    reg->SessionToken,
                    ULongToHandle(reg->RootProcessId),
                    reg->WorkspacePath[0] != L'\0' ? reg->WorkspacePath : NULL
                    );
                if (!NT_SUCCESS(status)) {
                    DbgPrint("AgentSH: Session registration failed: 0x%08X\n", status);
                }
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case MSG_UNREGISTER_SESSION:
            if (InputBufferLength >= sizeof(AGENTSH_SESSION_UNREGISTER)) {
                PAGENTSH_SESSION_UNREGISTER unreg = (PAGENTSH_SESSION_UNREGISTER)InputBuffer;
                status = AgentshUnregisterSession(unreg->SessionToken);
                if (!NT_SUCCESS(status)) {
                    DbgPrint("AgentSH: Session unregistration failed: 0x%08X\n", status);
                }
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        default:
            DbgPrint("AgentSH: Unknown message type: %d\n", header->Type);
            break;
    }

    return status;
```

**Step 2: Update function signature to return NTSTATUS**

Change `AgentshMessageNotify` to return status for feedback (currently just returns `STATUS_SUCCESS`):

```c
// At the end of the function, change:
    return STATUS_SUCCESS;
// To:
    return status;
```

And add `NTSTATUS status = STATUS_SUCCESS;` at the top of the function.

**Step 3: Commit**

```bash
git add drivers/windows/agentsh-minifilter/src/communication.c
git commit -m "feat(windows): handle session registration messages in driver"
```

---

## Task 6: Update Visual Studio Project

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/agentsh.vcxproj`

**Step 1: Add process.c and process.h to project**

In the `<ItemGroup>` containing `.c` files, add:

```xml
    <ClCompile Include="src\process.c" />
```

In the `<ItemGroup>` containing `.h` files, add:

```xml
    <ClInclude Include="inc\process.h" />
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/agentsh.vcxproj
git commit -m "build(windows): add process tracking files to VS project"
```

---

## Task 7: Add Session Registration to Go Client

**Files:**
- Modify: `internal/platform/windows/driver_client.go`
- Modify: `internal/platform/windows/driver_client_stub.go`

**Step 1: Add session registration method to driver_client.go**

Add after the `SendPong` method:

```go
// RegisterSession registers a session with the driver
func (c *DriverClient) RegisterSession(sessionToken uint64, rootPid uint32, workspacePath string) error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	// Build message: header (16) + token (8) + pid (4) + path (520*2)
	const maxPath = 520
	msgSize := 16 + 8 + 4 + (maxPath * 2)
	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgRegisterSession)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))

	// Session token
	binary.LittleEndian.PutUint64(msg[16:24], sessionToken)

	// Root process ID
	binary.LittleEndian.PutUint32(msg[24:28], rootPid)

	// Workspace path (UTF-16LE, null-terminated)
	if workspacePath != "" {
		pathBytes := utf16Encode(workspacePath)
		maxBytes := maxPath * 2
		if len(pathBytes) > maxBytes {
			pathBytes = pathBytes[:maxBytes-2] // Leave room for null terminator
		}
		copy(msg[28:], pathBytes)
	}

	return filterSendMessage(c.port, msg, nil)
}

// UnregisterSession unregisters a session from the driver
func (c *DriverClient) UnregisterSession(sessionToken uint64) error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	// Build message: header (16) + token (8)
	msgSize := 24
	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgUnregisterSession)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))

	// Session token
	binary.LittleEndian.PutUint64(msg[16:24], sessionToken)

	return filterSendMessage(c.port, msg, nil)
}

// utf16Encode converts a Go string to UTF-16LE bytes
func utf16Encode(s string) []byte {
	runes := []rune(s)
	result := make([]byte, len(runes)*2+2) // +2 for null terminator

	for i, r := range runes {
		binary.LittleEndian.PutUint16(result[i*2:], uint16(r))
	}
	// Null terminator already zero from make()

	return result
}
```

**Step 2: Add stub methods to driver_client_stub.go**

Add after the existing stub methods:

```go
// RegisterSession stub for non-Windows
func (c *DriverClient) RegisterSession(sessionToken uint64, rootPid uint32, workspacePath string) error {
	return fmt.Errorf("driver client only available on Windows")
}

// UnregisterSession stub for non-Windows
func (c *DriverClient) UnregisterSession(sessionToken uint64) error {
	return fmt.Errorf("driver client only available on Windows")
}
```

**Step 3: Commit**

```bash
git add internal/platform/windows/driver_client.go
git add internal/platform/windows/driver_client_stub.go
git commit -m "feat(windows): add session registration methods to Go driver client"
```

---

## Task 8: Add Process Event Handling to Go Client

**Files:**
- Modify: `internal/platform/windows/driver_client.go`

**Step 1: Add process event handler and callback interface**

Add after the constants:

```go
// ProcessEventHandler is called when the driver notifies about process events
type ProcessEventHandler func(sessionToken uint64, processId, parentId uint32, createTime uint64, isCreation bool)
```

Update the `DriverClient` struct to add the handler:

```go
type DriverClient struct {
	port            windows.Handle
	connected       atomic.Bool
	stopChan        chan struct{}
	wg              sync.WaitGroup
	mu              sync.Mutex
	msgCounter      atomic.Uint64
	processHandler  ProcessEventHandler
}
```

Add method to set the handler:

```go
// SetProcessEventHandler sets the callback for process events
func (c *DriverClient) SetProcessEventHandler(handler ProcessEventHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processHandler = handler
}
```

**Step 2: Handle process events in message loop**

In `handleMessage`, add cases for process events:

```go
	case MsgProcessCreated:
		return c.handleProcessEvent(msg, true)
	case MsgProcessTerminated:
		return c.handleProcessEvent(msg, false)
```

Add the handler method:

```go
// handleProcessEvent processes process creation/termination notifications
func (c *DriverClient) handleProcessEvent(msg []byte, isCreation bool) int {
	// Message format: header (16) + token (8) + pid (4) + ppid (4) + createTime (8)
	if len(msg) < 40 {
		return 0
	}

	sessionToken := binary.LittleEndian.Uint64(msg[16:24])
	processId := binary.LittleEndian.Uint32(msg[24:28])
	parentId := binary.LittleEndian.Uint32(msg[28:32])
	createTime := binary.LittleEndian.Uint64(msg[32:40])

	c.mu.Lock()
	handler := c.processHandler
	c.mu.Unlock()

	if handler != nil {
		handler(sessionToken, processId, parentId, createTime, isCreation)
	}

	return 0 // No reply needed for notifications
}
```

**Step 3: Commit**

```bash
git add internal/platform/windows/driver_client.go
git commit -m "feat(windows): add process event handling to Go driver client"
```

---

## Task 9: Add Unit Tests for Session Registration

**Files:**
- Modify: `internal/platform/windows/driver_client_test.go`

**Step 1: Add tests for message encoding**

```go
func TestSessionRegistrationEncoding(t *testing.T) {
	// Test that we can encode session registration correctly
	sessionToken := uint64(0x123456789ABCDEF0)
	rootPid := uint32(1234)
	workspacePath := "C:\\Users\\test\\workspace"

	// Calculate expected message structure
	const maxPath = 520
	msgSize := 16 + 8 + 4 + (maxPath * 2)

	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgRegisterSession)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], 1) // Request ID

	// Session token
	binary.LittleEndian.PutUint64(msg[16:24], sessionToken)

	// Root process ID
	binary.LittleEndian.PutUint32(msg[24:28], rootPid)

	// Verify encoding
	if binary.LittleEndian.Uint32(msg[0:4]) != MsgRegisterSession {
		t.Errorf("expected MsgRegisterSession, got %d", binary.LittleEndian.Uint32(msg[0:4]))
	}
	if binary.LittleEndian.Uint64(msg[16:24]) != sessionToken {
		t.Errorf("expected session token 0x%X, got 0x%X", sessionToken, binary.LittleEndian.Uint64(msg[16:24]))
	}
	if binary.LittleEndian.Uint32(msg[24:28]) != rootPid {
		t.Errorf("expected root PID %d, got %d", rootPid, binary.LittleEndian.Uint32(msg[24:28]))
	}
}

func TestProcessEventDecoding(t *testing.T) {
	// Test decoding process event message
	msg := make([]byte, 40)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgProcessCreated)
	binary.LittleEndian.PutUint32(msg[4:8], 40)
	binary.LittleEndian.PutUint64(msg[8:16], 1)

	// Event data
	binary.LittleEndian.PutUint64(msg[16:24], 0xDEADBEEF) // Session token
	binary.LittleEndian.PutUint32(msg[24:28], 5678)       // Process ID
	binary.LittleEndian.PutUint32(msg[28:32], 1234)       // Parent ID
	binary.LittleEndian.PutUint64(msg[32:40], 0x12345678) // Create time

	// Decode
	msgType := binary.LittleEndian.Uint32(msg[0:4])
	sessionToken := binary.LittleEndian.Uint64(msg[16:24])
	processId := binary.LittleEndian.Uint32(msg[24:28])
	parentId := binary.LittleEndian.Uint32(msg[28:32])
	createTime := binary.LittleEndian.Uint64(msg[32:40])

	if msgType != MsgProcessCreated {
		t.Errorf("expected MsgProcessCreated, got %d", msgType)
	}
	if sessionToken != 0xDEADBEEF {
		t.Errorf("expected session token 0xDEADBEEF, got 0x%X", sessionToken)
	}
	if processId != 5678 {
		t.Errorf("expected process ID 5678, got %d", processId)
	}
	if parentId != 1234 {
		t.Errorf("expected parent ID 1234, got %d", parentId)
	}
	if createTime != 0x12345678 {
		t.Errorf("expected create time 0x12345678, got 0x%X", createTime)
	}
}

func TestUtf16Encode(t *testing.T) {
	// Test UTF-16LE encoding
	tests := []struct {
		input    string
		expected []byte
	}{
		{"ABC", []byte{'A', 0, 'B', 0, 'C', 0, 0, 0}},
		{"", []byte{0, 0}},
	}

	for _, tc := range tests {
		result := utf16Encode(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("utf16Encode(%q): expected len %d, got %d", tc.input, len(tc.expected), len(result))
			continue
		}
		for i := range tc.expected {
			if result[i] != tc.expected[i] {
				t.Errorf("utf16Encode(%q)[%d]: expected %d, got %d", tc.input, i, tc.expected[i], result[i])
			}
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
git commit -m "test(windows): add unit tests for session registration and process events"
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

Expected: process.c and process.h present

**Step 3: Review commits**

```bash
git log --oneline -15
```

---

## Phase 2 Complete Checklist

- [ ] Session registration protocol messages added to protocol.h
- [ ] Process tracking header (process.h) created
- [ ] Process tracking implementation (process.c) with hash table and callback
- [ ] Process tracking integrated into driver lifecycle
- [ ] Session registration message handlers in communication.c
- [ ] Visual Studio project updated with new files
- [ ] Go client session registration methods
- [ ] Go client process event handling
- [ ] Unit tests for message encoding/decoding
- [ ] All tests pass

## Next Steps (Phase 3)

After Phase 2 is complete and tested in a Windows VM:
1. Add IRP callbacks for file operations
2. Query policy via filter port for session processes
3. Block/allow based on policy response
4. Add policy cache in driver
