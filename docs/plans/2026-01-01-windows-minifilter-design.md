# Windows Mini Filter Driver Design

**Status:** Approved
**Created:** 2026-01-01
**Author:** Claude + Eran

## Overview

This document describes the architecture for implementing a Windows kernel mini filter driver for agentsh. The driver provides full file system and registry interception with blocking capabilities, achieving feature parity with Linux and exceeding the current Windows stub implementation.

## Goals

- **Full feature parity**: Match Linux/macOS capabilities for file and network interception
- **Registry blocking**: Windows-specific capability - block writes to persistence/security paths
- **Kernel-level enforcement**: Cannot be bypassed by user-mode code
- **Minimal latency**: Target <1ms for cached decisions, <10ms for policy queries

## Requirements

### Development Requirements

| Requirement | Purpose |
|-------------|---------|
| Windows Driver Kit (WDK) | Driver compilation |
| Visual Studio 2022+ | Build toolchain |
| Test signing enabled | Development/testing |
| Windows 10/11 VM | Safe testing environment |

### Production Requirements

| Requirement | Purpose |
|-------------|---------|
| EV Code Signing Certificate | Production driver signing |
| Microsoft Hardware Dev Center | Attestation signing (Win10 1607+) |
| Administrator privileges | Driver installation |

## Architecture Overview

The implementation follows a similar pattern to the macOS ESF design: a privileged native component (kernel driver) communicates with the Go agentsh server via IPC.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Mode                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────┐         ┌──────────────────────────────┐  │
│  │    agentsh server    │◄───────►│  Windows Driver Client       │  │
│  │    (Go, policy)      │  chan   │  (Go, FilterConnect API)     │  │
│  └──────────────────────┘         └──────────────┬───────────────┘  │
│                                                  │                   │
│                                                  │ Filter Port       │
│                                                  │ (FltSendMessage)  │
├──────────────────────────────────────────────────┼──────────────────┤
│                         Kernel Mode              │                   │
├──────────────────────────────────────────────────┼──────────────────┤
│                                                  ▼                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  agentsh.sys Mini Filter                       │  │
│  ├───────────────────┬───────────────────┬───────────────────────┤  │
│  │  Filesystem Ops   │   Registry Ops    │   Process Tracking    │  │
│  │  (IRP callbacks)  │ (CmRegisterCb)    │ (PsSetCreateNotify)   │  │
│  └───────────────────┴───────────────────┴───────────────────────┘  │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐              │
│  │  NTFS.sys   │    │  Registry   │    │  Process    │              │
│  │             │    │  Hive       │    │  Manager    │              │
│  └─────────────┘    └─────────────┘    └─────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Role |
|-----------|------|
| **agentsh.sys** | Kernel mini filter - intercepts file/registry ops, tracks processes, queries policy |
| **Driver Client (Go)** | Connects to filter port, receives policy queries, sends decisions |
| **Policy Engine (Go)** | Existing agentsh policy engine - unchanged |

The driver is intentionally "dumb" - it intercepts, asks, and enforces. All policy logic stays in Go.

## Filter Port Communication Protocol

The driver and user-mode client communicate via filter ports using a request/response protocol.

### Message Types

```c
// protocol.h - shared between driver and Go client

typedef enum _AGENTSH_MSG_TYPE {
    // Driver → User-mode (requests)
    MSG_POLICY_CHECK_FILE = 1,
    MSG_POLICY_CHECK_REGISTRY = 2,
    MSG_PROCESS_CREATED = 3,
    MSG_PROCESS_TERMINATED = 4,

    // User-mode → Driver (commands)
    MSG_REGISTER_SESSION = 100,
    MSG_UNREGISTER_SESSION = 101,
    MSG_UPDATE_CACHE = 102,
    MSG_SHUTDOWN = 103,
} AGENTSH_MSG_TYPE;

typedef enum _AGENTSH_DECISION {
    DECISION_ALLOW = 0,
    DECISION_DENY = 1,
    DECISION_PENDING = 2,  // Hold for approval
} AGENTSH_DECISION;
```

### Policy Check Message (File)

```c
typedef struct _AGENTSH_FILE_REQUEST {
    AGENTSH_MSG_TYPE Type;          // MSG_POLICY_CHECK_FILE
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG64 SessionToken;           // Maps to agentsh session
    ULONG Operation;                // Create/Read/Write/Delete/Rename
    ULONG CreateDisposition;        // For creates: CREATE_NEW, OPEN_EXISTING, etc.
    ULONG DesiredAccess;            // Read/Write/Delete access flags
    WCHAR Path[MAX_PATH_LENGTH];    // Full NT path
    WCHAR RenameDest[MAX_PATH_LENGTH]; // For renames only
} AGENTSH_FILE_REQUEST;

typedef struct _AGENTSH_POLICY_RESPONSE {
    AGENTSH_DECISION Decision;
    ULONG CacheTTLMs;               // How long driver can cache this decision
    WCHAR RedirectPath[MAX_PATH_LENGTH]; // For redirects (empty = no redirect)
} AGENTSH_POLICY_RESPONSE;
```

### Policy Check Message (Registry)

```c
typedef struct _AGENTSH_REGISTRY_REQUEST {
    AGENTSH_MSG_TYPE Type;          // MSG_POLICY_CHECK_REGISTRY
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG64 SessionToken;
    ULONG Operation;                // CreateKey/SetValue/DeleteKey/QueryValue/etc.
    WCHAR KeyPath[MAX_PATH_LENGTH]; // Full registry path
    WCHAR ValueName[256];           // For value operations
    ULONG ValueType;                // REG_SZ, REG_DWORD, etc.
    ULONG DataSize;                 // Size of value data
} AGENTSH_REGISTRY_REQUEST;
```

### Session Registration

```c
typedef struct _AGENTSH_SESSION_REGISTER {
    AGENTSH_MSG_TYPE Type;          // MSG_REGISTER_SESSION
    ULONG64 SessionToken;           // Unique session identifier
    ULONG RootProcessId;            // Initial session process (children auto-tracked)
    WCHAR WorkspacePath[MAX_PATH_LENGTH]; // Session workspace root
} AGENTSH_SESSION_REGISTER;
```

## Filesystem Mini Filter Implementation

The filesystem component uses standard mini filter callbacks to intercept I/O operations.

### Driver Registration

```c
// agentsh.c

const FLT_OPERATION_REGISTRATION FilterCallbacks[] = {
    { IRP_MJ_CREATE,              0, PreCreate,  PostCreate },
    { IRP_MJ_READ,                0, PreRead,    NULL },
    { IRP_MJ_WRITE,               0, PreWrite,   NULL },
    { IRP_MJ_SET_INFORMATION,     0, PreSetInfo, NULL },  // Delete, Rename
    { IRP_MJ_CLEANUP,             0, NULL,       PostCleanup },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                            // Flags
    NULL,                         // Context registration
    FilterCallbacks,
    FilterUnload,
    InstanceSetup,
    InstanceQueryTeardown,
    NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) return status;

    status = InitializeCommunicationPort();
    if (!NT_SUCCESS(status)) { FltUnregisterFilter(gFilterHandle); return status; }

    status = InitializeProcessTracking();
    if (!NT_SUCCESS(status)) { /* cleanup */ return status; }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) { /* cleanup */ return status; }

    return STATUS_SUCCESS;
}
```

### Pre-Operation Callback

```c
// filesystem.c

FLT_PREOP_CALLBACK_STATUS PreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    ULONG64 sessionToken;
    AGENTSH_FILE_REQUEST request;
    AGENTSH_POLICY_RESPONSE response;

    // Fast path: not a session process?
    if (!IsSessionProcess(PsGetCurrentProcessId(), &sessionToken)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Fast path: check policy cache
    if (CheckPolicyCache(&request, &response)) {
        if (response.Decision == DECISION_DENY) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Slow path: query user-mode
    BuildFileRequest(Data, sessionToken, &request);

    if (QueryPolicy(&request, &response)) {
        UpdatePolicyCache(&request, &response);

        if (response.Decision == DECISION_DENY) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            return FLT_PREOP_COMPLETE;
        }
    }
    // Fail-open on communication failure

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
```

### Key Behaviors

- Session processes checked via PID lookup in tracked process table
- Policy cache checked before IPC (hot path optimization)
- Fail-open if user-mode communication fails
- `STATUS_ACCESS_DENIED` returned for denied operations

## Registry Filter Implementation

Registry filtering uses `CmRegisterCallbackEx` - a separate API from the filesystem mini filter but follows a similar pattern.

### Registry Callback Registration

```c
// registry.c

LARGE_INTEGER gRegistryCookie;

NTSTATUS InitializeRegistryFilter(void) {
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"385210");

    return CmRegisterCallbackEx(
        RegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &gRegistryCookie,
        NULL
    );
}
```

### Registry Callback

```c
NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,        // REG_NOTIFY_CLASS
    PVOID Argument2)        // Operation-specific structure
{
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    ULONG64 sessionToken;

    // Fast path: not a session process?
    if (!IsSessionProcess(PsGetCurrentProcessId(), &sessionToken)) {
        return STATUS_SUCCESS;
    }

    switch (notifyClass) {
        // Pre-operation callbacks (can block)
        case RegNtPreCreateKeyEx:
            return HandlePreCreateKey(Argument2, sessionToken);
        case RegNtPreSetValueKey:
            return HandlePreSetValue(Argument2, sessionToken);
        case RegNtPreDeleteKey:
            return HandlePreDeleteKey(Argument2, sessionToken);
        case RegNtPreDeleteValueKey:
            return HandlePreDeleteValue(Argument2, sessionToken);
        case RegNtPreRenameKey:
            return HandlePreRenameKey(Argument2, sessionToken);

        // Post-operation callbacks (audit only)
        case RegNtPostCreateKeyEx:
        case RegNtPostSetValueKey:
        case RegNtPostDeleteKey:
            EmitRegistryEvent(notifyClass, Argument2, sessionToken);
            break;

        default:
            break;
    }

    return STATUS_SUCCESS;
}
```

### High-Risk Registry Paths

The driver can optionally fast-path check for high-risk paths (from existing `registry.go` definitions):

```c
BOOLEAN IsHighRiskRegistryPath(PCWSTR Path) {
    static const PCWSTR HighRiskPrefixes[] = {
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services",
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        NULL
    };

    for (int i = 0; HighRiskPrefixes[i]; i++) {
        if (wcsnicmp(Path, HighRiskPrefixes[i], wcslen(HighRiskPrefixes[i])) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}
```

## Process Tracking

The driver maintains a table of session processes to quickly identify which operations need policy checks.

### Data Structures

```c
// process.c

typedef struct _SESSION_PROCESS {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONG64 SessionToken;
    LARGE_INTEGER CreateTime;
} SESSION_PROCESS, *PSESSION_PROCESS;

typedef struct _SESSION_INFO {
    LIST_ENTRY ListEntry;
    ULONG64 SessionToken;
    HANDLE RootProcessId;
    UNICODE_STRING WorkspacePath;
    LONG ProcessCount;
} SESSION_INFO, *PSESSION_INFO;

// Hash table for O(1) PID lookup
#define PROCESS_TABLE_SIZE 256
typedef struct _PROCESS_TABLE {
    EX_PUSH_LOCK Lock;
    LIST_ENTRY Buckets[PROCESS_TABLE_SIZE];
    LONG TotalCount;
} PROCESS_TABLE;
```

### Process Creation Callback

```c
VOID ProcessNotifyCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo) {
        // Process creation - check if parent is tracked
        ULONG64 parentSession;

        if (IsSessionProcess(CreateInfo->ParentProcessId, &parentSession)) {
            AddSessionProcess(ProcessId, CreateInfo->ParentProcessId, parentSession);
            QueueProcessEvent(MSG_PROCESS_CREATED, ProcessId, parentSession);
        }
    } else {
        // Process termination
        ULONG64 sessionToken;

        if (RemoveSessionProcess(ProcessId, &sessionToken)) {
            QueueProcessEvent(MSG_PROCESS_TERMINATED, ProcessId, sessionToken);
        }
    }
}
```

### Fast Session Lookup

```c
BOOLEAN IsSessionProcess(HANDLE ProcessId, PULONG64 SessionToken) {
    ULONG bucket = HandleToULong(ProcessId) % PROCESS_TABLE_SIZE;
    PLIST_ENTRY entry;
    PSESSION_PROCESS proc;
    BOOLEAN found = FALSE;

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
```

## Go Driver Client

The Go side connects to the driver's filter port and handles policy queries.

### Driver Client Interface

```go
// internal/platform/windows/driver_client.go

package windows

type DriverClient struct {
    port          windows.Handle
    policyEngine  platform.PolicyEngine
    eventChan     chan<- platform.IOEvent
    sessions      map[uint64]*sessionInfo
    sessionsMu    sync.RWMutex
    stopChan      chan struct{}
    wg            sync.WaitGroup
}

func NewDriverClient(policyEngine platform.PolicyEngine, eventChan chan<- platform.IOEvent) *DriverClient {
    return &DriverClient{
        policyEngine: policyEngine,
        eventChan:    eventChan,
        sessions:     make(map[uint64]*sessionInfo),
        stopChan:     make(chan struct{}),
    }
}
```

### Connection and Message Loop

```go
func (c *DriverClient) Connect() error {
    portName, _ := windows.UTF16PtrFromString("\\AgentshPort")

    var port windows.Handle
    err := filterConnectCommunicationPort(portName, 0, nil, 0, nil, &port)
    if err != nil {
        return fmt.Errorf("failed to connect to driver: %w", err)
    }

    c.port = port
    c.wg.Add(1)
    go c.messageLoop()

    return nil
}

func (c *DriverClient) messageLoop() {
    defer c.wg.Done()

    msgBuf := make([]byte, 4096)

    for {
        select {
        case <-c.stopChan:
            return
        default:
        }

        var bytesReturned uint32
        err := filterGetMessage(c.port, msgBuf, uint32(len(msgBuf)), &bytesReturned)
        if err != nil {
            continue
        }

        reply := c.handleMessage(msgBuf[:bytesReturned])
        if reply != nil {
            filterReplyMessage(c.port, reply, uint32(len(reply)))
        }
    }
}
```

### Policy Query Handling

```go
func (c *DriverClient) handleFileCheck(msg []byte) []byte {
    req := parseFileRequest(msg)

    c.sessionsMu.RLock()
    session, ok := c.sessions[req.SessionToken]
    c.sessionsMu.RUnlock()

    if !ok {
        return buildPolicyResponse(DecisionAllow, 0, "")
    }

    dosPath := ntPathToDosPath(req.Path)
    op := mapFileOperation(req.Operation, req.DesiredAccess)
    decision := c.policyEngine.CheckFile(dosPath, op)

    c.emitFileEvent(session, req, decision)

    cacheTTL := uint32(5000)
    if decision == platform.DecisionDeny {
        cacheTTL = 60000
    }

    return buildPolicyResponse(decision, cacheTTL, "")
}
```

## Policy Cache

The driver maintains an in-kernel cache to avoid IPC for repeated operations.

### Cache Structure

```c
#define CACHE_BUCKET_COUNT 512
#define CACHE_ENTRY_TTL_DEFAULT_MS 5000
#define CACHE_MAX_ENTRIES 10000

typedef struct _CACHE_ENTRY {
    LIST_ENTRY ListEntry;
    LIST_ENTRY LruEntry;
    ULONG64 SessionToken;
    ULONG Operation;
    ULONG Hash;
    AGENTSH_DECISION Decision;
    LARGE_INTEGER ExpiryTime;
    WCHAR Path[MAX_PATH_LENGTH];
} CACHE_ENTRY, *PCACHE_ENTRY;

typedef struct _POLICY_CACHE {
    EX_PUSH_LOCK Lock;
    LIST_ENTRY Buckets[CACHE_BUCKET_COUNT];
    LIST_ENTRY LruHead;
    LONG EntryCount;
    LONG HitCount;
    LONG MissCount;
} POLICY_CACHE;
```

### Cache Operations

- **Lookup**: O(1) hash table lookup with expiry check
- **Insert**: LRU eviction when at capacity
- **Invalidate**: Remove all entries for a session on session end
- **Stats**: Track hit/miss counts for monitoring

## Error Handling and Fail Modes

### Communication Failure Handling

```c
#define POLICY_QUERY_TIMEOUT_MS 5000
#define MAX_CONSECUTIVE_FAILURES 10

static volatile LONG gConsecutiveFailures = 0;
static volatile BOOLEAN gFailOpenMode = FALSE;

BOOLEAN QueryPolicy(PVOID Request, PAGENTSH_POLICY_RESPONSE Response) {
    // If in fail-open mode, allow everything
    if (gFailOpenMode) {
        Response->Decision = DECISION_ALLOW;
        Response->CacheTTLMs = 1000;
        return TRUE;
    }

    // Query with timeout
    status = FltSendMessage(gFilterHandle, &gClientPort, Request, ...);

    if (NT_SUCCESS(status)) {
        InterlockedExchange(&gConsecutiveFailures, 0);
        return TRUE;
    }

    // Enter fail-open after repeated failures
    LONG failures = InterlockedIncrement(&gConsecutiveFailures);
    if (failures >= MAX_CONSECUTIVE_FAILURES && !gFailOpenMode) {
        gFailOpenMode = TRUE;
        LogEvent(AGENTSH_EVENT_FAILOPEN, "Entering fail-open mode");
    }

    Response->Decision = DECISION_ALLOW;
    return FALSE;
}
```

### Recovery

When user-mode reconnects:
1. Exit fail-open mode
2. Reset failure counter
3. Invalidate all caches (stale decisions may be wrong)

### Configurable Fail Mode

```go
type DriverConfig struct {
    FailMode          FailMode      // FailOpen or FailClosed
    QueryTimeoutMs    uint32        // Default 5000
    MaxConsecFailures uint32        // Default 10
}
```

## Directory Structure

```
agentsh/
├── cmd/agentsh/
├── internal/platform/windows/
│   ├── driver_client.go          # Go filter port client
│   ├── driver_client_windows.go  # Windows-specific syscalls
│   ├── driver_stub.go            # Stub for non-Windows builds
│   └── ...
├── drivers/
│   └── windows/
│       └── agentsh-minifilter/
│           ├── agentsh.sln               # Visual Studio solution
│           ├── agentsh.vcxproj           # Project file
│           ├── agentsh.inf               # Driver install manifest
│           ├── src/
│           │   ├── driver.c              # DriverEntry, registration
│           │   ├── filesystem.c          # File system callbacks
│           │   ├── registry.c            # Registry callbacks
│           │   ├── process.c             # Process tracking
│           │   ├── communication.c       # Filter port handling
│           │   ├── cache.c               # Policy cache
│           │   └── util.c                # Helpers
│           ├── inc/
│           │   ├── driver.h              # Internal headers
│           │   └── protocol.h            # Shared with Go
│           ├── test/
│           │   └── driver_test.cpp       # Unit tests
│           └── scripts/
│               ├── build.cmd             # Build script
│               ├── sign-test.cmd         # Test signing
│               ├── install.cmd           # Driver install
│               └── uninstall.cmd         # Driver removal
```

## INF File (Driver Manifest)

```inf
[Version]
Signature   = "$Windows NT$"
Class       = "ActivityMonitor"
ClassGuid   = {b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}
Provider    = %Provider%
DriverVer   = 01/01/2026,1.0.0.0
CatalogFile = agentsh.cat

[DefaultInstall.NTamd64.Services]
AddService = %ServiceName%,,AgentSH.Service

[AgentSH.Service]
DisplayName    = %ServiceName%
Description    = %ServiceDescription%
ServiceBinary  = %12%\agentsh.sys
ServiceType    = 2                      ; SERVICE_FILE_SYSTEM_DRIVER
StartType      = 3                      ; SERVICE_DEMAND_START
ErrorControl   = 1                      ; SERVICE_ERROR_NORMAL
LoadOrderGroup = "FSFilter Activity Monitor"

[AgentSH.AddRegistry]
HKR,"Instances","DefaultInstance",0x00000000,%DefaultInstance%
HKR,"Instances\"%Instance1.Name%,"Altitude",0x00000000,"385200"
HKR,"Instances\"%Instance1.Name%,"Flags",0x00010001,0x0

[Strings]
Provider           = "AgentSH"
ServiceName        = "AgentSH"
ServiceDescription = "AgentSH Security Monitor"
```

## Testing Strategy

### Layer 1: Unit Tests (user-mode)

- Message parsing and serialization
- NT path to DOS path conversion
- Registry path conversion
- Policy response building

### Layer 2: Driver Unit Tests (kernel-mode)

- Cache insert/lookup/eviction
- Process table operations
- Hash function distribution

### Layer 3: Integration Tests (VM-based)

- File interception (allow/deny)
- Registry interception (allow/deny)
- Process tracking (child inheritance)
- Failover behavior

### Layer 4: CI Integration

- GitHub Actions for Go code
- Separate pipeline for driver builds (requires WDK)
- VM-based integration test runs

## Implementation Phases

### Phase 1: Driver Skeleton + Communication

- Driver entry, registration, filter port setup
- Go driver client with FilterConnect
- Basic message passing
- Build system and test signing workflow
- VM-based dev environment setup

### Phase 2: Process Tracking

- PsSetCreateProcessNotifyRoutineEx integration
- Session registration from user-mode
- Process table with PID lookup
- Child process inheritance

### Phase 3: Filesystem Interception

- IRP callbacks for Create/Read/Write/SetInfo
- Policy queries to user-mode
- Policy cache (file operations)
- Event emission to agentsh

### Phase 4: Registry Interception

- CmRegisterCallbackEx integration
- Pre-operation callbacks for writes
- High-risk path detection
- Policy cache (registry operations)
- Event emission with MITRE mappings

### Phase 5: Hardening + Production Readiness

- Comprehensive error handling
- Fail-open/fail-closed modes
- Cache tuning and metrics
- Production signing pipeline (EV cert)
- Documentation and deployment guides

## Security Considerations

1. **Filter port validation**: Driver validates connection is from signed agentsh binary
2. **No secrets in driver**: All policy logic in Go; driver only asks yes/no
3. **Audit logging**: All decisions logged regardless of allow/deny
4. **Fail-open default**: Prevents system lockup if agentsh crashes
5. **Session scoping**: Only session processes are filtered; system processes bypass

## Comparison with Other Platforms

| Feature | Linux | macOS ESF | Windows Mini Filter |
|---------|-------|-----------|---------------------|
| File blocking | FUSE | ESF AUTH | IRP callbacks |
| Registry blocking | N/A | N/A | CmRegisterCallback |
| Process tracking | procfs/eBPF | ESF NOTIFY | PsSetCreateNotify |
| Communication | FUSE ops | XPC + Unix socket | Filter ports |
| Fail mode | Configurable | Configurable | Configurable |

## Future Enhancements

1. **Network filtering**: Integrate with WFP for network policy enforcement
2. **ETW integration**: Emit events to Windows Event Tracing for SIEM integration
3. **ELAM support**: Early Launch Anti-Malware for boot-time protection
4. **Secure boot**: Driver signing for Secure Boot environments

## Changelog

| Date | Change |
|------|--------|
| 2026-01-01 | Initial design document |
