# Windows Mini Filter Phase 4: Registry Interception

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add registry interception to the Windows mini filter driver so it can query policy for registry operations (create key, set value, delete key/value, rename) and block/allow based on the Go policy engine's response.

**Architecture:** The driver uses CmRegisterCallbackEx to receive registry operation callbacks. When a session process performs a registry operation, the callback queries user-mode for a policy decision. High-risk paths (persistence, security settings) are flagged with MITRE technique IDs. Registry decisions are cached separately from file decisions.

**Tech Stack:** C (WDK), Go, CmRegisterCallbackEx, registry policy cache

---

## Prerequisites

- Phase 3 complete (filesystem interception with policy cache)
- Working in worktree: `/home/eran/work/agentsh/.worktrees/feature-windows-minifilter`

---

## Task 1: Add Registry Operation Protocol Messages

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/inc/protocol.h`

**Step 1: Add registry operation enum and structures**

Add after `AGENTSH_POLICY_RESPONSE` struct:

```c
// Registry operation types
typedef enum _AGENTSH_REGISTRY_OP {
    REG_OP_CREATE_KEY = 1,
    REG_OP_SET_VALUE = 2,
    REG_OP_DELETE_KEY = 3,
    REG_OP_DELETE_VALUE = 4,
    REG_OP_RENAME_KEY = 5,
    REG_OP_QUERY_VALUE = 6
} AGENTSH_REGISTRY_OP;

// Registry value types (subset of REG_* constants)
#define AGENTSH_REG_NONE      0
#define AGENTSH_REG_SZ        1
#define AGENTSH_REG_DWORD     4
#define AGENTSH_REG_BINARY    3
#define AGENTSH_REG_MULTI_SZ  7
#define AGENTSH_REG_QWORD     11

// Maximum value name length
#define AGENTSH_MAX_VALUE_NAME 256

// Registry policy check request (driver -> user-mode)
typedef struct _AGENTSH_REGISTRY_REQUEST {
    AGENTSH_MESSAGE_HEADER Header;
    ULONG64 SessionToken;
    ULONG ProcessId;
    ULONG ThreadId;
    AGENTSH_REGISTRY_OP Operation;
    ULONG ValueType;                // REG_SZ, REG_DWORD, etc.
    ULONG DataSize;                 // Size of value data
    WCHAR KeyPath[AGENTSH_MAX_PATH];
    WCHAR ValueName[AGENTSH_MAX_VALUE_NAME];
} AGENTSH_REGISTRY_REQUEST, *PAGENTSH_REGISTRY_REQUEST;
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/protocol.h
git commit -m "feat(windows): add registry operation protocol messages"
```

---

## Task 2: Create Registry Header

**Files:**
- Create: `drivers/windows/agentsh-minifilter/inc/registry.h`

**Step 1: Write the registry header**

```c
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
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/registry.h
git commit -m "feat(windows): add registry interception header"
```

---

## Task 3: Create Registry Implementation

**Files:**
- Create: `drivers/windows/agentsh-minifilter/src/registry.c`

**Step 1: Write the registry implementation**

```c
// registry.c - Registry interception implementation
#include "driver.h"
#include "registry.h"
#include "process.h"
#include "cache.h"

// Registry callback cookie
static LARGE_INTEGER gRegistryCookie = {0};

// Query timeout (5 seconds)
#define REGISTRY_QUERY_TIMEOUT_MS 5000

// High-risk registry path prefixes (persistence, security, defense evasion)
static const PCWSTR HighRiskPaths[HIGH_RISK_PATH_COUNT] = {
    // Persistence - Run keys (T1547.001)
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    // Persistence - Services (T1543.003)
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services",
    // Persistence - Winlogon (T1547.004)
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    // Defense Evasion - Image File Execution Options (T1546.012)
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    // Defense Evasion - Windows Defender (T1562.001)
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender",
    // Credential Access - LSA (T1003)
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    // Persistence - COM Hijacking (T1546.015)
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Classes\\CLSID",
    // Persistence - Scheduled Tasks
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule"
};

// Check if path is high-risk
BOOLEAN
AgentshIsHighRiskRegistryPath(
    _In_ PCWSTR KeyPath
    )
{
    ULONG i;
    SIZE_T pathLen;
    SIZE_T prefixLen;

    if (KeyPath == NULL) {
        return FALSE;
    }

    for (i = 0; i < HIGH_RISK_PATH_COUNT; i++) {
        prefixLen = wcslen(HighRiskPaths[i]);

        // Handle wildcard for user SID
        if (wcsstr(HighRiskPaths[i], L"\\*\\") != NULL) {
            // Check prefix before wildcard
            PCWSTR wildcard = wcsstr(HighRiskPaths[i], L"\\*\\");
            SIZE_T beforeWild = wildcard - HighRiskPaths[i];

            if (_wcsnicmp(KeyPath, HighRiskPaths[i], beforeWild) == 0) {
                // Find next backslash after the SID
                PCWSTR afterSid = wcschr(KeyPath + beforeWild + 1, L'\\');
                if (afterSid != NULL) {
                    PCWSTR afterWildcard = wildcard + 3; // Skip "\*\"
                    if (_wcsnicmp(afterSid + 1, afterWildcard, wcslen(afterWildcard)) == 0) {
                        return TRUE;
                    }
                }
            }
        } else {
            // Direct prefix match
            if (_wcsnicmp(KeyPath, HighRiskPaths[i], prefixLen) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

// Get registry key path from object
static NTSTATUS
GetRegistryKeyPath(
    _In_ PVOID Object,
    _Out_writes_(PathSize) PWCHAR PathBuffer,
    _In_ ULONG PathSize
    )
{
    NTSTATUS status;
    PCUNICODE_STRING keyName = NULL;

    status = CmCallbackGetKeyObjectIDEx(
        &gRegistryCookie,
        Object,
        NULL,
        &keyName,
        0
        );

    if (!NT_SUCCESS(status) || keyName == NULL) {
        return status;
    }

    if (keyName->Length >= PathSize * sizeof(WCHAR)) {
        CmCallbackReleaseKeyObjectIDEx(keyName);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(PathBuffer, keyName->Buffer, keyName->Length);
    PathBuffer[keyName->Length / sizeof(WCHAR)] = L'\0';

    CmCallbackReleaseKeyObjectIDEx(keyName);
    return STATUS_SUCCESS;
}

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
    )
{
    NTSTATUS status;
    AGENTSH_REGISTRY_REQUEST request = {0};
    AGENTSH_POLICY_RESPONSE response = {0};
    ULONG replyLength = sizeof(response);
    LARGE_INTEGER timeout;
    SIZE_T pathLen;
    SIZE_T valueLen;

    // Default to allow on failure
    *Decision = DECISION_ALLOW;

    // Check if client is connected
    if (!AgentshData.ClientConnected) {
        return FALSE;
    }

    // Build request
    request.Header.Type = MSG_POLICY_CHECK_REGISTRY;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = InterlockedIncrement(&AgentshData.MessageId);
    request.SessionToken = SessionToken;
    request.ProcessId = ProcessId;
    request.ThreadId = HandleToULong(PsGetCurrentThreadId());
    request.Operation = Operation;
    request.ValueType = ValueType;
    request.DataSize = DataSize;

    // Copy key path
    pathLen = wcslen(KeyPath);
    if (pathLen >= AGENTSH_MAX_PATH) {
        pathLen = AGENTSH_MAX_PATH - 1;
    }
    RtlCopyMemory(request.KeyPath, KeyPath, pathLen * sizeof(WCHAR));
    request.KeyPath[pathLen] = L'\0';

    // Copy value name if provided
    if (ValueName != NULL) {
        valueLen = wcslen(ValueName);
        if (valueLen >= AGENTSH_MAX_VALUE_NAME) {
            valueLen = AGENTSH_MAX_VALUE_NAME - 1;
        }
        RtlCopyMemory(request.ValueName, ValueName, valueLen * sizeof(WCHAR));
        request.ValueName[valueLen] = L'\0';
    }

    // Set timeout (negative = relative)
    timeout.QuadPart = -((LONGLONG)REGISTRY_QUERY_TIMEOUT_MS * 10000);

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

        // Update cache
        AgentshCacheInsert(
            SessionToken,
            (AGENTSH_FILE_OP)(Operation + 100),  // Offset to avoid collision with file ops
            KeyPath,
            response.Decision,
            response.CacheTTLMs > 0 ? response.CacheTTLMs : CACHE_DEFAULT_TTL_MS
            );

        return TRUE;
    }

    return FALSE;
}

// Handle pre-create key operation
static NTSTATUS
HandlePreCreateKey(
    _In_ PREG_CREATE_KEY_INFORMATION_V1 Info,
    _In_ ULONG64 SessionToken
    )
{
    WCHAR keyPath[AGENTSH_MAX_PATH];
    AGENTSH_DECISION decision;
    NTSTATUS status;

    status = GetRegistryKeyPath(Info->RootObject, keyPath, AGENTSH_MAX_PATH);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS; // Fail-open
    }

    // Append the relative key name
    if (Info->CompleteName != NULL && Info->CompleteName->Length > 0) {
        SIZE_T currentLen = wcslen(keyPath);
        SIZE_T appendLen = Info->CompleteName->Length / sizeof(WCHAR);

        if (currentLen + 1 + appendLen < AGENTSH_MAX_PATH) {
            keyPath[currentLen] = L'\\';
            RtlCopyMemory(&keyPath[currentLen + 1], Info->CompleteName->Buffer, Info->CompleteName->Length);
            keyPath[currentLen + 1 + appendLen] = L'\0';
        }
    }

    // Check cache first
    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_CREATE_KEY + 100), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

    // Query policy
    if (AgentshQueryRegistryPolicy(
            SessionToken,
            HandleToULong(PsGetCurrentProcessId()),
            REG_OP_CREATE_KEY,
            keyPath,
            NULL,
            0,
            0,
            &decision))
    {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
    }

    return STATUS_SUCCESS;
}

// Handle pre-set value operation
static NTSTATUS
HandlePreSetValue(
    _In_ PREG_SET_VALUE_KEY_INFORMATION Info,
    _In_ ULONG64 SessionToken
    )
{
    WCHAR keyPath[AGENTSH_MAX_PATH];
    WCHAR valueName[AGENTSH_MAX_VALUE_NAME];
    AGENTSH_DECISION decision;
    NTSTATUS status;

    status = GetRegistryKeyPath(Info->Object, keyPath, AGENTSH_MAX_PATH);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS; // Fail-open
    }

    // Extract value name
    if (Info->ValueName != NULL && Info->ValueName->Length > 0) {
        SIZE_T len = Info->ValueName->Length / sizeof(WCHAR);
        if (len >= AGENTSH_MAX_VALUE_NAME) {
            len = AGENTSH_MAX_VALUE_NAME - 1;
        }
        RtlCopyMemory(valueName, Info->ValueName->Buffer, len * sizeof(WCHAR));
        valueName[len] = L'\0';
    } else {
        valueName[0] = L'\0';
    }

    // Check cache first
    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_SET_VALUE + 100), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

    // Query policy
    if (AgentshQueryRegistryPolicy(
            SessionToken,
            HandleToULong(PsGetCurrentProcessId()),
            REG_OP_SET_VALUE,
            keyPath,
            valueName,
            Info->Type,
            Info->DataSize,
            &decision))
    {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
    }

    return STATUS_SUCCESS;
}

// Handle pre-delete key operation
static NTSTATUS
HandlePreDeleteKey(
    _In_ PREG_DELETE_KEY_INFORMATION Info,
    _In_ ULONG64 SessionToken
    )
{
    WCHAR keyPath[AGENTSH_MAX_PATH];
    AGENTSH_DECISION decision;
    NTSTATUS status;

    status = GetRegistryKeyPath(Info->Object, keyPath, AGENTSH_MAX_PATH);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS; // Fail-open
    }

    // Check cache first
    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_DELETE_KEY + 100), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

    // Query policy
    if (AgentshQueryRegistryPolicy(
            SessionToken,
            HandleToULong(PsGetCurrentProcessId()),
            REG_OP_DELETE_KEY,
            keyPath,
            NULL,
            0,
            0,
            &decision))
    {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
    }

    return STATUS_SUCCESS;
}

// Handle pre-delete value operation
static NTSTATUS
HandlePreDeleteValue(
    _In_ PREG_DELETE_VALUE_KEY_INFORMATION Info,
    _In_ ULONG64 SessionToken
    )
{
    WCHAR keyPath[AGENTSH_MAX_PATH];
    WCHAR valueName[AGENTSH_MAX_VALUE_NAME];
    AGENTSH_DECISION decision;
    NTSTATUS status;

    status = GetRegistryKeyPath(Info->Object, keyPath, AGENTSH_MAX_PATH);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS; // Fail-open
    }

    // Extract value name
    if (Info->ValueName != NULL && Info->ValueName->Length > 0) {
        SIZE_T len = Info->ValueName->Length / sizeof(WCHAR);
        if (len >= AGENTSH_MAX_VALUE_NAME) {
            len = AGENTSH_MAX_VALUE_NAME - 1;
        }
        RtlCopyMemory(valueName, Info->ValueName->Buffer, len * sizeof(WCHAR));
        valueName[len] = L'\0';
    } else {
        valueName[0] = L'\0';
    }

    // Check cache first
    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_DELETE_VALUE + 100), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

    // Query policy
    if (AgentshQueryRegistryPolicy(
            SessionToken,
            HandleToULong(PsGetCurrentProcessId()),
            REG_OP_DELETE_VALUE,
            keyPath,
            valueName,
            0,
            0,
            &decision))
    {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
    }

    return STATUS_SUCCESS;
}

// Handle pre-rename key operation
static NTSTATUS
HandlePreRenameKey(
    _In_ PREG_RENAME_KEY_INFORMATION Info,
    _In_ ULONG64 SessionToken
    )
{
    WCHAR keyPath[AGENTSH_MAX_PATH];
    AGENTSH_DECISION decision;
    NTSTATUS status;

    status = GetRegistryKeyPath(Info->Object, keyPath, AGENTSH_MAX_PATH);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS; // Fail-open
    }

    // Check cache first
    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_RENAME_KEY + 100), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

    // Query policy
    if (AgentshQueryRegistryPolicy(
            SessionToken,
            HandleToULong(PsGetCurrentProcessId()),
            REG_OP_RENAME_KEY,
            keyPath,
            NULL,
            0,
            0,
            &decision))
    {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
    }

    return STATUS_SUCCESS;
}

// Main registry callback
static NTSTATUS
RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass;
    ULONG64 sessionToken;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 == NULL || Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    // Fast path: not a session process?
    if (!AgentshIsSessionProcess(PsGetCurrentProcessId(), &sessionToken)) {
        return STATUS_SUCCESS;
    }

    switch (notifyClass) {
        case RegNtPreCreateKeyEx:
            return HandlePreCreateKey((PREG_CREATE_KEY_INFORMATION_V1)Argument2, sessionToken);

        case RegNtPreSetValueKey:
            return HandlePreSetValue((PREG_SET_VALUE_KEY_INFORMATION)Argument2, sessionToken);

        case RegNtPreDeleteKey:
            return HandlePreDeleteKey((PREG_DELETE_KEY_INFORMATION)Argument2, sessionToken);

        case RegNtPreDeleteValueKey:
            return HandlePreDeleteValue((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2, sessionToken);

        case RegNtPreRenameKey:
            return HandlePreRenameKey((PREG_RENAME_KEY_INFORMATION)Argument2, sessionToken);

        default:
            break;
    }

    return STATUS_SUCCESS;
}

// Initialize registry filtering
NTSTATUS
AgentshInitializeRegistryFilter(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    RtlInitUnicodeString(&altitude, AGENTSH_REGISTRY_ALTITUDE);

    status = CmRegisterCallbackEx(
        RegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &gRegistryCookie,
        NULL
        );

    if (NT_SUCCESS(status)) {
        DbgPrint("AgentSH: Registry filter initialized (altitude=%wZ)\\n", &altitude);
    } else {
        DbgPrint("AgentSH: Failed to register registry callback: 0x%08X\\n", status);
    }

    return status;
}

// Shutdown registry filtering
VOID
AgentshShutdownRegistryFilter(
    VOID
    )
{
    NTSTATUS status;

    if (gRegistryCookie.QuadPart != 0) {
        status = CmUnRegisterCallback(gRegistryCookie);
        if (NT_SUCCESS(status)) {
            DbgPrint("AgentSH: Registry filter shutdown\\n");
        }
        gRegistryCookie.QuadPart = 0;
    }
}
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/src/registry.c
git commit -m "feat(windows): implement registry interception with policy queries"
```

---

## Task 4: Update Driver to Use Registry Callbacks

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/inc/driver.h`
- Modify: `drivers/windows/agentsh-minifilter/src/driver.c`

**Step 1: Add include to driver.h**

Add after `#include "filesystem.h"`:

```c
#include "registry.h"
```

**Step 2: Add registry initialization in driver.c DriverEntry**

After `AgentshInitializeCache()` success, add:

```c
    // Initialize registry filter
    status = AgentshInitializeRegistryFilter(DriverObject);
    if (!NT_SUCCESS(status)) {
        AgentshShutdownCache();
        AgentshShutdownProcessTracking();
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }
```

**Step 3: Add registry shutdown in driver.c AgentshFilterUnload**

Before `AgentshShutdownCache()`, add:

```c
    // Shutdown registry filter
    AgentshShutdownRegistryFilter();
```

**Step 4: Update cleanup path for FltStartFiltering failure**

```c
    if (!NT_SUCCESS(status)) {
        AgentshShutdownRegistryFilter();
        AgentshShutdownCache();
        AgentshShutdownProcessTracking();
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }
```

**Step 5: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/driver.h
git add drivers/windows/agentsh-minifilter/src/driver.c
git commit -m "feat(windows): integrate registry callbacks into driver lifecycle"
```

---

## Task 5: Update Visual Studio Project

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/agentsh.vcxproj`

**Step 1: Add new files to project**

In the `<ItemGroup>` containing `.c` files, add:

```xml
    <ClCompile Include="src\registry.c" />
```

In the `<ItemGroup>` containing `.h` files, add:

```xml
    <ClInclude Include="inc\registry.h" />
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/agentsh.vcxproj
git commit -m "build(windows): add registry files to VS project"
```

---

## Task 6: Add Registry Policy Handling to Go Client

**Files:**
- Modify: `internal/platform/windows/driver_client.go`
- Modify: `internal/platform/windows/driver_client_stub.go`

**Step 1: Add registry policy types after FileOperation types**

```go
// RegistryOperation represents the type of registry operation from driver
type RegistryOperation uint32

const (
	RegOpCreateKey   RegistryOperation = 1
	RegOpSetValue    RegistryOperation = 2
	RegOpDeleteKey   RegistryOperation = 3
	RegOpDeleteValue RegistryOperation = 4
	RegOpRenameKey   RegistryOperation = 5
	RegOpQueryValue  RegistryOperation = 6
)

// RegistryRequest represents a registry policy check request from the driver
type RegistryRequest struct {
	SessionToken uint64
	ProcessId    uint32
	ThreadId     uint32
	Operation    RegistryOperation
	ValueType    uint32
	DataSize     uint32
	KeyPath      string
	ValueName    string
}

// RegistryPolicyHandler is called when the driver requests a registry policy decision
type RegistryPolicyHandler func(req *RegistryRequest) (PolicyDecision, uint32)
```

**Step 2: Update DriverClient struct**

Add `registryPolicyHandler RegistryPolicyHandler` field:

```go
type DriverClient struct {
	port                  windows.Handle
	connected             atomic.Bool
	stopChan              chan struct{}
	wg                    sync.WaitGroup
	mu                    sync.Mutex
	msgCounter            atomic.Uint64
	processHandler        ProcessEventHandler
	filePolicyHandler     FilePolicyHandler
	registryPolicyHandler RegistryPolicyHandler
}
```

**Step 3: Add SetRegistryPolicyHandler method**

```go
// SetRegistryPolicyHandler sets the callback for registry policy requests
func (c *DriverClient) SetRegistryPolicyHandler(handler RegistryPolicyHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.registryPolicyHandler = handler
}
```

**Step 4: Handle registry policy requests in handleMessage**

Add case for `MsgPolicyCheckRegistry`:

```go
	case MsgPolicyCheckRegistry:
		return c.handleRegistryPolicyCheck(msg, reply)
```

**Step 5: Add handleRegistryPolicyCheck method**

```go
// handleRegistryPolicyCheck handles registry policy check requests from driver
func (c *DriverClient) handleRegistryPolicyCheck(msg []byte, reply []byte) int {
	// Minimum size: header(16) + token(8) + pid(4) + tid(4) + op(4) + valuetype(4) + datasize(4)
	const minSize = 16 + 8 + 4 + 4 + 4 + 4 + 4
	if len(msg) < minSize {
		return 0
	}

	const maxPath = 520
	const maxValueName = 256

	req := &RegistryRequest{
		SessionToken: binary.LittleEndian.Uint64(msg[16:24]),
		ProcessId:    binary.LittleEndian.Uint32(msg[24:28]),
		ThreadId:     binary.LittleEndian.Uint32(msg[28:32]),
		Operation:    RegistryOperation(binary.LittleEndian.Uint32(msg[32:36])),
		ValueType:    binary.LittleEndian.Uint32(msg[36:40]),
		DataSize:     binary.LittleEndian.Uint32(msg[40:44]),
	}

	// Decode key path (UTF-16LE)
	keyPathStart := 44
	if len(msg) >= keyPathStart+maxPath*2 {
		req.KeyPath = utf16Decode(msg[keyPathStart : keyPathStart+maxPath*2])
	}

	// Decode value name (UTF-16LE)
	valueNameStart := keyPathStart + maxPath*2
	if len(msg) >= valueNameStart+maxValueName*2 {
		req.ValueName = utf16Decode(msg[valueNameStart : valueNameStart+maxValueName*2])
	}

	// Get handler
	c.mu.Lock()
	handler := c.registryPolicyHandler
	c.mu.Unlock()

	// Default to allow
	decision := DecisionAllow
	cacheTTL := uint32(5000)

	if handler != nil {
		decision, cacheTTL = handler(req)
	}

	// Build response: header(16) + decision(4) + cacheTTL(4)
	requestId := binary.LittleEndian.Uint64(msg[8:16])
	binary.LittleEndian.PutUint32(reply[0:4], MsgPolicyCheckRegistry)
	binary.LittleEndian.PutUint32(reply[4:8], 24)
	binary.LittleEndian.PutUint64(reply[8:16], requestId)
	binary.LittleEndian.PutUint32(reply[16:20], uint32(decision))
	binary.LittleEndian.PutUint32(reply[20:24], cacheTTL)

	return 24
}
```

**Step 6: Add stubs to driver_client_stub.go**

```go
// RegistryOperation represents the type of registry operation from driver
type RegistryOperation uint32

const (
	RegOpCreateKey   RegistryOperation = 1
	RegOpSetValue    RegistryOperation = 2
	RegOpDeleteKey   RegistryOperation = 3
	RegOpDeleteValue RegistryOperation = 4
	RegOpRenameKey   RegistryOperation = 5
	RegOpQueryValue  RegistryOperation = 6
)

// RegistryRequest represents a registry policy check request from the driver
type RegistryRequest struct {
	SessionToken uint64
	ProcessId    uint32
	ThreadId     uint32
	Operation    RegistryOperation
	ValueType    uint32
	DataSize     uint32
	KeyPath      string
	ValueName    string
}

// RegistryPolicyHandler stub type
type RegistryPolicyHandler func(req *RegistryRequest) (PolicyDecision, uint32)

// SetRegistryPolicyHandler stub for non-Windows
func (c *DriverClient) SetRegistryPolicyHandler(handler RegistryPolicyHandler) {
	// No-op on non-Windows
}
```

**Step 7: Commit**

```bash
git add internal/platform/windows/driver_client.go
git add internal/platform/windows/driver_client_stub.go
git commit -m "feat(windows): add registry policy handling to Go driver client"
```

---

## Task 7: Add Unit Tests for Registry Policy

**Files:**
- Modify: `internal/platform/windows/driver_client_test.go`

**Step 1: Add registry policy tests**

```go
func TestRegistryRequestDecoding(t *testing.T) {
	// Build a mock registry request message
	const maxPath = 520
	const maxValueName = 256
	msgSize := 16 + 8 + 4 + 4 + 4 + 4 + 4 + (maxPath * 2) + (maxValueName * 2)
	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgPolicyCheckRegistry)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], 54321) // Request ID

	// Request fields
	binary.LittleEndian.PutUint64(msg[16:24], 0xDEADBEEF) // Session token
	binary.LittleEndian.PutUint32(msg[24:28], 1234)       // Process ID
	binary.LittleEndian.PutUint32(msg[28:32], 5678)       // Thread ID
	binary.LittleEndian.PutUint32(msg[32:36], uint32(RegOpSetValue))
	binary.LittleEndian.PutUint32(msg[36:40], 1)    // REG_SZ
	binary.LittleEndian.PutUint32(msg[40:44], 100)  // Data size

	// Key path in UTF-16LE
	keyPath := "\\REGISTRY\\MACHINE\\SOFTWARE\\Test"
	keyPathBytes := utf16Encode(keyPath)
	copy(msg[44:], keyPathBytes)

	// Value name in UTF-16LE
	valueName := "TestValue"
	valueNameBytes := utf16Encode(valueName)
	copy(msg[44+maxPath*2:], valueNameBytes)

	// Decode and verify
	sessionToken := binary.LittleEndian.Uint64(msg[16:24])
	processId := binary.LittleEndian.Uint32(msg[24:28])
	operation := RegistryOperation(binary.LittleEndian.Uint32(msg[32:36]))
	decodedPath := utf16Decode(msg[44 : 44+maxPath*2])
	decodedValue := utf16Decode(msg[44+maxPath*2 : 44+maxPath*2+maxValueName*2])

	if sessionToken != 0xDEADBEEF {
		t.Errorf("expected session token 0xDEADBEEF, got 0x%X", sessionToken)
	}
	if processId != 1234 {
		t.Errorf("expected process ID 1234, got %d", processId)
	}
	if operation != RegOpSetValue {
		t.Errorf("expected RegOpSetValue, got %d", operation)
	}
	if decodedPath != keyPath {
		t.Errorf("expected key path %q, got %q", keyPath, decodedPath)
	}
	if decodedValue != valueName {
		t.Errorf("expected value name %q, got %q", valueName, decodedValue)
	}
}

func TestRegistryOperationConstants(t *testing.T) {
	// Verify constants match protocol.h
	tests := []struct {
		name     string
		got      RegistryOperation
		expected RegistryOperation
	}{
		{"RegOpCreateKey", RegOpCreateKey, 1},
		{"RegOpSetValue", RegOpSetValue, 2},
		{"RegOpDeleteKey", RegOpDeleteKey, 3},
		{"RegOpDeleteValue", RegOpDeleteValue, 4},
		{"RegOpRenameKey", RegOpRenameKey, 5},
		{"RegOpQueryValue", RegOpQueryValue, 6},
	}

	for _, tc := range tests {
		if tc.got != tc.expected {
			t.Errorf("%s: expected %d, got %d", tc.name, tc.expected, tc.got)
		}
	}
}

func TestRegistryPolicyResponse(t *testing.T) {
	reply := make([]byte, 24)

	// Build response
	binary.LittleEndian.PutUint32(reply[0:4], MsgPolicyCheckRegistry)
	binary.LittleEndian.PutUint32(reply[4:8], 24)
	binary.LittleEndian.PutUint64(reply[8:16], 54321) // Request ID
	binary.LittleEndian.PutUint32(reply[16:20], uint32(DecisionDeny))
	binary.LittleEndian.PutUint32(reply[20:24], 30000) // Cache TTL

	// Decode and verify
	decision := PolicyDecision(binary.LittleEndian.Uint32(reply[16:20]))
	cacheTTL := binary.LittleEndian.Uint32(reply[20:24])

	if decision != DecisionDeny {
		t.Errorf("expected DecisionDeny, got %d", decision)
	}
	if cacheTTL != 30000 {
		t.Errorf("expected cache TTL 30000, got %d", cacheTTL)
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
git commit -m "test(windows): add unit tests for registry policy handling"
```

---

## Task 8: Final Verification

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

Expected: registry.c, registry.h present

**Step 3: Review commits**

```bash
git log --oneline -10
```

---

## Phase 4 Complete Checklist

- [ ] Registry operation protocol messages added to protocol.h
- [ ] Registry header (registry.h) created
- [ ] Registry implementation (registry.c) with CmRegisterCallbackEx
- [ ] High-risk registry path detection implemented
- [ ] Driver updated with registry filter lifecycle
- [ ] Visual Studio project updated with new files
- [ ] Go client registry policy handling
- [ ] Unit tests for registry request/response encoding
- [ ] All tests pass

## Next Steps (Phase 5)

After Phase 4 is complete and tested in a Windows VM:
1. Add comprehensive error handling and fail-open/fail-closed modes
2. Add cache tuning and metrics collection
3. Add ETW event logging for SIEM integration
4. Production signing pipeline documentation
