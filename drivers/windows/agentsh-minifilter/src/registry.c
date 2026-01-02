// registry.c - Registry interception implementation
#include "driver.h"
#include "registry.h"
#include "process.h"
#include "cache.h"
#include "config.h"
#include "metrics.h"

// Registry callback cookie
static LARGE_INTEGER gRegistryCookie = {0};

// Fail-open tracking (local state, also reported via metrics)
static volatile LONG gConsecutiveFailures = 0;
static volatile BOOLEAN gFailOpenMode = FALSE;

// Registry operations use offset 100+ in the cache to distinguish from file operations
#define REG_OP_CACHE_OFFSET 100

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
    SIZE_T prefixLen;

    if (KeyPath == NULL) {
        return FALSE;
    }

    for (i = 0; i < HIGH_RISK_PATH_COUNT; i++) {
        prefixLen = wcslen(HighRiskPaths[i]);

        // Handle wildcard for user SID
        if (wcsstr(HighRiskPaths[i], L"\\*\\") != NULL) {
            PCWSTR wildcard = wcsstr(HighRiskPaths[i], L"\\*\\");
            SIZE_T beforeWild = wildcard - HighRiskPaths[i];

            if (_wcsnicmp(KeyPath, HighRiskPaths[i], beforeWild) == 0) {
                PCWSTR afterSid = wcschr(KeyPath + beforeWild + 1, L'\\');
                if (afterSid != NULL) {
                    PCWSTR afterWildcard = wildcard + 3;
                    if (_wcsnicmp(afterSid + 1, afterWildcard, wcslen(afterWildcard)) == 0) {
                        return TRUE;
                    }
                }
            }
        } else {
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

    AgentshMetricsIncrementRegistryPolicyQuery();

    *Decision = DECISION_ALLOW;

    // Check fail mode
    AGENTSH_FAIL_MODE failMode = AgentshGetFailMode();
    if (gFailOpenMode) {
        // In fail-open mode, apply configured policy
        if (failMode == FAIL_MODE_OPEN) {
            AgentshMetricsIncrementAllowDecision();
            return TRUE;
        }
        // In fail-closed mode, deny all
        *Decision = DECISION_DENY;
        AgentshMetricsIncrementDenyDecision();
        return TRUE;
    }

    if (!AgentshData.ClientConnected) {
        return FALSE;
    }

    request.Header.Type = MSG_POLICY_CHECK_REGISTRY;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = InterlockedIncrement(&AgentshData.MessageId);
    request.SessionToken = SessionToken;
    request.ProcessId = ProcessId;
    request.ThreadId = HandleToULong(PsGetCurrentThreadId());
    request.Operation = Operation;
    request.ValueType = ValueType;
    request.DataSize = DataSize;

    pathLen = wcslen(KeyPath);
    if (pathLen >= AGENTSH_MAX_PATH) {
        pathLen = AGENTSH_MAX_PATH - 1;
    }
    RtlCopyMemory(request.KeyPath, KeyPath, pathLen * sizeof(WCHAR));
    request.KeyPath[pathLen] = L'\0';

    if (ValueName != NULL) {
        valueLen = wcslen(ValueName);
        if (valueLen >= AGENTSH_MAX_VALUE_NAME) {
            valueLen = AGENTSH_MAX_VALUE_NAME - 1;
        }
        RtlCopyMemory(request.ValueName, ValueName, valueLen * sizeof(WCHAR));
        request.ValueName[valueLen] = L'\0';
    }

    ULONG timeoutMs = AgentshGetPolicyTimeoutMs();
    timeout.QuadPart = -((LONGLONG)timeoutMs * 10000);

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
        AgentshMetricsSetConsecutiveFailures(0);
        AgentshMetricsSetFailOpenMode(FALSE);

        if (response.Decision == DECISION_ALLOW) {
            AgentshMetricsIncrementAllowDecision();
        } else {
            AgentshMetricsIncrementDenyDecision();
        }

        // Update cache with config TTL
        ULONG ttl = response.CacheTTLMs > 0 ? response.CacheTTLMs : AgentshGetCacheDefaultTTLMs();
        AgentshCacheInsert(
            SessionToken,
            (AGENTSH_FILE_OP)(Operation + REG_OP_CACHE_OFFSET),
            KeyPath,
            response.Decision,
            ttl
            );

        return TRUE;
    }

    // Handle failure
    LONG failures = InterlockedIncrement(&gConsecutiveFailures);
    AgentshMetricsSetConsecutiveFailures(failures);
    AgentshMetricsIncrementPolicyFailure();

    ULONG maxFail = AgentshGetMaxConsecutiveFailures();
    if (failures >= (LONG)maxFail && !gFailOpenMode) {
        gFailOpenMode = TRUE;
        AgentshMetricsSetFailOpenMode(TRUE);
        DbgPrint("AgentSH: Registry entering fail mode after %ld failures\n", failures);
    }

    // Apply fail mode policy (reuse failMode from start of function for consistency)
    if (failMode == FAIL_MODE_CLOSED) {
        *Decision = DECISION_DENY;
        AgentshMetricsIncrementDenyDecision();
    } else {
        AgentshMetricsIncrementAllowDecision();
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
        return STATUS_SUCCESS;
    }

    if (Info->CompleteName != NULL && Info->CompleteName->Length > 0) {
        SIZE_T currentLen = wcslen(keyPath);
        SIZE_T appendLen = Info->CompleteName->Length / sizeof(WCHAR);

        if (currentLen + 1 + appendLen < AGENTSH_MAX_PATH) {
            keyPath[currentLen] = L'\\';
            RtlCopyMemory(&keyPath[currentLen + 1], Info->CompleteName->Buffer, Info->CompleteName->Length);
            keyPath[currentLen + 1 + appendLen] = L'\0';
        }
    }

    if (AgentshIsHighRiskRegistryPath(keyPath)) {
        DbgPrint("AgentSH: High-risk registry create key: %ws\n", keyPath);
    }

    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_CREATE_KEY + REG_OP_CACHE_OFFSET), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

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
        return STATUS_SUCCESS;
    }

    if (AgentshIsHighRiskRegistryPath(keyPath)) {
        DbgPrint("AgentSH: High-risk registry set value: %ws\n", keyPath);
    }

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

    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_SET_VALUE + REG_OP_CACHE_OFFSET), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

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
        return STATUS_SUCCESS;
    }

    if (AgentshIsHighRiskRegistryPath(keyPath)) {
        DbgPrint("AgentSH: High-risk registry delete key: %ws\n", keyPath);
    }

    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_DELETE_KEY + REG_OP_CACHE_OFFSET), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

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
        return STATUS_SUCCESS;
    }

    if (AgentshIsHighRiskRegistryPath(keyPath)) {
        DbgPrint("AgentSH: High-risk registry delete value: %ws\n", keyPath);
    }

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

    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_DELETE_VALUE + REG_OP_CACHE_OFFSET), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

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
        return STATUS_SUCCESS;
    }

    if (AgentshIsHighRiskRegistryPath(keyPath)) {
        DbgPrint("AgentSH: High-risk registry rename key: %ws\n", keyPath);
    }

    if (AgentshCacheLookup(SessionToken, (AGENTSH_FILE_OP)(REG_OP_RENAME_KEY + REG_OP_CACHE_OFFSET), keyPath, &decision)) {
        if (decision == DECISION_DENY) {
            return STATUS_ACCESS_DENIED;
        }
        return STATUS_SUCCESS;
    }

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
        DbgPrint("AgentSH: Registry filter initialized (altitude=%wZ)\n", &altitude);
    } else {
        DbgPrint("AgentSH: Failed to register registry callback: 0x%08X\n", status);
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
            DbgPrint("AgentSH: Registry filter shutdown\n");
        }
        gRegistryCookie.QuadPart = 0;
    }
}
