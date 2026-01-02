// driver.c - Main driver entry point
#include "driver.h"

// Global data
AGENTSH_GLOBAL_DATA AgentshData = {0};

// Filter callbacks
CONST FLT_OPERATION_REGISTRATION FilterCallbacks[] = {
    { IRP_MJ_CREATE, 0, AgentshPreCreate, NULL },
    { IRP_MJ_WRITE, 0, AgentshPreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, AgentshPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

// Filter registration
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    NULL,                               // Context registration
    FilterCallbacks,                    // Operation callbacks
    AgentshFilterUnload,                // FilterUnload
    AgentshInstanceSetup,               // InstanceSetup
    AgentshInstanceQueryTeardown,       // InstanceQueryTeardown
    NULL,                               // InstanceTeardownStart
    NULL,                               // InstanceTeardownComplete
    NULL,                               // GenerateFileName
    NULL,                               // NormalizeNameComponent
    NULL                                // NormalizeContextCleanup
};

// Instance setup - attach to all NTFS volumes
NTSTATUS
AgentshInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    // Only attach to NTFS
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

// Instance query teardown - allow detach
NTSTATUS
AgentshInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}

// Filter unload
NTSTATUS
AgentshFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    // Shutdown registry filter
    AgentshShutdownRegistryFilter();

    // Shutdown policy cache
    AgentshShutdownCache();

    // Shutdown process tracking
    AgentshShutdownProcessTracking();

    // Shutdown communication
    AgentshShutdownCommunication();

    // Unregister filter
    if (AgentshData.FilterHandle != NULL) {
        FltUnregisterFilter(AgentshData.FilterHandle);
        AgentshData.FilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

// Driver entry point
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    // Initialize global data
    RtlZeroMemory(&AgentshData, sizeof(AgentshData));

    // Register with filter manager
    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &AgentshData.FilterHandle
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Initialize communication port
    status = AgentshInitializeCommunication(AgentshData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }

    // Initialize process tracking
    status = AgentshInitializeProcessTracking();
    if (!NT_SUCCESS(status)) {
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }

    // Initialize policy cache
    status = AgentshInitializeCache();
    if (!NT_SUCCESS(status)) {
        AgentshShutdownProcessTracking();
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }

    // Initialize registry filter
    status = AgentshInitializeRegistryFilter(DriverObject);
    if (!NT_SUCCESS(status)) {
        AgentshShutdownCache();
        AgentshShutdownProcessTracking();
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }

    // Start filtering
    status = FltStartFiltering(AgentshData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        AgentshShutdownRegistryFilter();
        AgentshShutdownCache();
        AgentshShutdownProcessTracking();
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }

    return STATUS_SUCCESS;
}
