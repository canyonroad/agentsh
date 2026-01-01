# Windows Mini Filter Phase 1: Driver Skeleton + Communication

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a minimal Windows kernel mini filter driver that can communicate with a Go user-mode client via filter ports.

**Architecture:** A kernel-mode mini filter driver (C, WDK) registers with the filter manager and creates a communication port. A Go client connects to the port and exchanges ping/pong messages. This establishes the foundation for policy queries in later phases.

**Tech Stack:** C (WDK), Go, Windows Filter Manager API, FilterConnectCommunicationPort

---

## Prerequisites

Before starting, ensure you have:
- Windows 10/11 VM with test signing enabled (`bcdedit /set testsigning on`)
- Visual Studio 2022 with C++ desktop development
- Windows Driver Kit (WDK) 10 installed
- Go 1.21+ installed in the VM

---

## Task 1: Create Driver Directory Structure

**Files:**
- Create: `drivers/windows/agentsh-minifilter/`
- Create: `drivers/windows/agentsh-minifilter/src/`
- Create: `drivers/windows/agentsh-minifilter/inc/`
- Create: `drivers/windows/agentsh-minifilter/scripts/`

**Step 1: Create directory structure**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-windows-minifilter
mkdir -p drivers/windows/agentsh-minifilter/src
mkdir -p drivers/windows/agentsh-minifilter/inc
mkdir -p drivers/windows/agentsh-minifilter/scripts
```

**Step 2: Commit**

```bash
git add drivers/
git commit -m "feat(windows): create mini filter driver directory structure"
```

---

## Task 2: Create Shared Protocol Header

**Files:**
- Create: `drivers/windows/agentsh-minifilter/inc/protocol.h`

**Step 1: Write the protocol header**

```c
// protocol.h - Communication protocol between driver and user-mode
#ifndef _AGENTSH_PROTOCOL_H_
#define _AGENTSH_PROTOCOL_H_

#define AGENTSH_PORT_NAME L"\\AgentshPort"
#define AGENTSH_MAX_PATH 520

// Message types
typedef enum _AGENTSH_MSG_TYPE {
    // Driver -> User-mode (requests)
    MSG_PING = 0,
    MSG_POLICY_CHECK_FILE = 1,
    MSG_POLICY_CHECK_REGISTRY = 2,
    MSG_PROCESS_CREATED = 3,
    MSG_PROCESS_TERMINATED = 4,

    // User-mode -> Driver (commands)
    MSG_PONG = 50,
    MSG_REGISTER_SESSION = 100,
    MSG_UNREGISTER_SESSION = 101,
    MSG_UPDATE_CACHE = 102,
    MSG_SHUTDOWN = 103,
} AGENTSH_MSG_TYPE;

// Policy decisions
typedef enum _AGENTSH_DECISION {
    DECISION_ALLOW = 0,
    DECISION_DENY = 1,
    DECISION_PENDING = 2,
} AGENTSH_DECISION;

// Message header (all messages start with this)
typedef struct _AGENTSH_MESSAGE_HEADER {
    AGENTSH_MSG_TYPE Type;
    ULONG Size;
    ULONG64 RequestId;
} AGENTSH_MESSAGE_HEADER, *PAGENTSH_MESSAGE_HEADER;

// Ping message (driver -> user-mode)
typedef struct _AGENTSH_PING {
    AGENTSH_MESSAGE_HEADER Header;
    ULONG DriverVersion;
    ULONG64 Timestamp;
} AGENTSH_PING, *PAGENTSH_PING;

// Pong response (user-mode -> driver)
typedef struct _AGENTSH_PONG {
    AGENTSH_MESSAGE_HEADER Header;
    ULONG ClientVersion;
    ULONG64 Timestamp;
} AGENTSH_PONG, *PAGENTSH_PONG;

// Connection context passed during FilterConnectCommunicationPort
typedef struct _AGENTSH_CONNECTION_CONTEXT {
    ULONG ClientVersion;
    ULONG ClientPid;
} AGENTSH_CONNECTION_CONTEXT, *PAGENTSH_CONNECTION_CONTEXT;

#endif // _AGENTSH_PROTOCOL_H_
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/protocol.h
git commit -m "feat(windows): add filter port communication protocol header"
```

---

## Task 3: Create Main Driver Entry

**Files:**
- Create: `drivers/windows/agentsh-minifilter/src/driver.c`
- Create: `drivers/windows/agentsh-minifilter/inc/driver.h`

**Step 1: Write the driver header**

```c
// driver.h - Main driver definitions
#ifndef _AGENTSH_DRIVER_H_
#define _AGENTSH_DRIVER_H_

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "protocol.h"

// Driver version
#define AGENTSH_DRIVER_VERSION 0x00010000  // 1.0.0.0

// Pool tags
#define AGENTSH_TAG_GENERAL 'hsGA'
#define AGENTSH_TAG_MESSAGE 'smGA'

// Global driver data
typedef struct _AGENTSH_GLOBAL_DATA {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    BOOLEAN ClientConnected;
    ULONG ClientPid;
    LONG MessageId;
} AGENTSH_GLOBAL_DATA, *PAGENTSH_GLOBAL_DATA;

extern AGENTSH_GLOBAL_DATA AgentshData;

// Communication functions (communication.c)
NTSTATUS
AgentshInitializeCommunication(
    _In_ PFLT_FILTER Filter
    );

VOID
AgentshShutdownCommunication(
    VOID
    );

NTSTATUS
AgentshSendPing(
    VOID
    );

// Filter callbacks
FLT_PREOP_CALLBACK_STATUS
AgentshPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

NTSTATUS
AgentshInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

NTSTATUS
AgentshInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

NTSTATUS
AgentshFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

#endif // _AGENTSH_DRIVER_H_
```

**Step 2: Write the driver entry**

```c
// driver.c - Main driver entry point
#include "driver.h"

// Global data
AGENTSH_GLOBAL_DATA AgentshData = {0};

// Filter callbacks - minimal for Phase 1
CONST FLT_OPERATION_REGISTRATION FilterCallbacks[] = {
    { IRP_MJ_CREATE, 0, AgentshPreCreate, NULL },
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

// Minimal pre-create callback (just pass through for Phase 1)
FLT_PREOP_CALLBACK_STATUS
AgentshPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Phase 1: Just pass through everything
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

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

    // Start filtering
    status = FltStartFiltering(AgentshData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        AgentshShutdownCommunication();
        FltUnregisterFilter(AgentshData.FilterHandle);
        return status;
    }

    return STATUS_SUCCESS;
}
```

**Step 3: Commit**

```bash
git add drivers/windows/agentsh-minifilter/inc/driver.h
git add drivers/windows/agentsh-minifilter/src/driver.c
git commit -m "feat(windows): add mini filter driver entry and registration"
```

---

## Task 4: Create Communication Port Handler

**Files:**
- Create: `drivers/windows/agentsh-minifilter/src/communication.c`

**Step 1: Write the communication handler**

```c
// communication.c - Filter port communication
#include "driver.h"

// Forward declarations
NTSTATUS
AgentshConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    );

VOID
AgentshDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
AgentshMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

// Initialize communication port
NTSTATUS
AgentshInitializeCommunication(
    _In_ PFLT_FILTER Filter
    )
{
    NTSTATUS status;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;

    // Create security descriptor allowing all access
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, AGENTSH_PORT_NAME);

    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sd
        );

    // Create communication port
    status = FltCreateCommunicationPort(
        Filter,
        &AgentshData.ServerPort,
        &oa,
        NULL,                       // ServerPortCookie
        AgentshConnectNotify,
        AgentshDisconnectNotify,
        AgentshMessageNotify,
        1                           // MaxConnections
        );

    FltFreeSecurityDescriptor(sd);

    return status;
}

// Shutdown communication
VOID
AgentshShutdownCommunication(
    VOID
    )
{
    if (AgentshData.ServerPort != NULL) {
        FltCloseCommunicationPort(AgentshData.ServerPort);
        AgentshData.ServerPort = NULL;
    }
}

// Client connect notification
NTSTATUS
AgentshConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    PAGENTSH_CONNECTION_CONTEXT ctx;

    UNREFERENCED_PARAMETER(ServerPortCookie);

    // Validate connection context
    if (ConnectionContext == NULL ||
        SizeOfContext < sizeof(AGENTSH_CONNECTION_CONTEXT)) {
        return STATUS_INVALID_PARAMETER;
    }

    ctx = (PAGENTSH_CONNECTION_CONTEXT)ConnectionContext;

    // Store client info
    AgentshData.ClientPort = ClientPort;
    AgentshData.ClientPid = ctx->ClientPid;
    AgentshData.ClientConnected = TRUE;

    *ConnectionPortCookie = NULL;

    DbgPrint("AgentSH: Client connected (PID: %u, Version: 0x%08X)\n",
             ctx->ClientPid, ctx->ClientVersion);

    return STATUS_SUCCESS;
}

// Client disconnect notification
VOID
AgentshDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    DbgPrint("AgentSH: Client disconnected\n");

    // Clear client state
    FltCloseClientPort(AgentshData.FilterHandle, &AgentshData.ClientPort);
    AgentshData.ClientPort = NULL;
    AgentshData.ClientPid = 0;
    AgentshData.ClientConnected = FALSE;
}

// Message notification from user-mode
NTSTATUS
AgentshMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    PAGENTSH_MESSAGE_HEADER header;

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(AGENTSH_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    header = (PAGENTSH_MESSAGE_HEADER)InputBuffer;

    switch (header->Type) {
        case MSG_PONG:
            DbgPrint("AgentSH: Received PONG from client\n");
            break;

        case MSG_REGISTER_SESSION:
            DbgPrint("AgentSH: Session registration (Phase 2)\n");
            break;

        case MSG_UNREGISTER_SESSION:
            DbgPrint("AgentSH: Session unregistration (Phase 2)\n");
            break;

        default:
            DbgPrint("AgentSH: Unknown message type: %d\n", header->Type);
            break;
    }

    return STATUS_SUCCESS;
}

// Send ping to user-mode client
NTSTATUS
AgentshSendPing(
    VOID
    )
{
    NTSTATUS status;
    AGENTSH_PING ping = {0};
    AGENTSH_PONG pong = {0};
    ULONG replyLength = sizeof(pong);
    LARGE_INTEGER timeout;

    if (!AgentshData.ClientConnected || AgentshData.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    // Build ping message
    ping.Header.Type = MSG_PING;
    ping.Header.Size = sizeof(ping);
    ping.Header.RequestId = InterlockedIncrement(&AgentshData.MessageId);
    ping.DriverVersion = AGENTSH_DRIVER_VERSION;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&ping.Timestamp);

    // 5 second timeout
    timeout.QuadPart = -50000000LL;  // 100ns units, negative = relative

    status = FltSendMessage(
        AgentshData.FilterHandle,
        &AgentshData.ClientPort,
        &ping,
        sizeof(ping),
        &pong,
        &replyLength,
        &timeout
        );

    if (NT_SUCCESS(status)) {
        DbgPrint("AgentSH: Ping successful, client version: 0x%08X\n",
                 pong.ClientVersion);
    }

    return status;
}
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/src/communication.c
git commit -m "feat(windows): add filter port communication handling"
```

---

## Task 5: Create Visual Studio Project Files

**Files:**
- Create: `drivers/windows/agentsh-minifilter/agentsh.vcxproj`
- Create: `drivers/windows/agentsh-minifilter/agentsh.sln`

**Step 1: Write the vcxproj file**

```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="12.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Debug|x64">
      <Configuration>Debug</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid>{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</ProjectGuid>
    <TemplateGuid>{1bc93793-694f-48fe-9372-81e2b05556fd}</TemplateGuid>
    <TargetFrameworkVersion>v4.5</TargetFrameworkVersion>
    <MinimumVisualStudioVersion>12.0</MinimumVisualStudioVersion>
    <Configuration>Debug</Configuration>
    <Platform Condition="'$(Platform)' == ''">x64</Platform>
    <RootNamespace>agentsh</RootNamespace>
    <DriverType>KMDF</DriverType>
    <DriverTargetPlatform>Universal</DriverTargetPlatform>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'" Label="Configuration">
    <TargetVersion>Windows10</TargetVersion>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
    <ConfigurationType>Driver</ConfigurationType>
    <DriverType>WDM</DriverType>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <TargetVersion>Windows10</TargetVersion>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
    <ConfigurationType>Driver</ConfigurationType>
    <DriverType>WDM</DriverType>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings">
  </ImportGroup>
  <ImportGroup Label="PropertySheets">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup>
    <OutDir>$(SolutionDir)bin\$(Platform)\$(Configuration)\</OutDir>
    <IntDir>$(SolutionDir)obj\$(Platform)\$(Configuration)\</IntDir>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <ClCompile>
      <AdditionalIncludeDirectories>$(ProjectDir)inc;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <PreprocessorDefinitions>_DEBUG;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <WppEnabled>false</WppEnabled>
    </ClCompile>
    <Link>
      <AdditionalDependencies>$(DDK_LIB_PATH)\fltMgr.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <AdditionalIncludeDirectories>$(ProjectDir)inc;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <PreprocessorDefinitions>NDEBUG;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <WppEnabled>false</WppEnabled>
    </ClCompile>
    <Link>
      <AdditionalDependencies>$(DDK_LIB_PATH)\fltMgr.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="src\driver.c" />
    <ClCompile Include="src\communication.c" />
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="inc\driver.h" />
    <ClInclude Include="inc\protocol.h" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets">
  </ImportGroup>
</Project>
```

**Step 2: Write the solution file**

```
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "agentsh", "agentsh.vcxproj", "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|x64 = Debug|x64
		Release|x64 = Release|x64
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}.Debug|x64.ActiveCfg = Debug|x64
		{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}.Debug|x64.Build.0 = Debug|x64
		{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}.Release|x64.ActiveCfg = Release|x64
		{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}.Release|x64.Build.0 = Release|x64
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
EndGlobal
```

**Step 3: Commit**

```bash
git add drivers/windows/agentsh-minifilter/agentsh.vcxproj
git add drivers/windows/agentsh-minifilter/agentsh.sln
git commit -m "feat(windows): add Visual Studio project files for driver build"
```

---

## Task 6: Create Driver INF File

**Files:**
- Create: `drivers/windows/agentsh-minifilter/agentsh.inf`

**Step 1: Write the INF file**

```inf
;
; agentsh.inf - AgentSH Mini Filter Driver
;

[Version]
Signature   = "$Windows NT$"
Class       = "ActivityMonitor"
ClassGuid   = {b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}
Provider    = %Provider%
DriverVer   = 01/01/2026,1.0.0.0
CatalogFile = agentsh.cat
PnpLockdown = 1

[SourceDisksNames]
1 = %DiskName%

[SourceDisksFiles]
agentsh.sys = 1

[DestinationDirs]
DefaultDestDir      = 12
AgentSH.DriverFiles = 12

[DefaultInstall.NTamd64]
OptionDesc = %ServiceDescription%
CopyFiles  = AgentSH.DriverFiles

[DefaultInstall.NTamd64.Services]
AddService = %ServiceName%,,AgentSH.Service

[DefaultUninstall.NTamd64]
LegacyUninstall = 1
DelFiles        = AgentSH.DriverFiles

[DefaultUninstall.NTamd64.Services]
DelService = %ServiceName%,0x200

[AgentSH.Service]
DisplayName      = %ServiceName%
Description      = %ServiceDescription%
ServiceBinary    = %12%\agentsh.sys
Dependencies     = FltMgr
ServiceType      = 2    ; SERVICE_FILE_SYSTEM_DRIVER
StartType        = 3    ; SERVICE_DEMAND_START
ErrorControl     = 1    ; SERVICE_ERROR_NORMAL
LoadOrderGroup   = "FSFilter Activity Monitor"
AddReg           = AgentSH.AddRegistry

[AgentSH.AddRegistry]
HKR,"Instances","DefaultInstance",0x00000000,%DefaultInstance%
HKR,"Instances\"%Instance.Name%,"Altitude",0x00000000,%Instance.Altitude%
HKR,"Instances\"%Instance.Name%,"Flags",0x00010001,%Instance.Flags%

[AgentSH.DriverFiles]
agentsh.sys

[Strings]
Provider           = "AgentSH"
ServiceName        = "AgentSH"
ServiceDescription = "AgentSH Security Monitor Mini-Filter"
DiskName           = "AgentSH Installation Disk"
DefaultInstance    = "AgentSH Instance"
Instance.Name      = "AgentSH Instance"
Instance.Altitude  = "385200"
Instance.Flags     = 0x0
```

**Step 2: Commit**

```bash
git add drivers/windows/agentsh-minifilter/agentsh.inf
git commit -m "feat(windows): add driver INF installation manifest"
```

---

## Task 7: Create Build Scripts

**Files:**
- Create: `drivers/windows/agentsh-minifilter/scripts/build.cmd`
- Create: `drivers/windows/agentsh-minifilter/scripts/install.cmd`
- Create: `drivers/windows/agentsh-minifilter/scripts/uninstall.cmd`

**Step 1: Write build.cmd**

```batch
@echo off
REM build.cmd - Build the AgentSH mini filter driver

setlocal

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Debug

set PLATFORM=%2
if "%PLATFORM%"=="" set PLATFORM=x64

echo ========================================
echo Building AgentSH Driver (%CONFIG%/%PLATFORM%)
echo ========================================

pushd %~dp0..

REM Find MSBuild
set MSBUILD=
for %%i in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
) do (
    if exist %%i (
        set MSBUILD=%%i
        goto :found
    )
)

echo ERROR: MSBuild not found. Install Visual Studio with C++ and WDK.
exit /b 1

:found
echo Using MSBuild: %MSBUILD%

%MSBUILD% agentsh.sln /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /t:Build /v:minimal

if errorlevel 1 (
    echo Build FAILED
    popd
    exit /b 1
)

echo ========================================
echo Build successful: bin\%PLATFORM%\%CONFIG%\agentsh.sys
echo ========================================

popd
exit /b 0
```

**Step 2: Write install.cmd**

```batch
@echo off
REM install.cmd - Install the AgentSH driver (requires admin)

setlocal

set DRIVER_PATH=%1
if "%DRIVER_PATH%"=="" set DRIVER_PATH=%~dp0..\bin\x64\Debug\agentsh.sys

if not exist "%DRIVER_PATH%" (
    echo ERROR: Driver not found at %DRIVER_PATH%
    echo Build the driver first with: scripts\build.cmd
    exit /b 1
)

echo ========================================
echo Installing AgentSH Driver
echo ========================================

REM Check admin privileges
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This script requires administrator privileges.
    echo Right-click and select "Run as administrator".
    exit /b 1
)

REM Copy driver to System32\drivers
copy /y "%DRIVER_PATH%" "%SystemRoot%\System32\drivers\agentsh.sys"
if errorlevel 1 (
    echo ERROR: Failed to copy driver
    exit /b 1
)

REM Install using INF
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 %~dp0..\agentsh.inf
if errorlevel 1 (
    echo ERROR: INF installation failed
    exit /b 1
)

REM Load the driver
fltmc load agentsh
if errorlevel 1 (
    echo WARNING: Driver load failed (may already be loaded or need reboot)
)

echo ========================================
echo Driver installed successfully
echo Use 'fltmc' to verify filter is loaded
echo ========================================

exit /b 0
```

**Step 3: Write uninstall.cmd**

```batch
@echo off
REM uninstall.cmd - Uninstall the AgentSH driver (requires admin)

setlocal

echo ========================================
echo Uninstalling AgentSH Driver
echo ========================================

REM Check admin privileges
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This script requires administrator privileges.
    echo Right-click and select "Run as administrator".
    exit /b 1
)

REM Unload the driver
fltmc unload agentsh 2>nul

REM Uninstall using INF
rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 %~dp0..\agentsh.inf

REM Delete driver file
del /f "%SystemRoot%\System32\drivers\agentsh.sys" 2>nul

echo ========================================
echo Driver uninstalled successfully
echo ========================================

exit /b 0
```

**Step 4: Commit**

```bash
git add drivers/windows/agentsh-minifilter/scripts/
git commit -m "feat(windows): add driver build and install scripts"
```

---

## Task 8: Create Go Driver Client Stub

**Files:**
- Create: `internal/platform/windows/driver_client.go`
- Create: `internal/platform/windows/driver_client_stub.go`

**Step 1: Write the driver client interface (cross-platform safe)**

```go
// internal/platform/windows/driver_client.go
//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Message types (must match protocol.h)
const (
	MsgPing              = 0
	MsgPolicyCheckFile   = 1
	MsgPolicyCheckRegistry = 2
	MsgProcessCreated    = 3
	MsgProcessTerminated = 4
	MsgPong              = 50
	MsgRegisterSession   = 100
	MsgUnregisterSession = 101
)

// Driver client version
const DriverClientVersion = 0x00010000

// DriverClient communicates with the agentsh.sys mini filter
type DriverClient struct {
	port       windows.Handle
	connected  atomic.Bool
	stopChan   chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex
	msgCounter atomic.Uint64
}

// NewDriverClient creates a new driver client
func NewDriverClient() *DriverClient {
	return &DriverClient{
		stopChan: make(chan struct{}),
	}
}

// Connect establishes connection to the mini filter driver
func (c *DriverClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected.Load() {
		return fmt.Errorf("already connected")
	}

	portName, err := windows.UTF16PtrFromString(`\AgentshPort`)
	if err != nil {
		return fmt.Errorf("invalid port name: %w", err)
	}

	// Connection context
	ctx := struct {
		ClientVersion uint32
		ClientPid     uint32
	}{
		ClientVersion: DriverClientVersion,
		ClientPid:     uint32(windows.GetCurrentProcessId()),
	}

	var port windows.Handle
	err = filterConnectCommunicationPort(
		portName,
		0,
		unsafe.Pointer(&ctx),
		uint16(unsafe.Sizeof(ctx)),
		nil,
		&port,
	)
	if err != nil {
		return fmt.Errorf("failed to connect to driver: %w", err)
	}

	c.port = port
	c.connected.Store(true)

	// Start message loop
	c.wg.Add(1)
	go c.messageLoop()

	return nil
}

// Disconnect closes the connection to the driver
func (c *DriverClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected.Load() {
		return nil
	}

	close(c.stopChan)
	c.wg.Wait()

	if c.port != 0 {
		windows.CloseHandle(c.port)
		c.port = 0
	}

	c.connected.Store(false)
	c.stopChan = make(chan struct{})

	return nil
}

// Connected returns whether the client is connected
func (c *DriverClient) Connected() bool {
	return c.connected.Load()
}

// messageLoop handles incoming messages from the driver
func (c *DriverClient) messageLoop() {
	defer c.wg.Done()

	msgBuf := make([]byte, 4096)
	replyBuf := make([]byte, 512)

	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		// Get message from driver with timeout
		var bytesReturned uint32
		err := filterGetMessage(c.port, msgBuf, uint32(len(msgBuf)), &bytesReturned)
		if err != nil {
			// Timeout or error, check if we should stop
			select {
			case <-c.stopChan:
				return
			default:
				continue
			}
		}

		// Handle message
		replyLen := c.handleMessage(msgBuf[:bytesReturned], replyBuf)
		if replyLen > 0 {
			_ = filterReplyMessage(c.port, replyBuf[:replyLen])
		}
	}
}

// handleMessage processes a message from the driver
func (c *DriverClient) handleMessage(msg []byte, reply []byte) int {
	if len(msg) < 12 { // Minimum header size
		return 0
	}

	msgType := binary.LittleEndian.Uint32(msg[0:4])
	// size := binary.LittleEndian.Uint32(msg[4:8])
	requestId := binary.LittleEndian.Uint64(msg[8:16])

	switch msgType {
	case MsgPing:
		return c.handlePing(msg, reply, requestId)
	default:
		// Unknown message type
		return 0
	}
}

// handlePing responds to a ping from the driver
func (c *DriverClient) handlePing(msg []byte, reply []byte, requestId uint64) int {
	// Build pong response
	binary.LittleEndian.PutUint32(reply[0:4], MsgPong)
	binary.LittleEndian.PutUint32(reply[4:8], 24) // Size
	binary.LittleEndian.PutUint64(reply[8:16], requestId)
	binary.LittleEndian.PutUint32(reply[16:20], DriverClientVersion)
	binary.LittleEndian.PutUint64(reply[20:28], uint64(time.Now().UnixNano()))

	return 28
}

// SendPong sends a pong message to the driver (for testing)
func (c *DriverClient) SendPong() error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	msg := make([]byte, 28)
	binary.LittleEndian.PutUint32(msg[0:4], MsgPong)
	binary.LittleEndian.PutUint32(msg[4:8], 28)
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))
	binary.LittleEndian.PutUint32(msg[16:20], DriverClientVersion)
	binary.LittleEndian.PutUint64(msg[20:28], uint64(time.Now().UnixNano()))

	return filterSendMessage(c.port, msg, nil)
}
```

**Step 2: Write the stub for non-Windows builds**

```go
// internal/platform/windows/driver_client_stub.go
//go:build !windows

package windows

import "fmt"

// DriverClient stub for non-Windows builds
type DriverClient struct{}

// NewDriverClient creates a stub driver client
func NewDriverClient() *DriverClient {
	return &DriverClient{}
}

// Connect always fails on non-Windows
func (c *DriverClient) Connect() error {
	return fmt.Errorf("driver client only available on Windows")
}

// Disconnect is a no-op on non-Windows
func (c *DriverClient) Disconnect() error {
	return nil
}

// Connected always returns false on non-Windows
func (c *DriverClient) Connected() bool {
	return false
}

// SendPong is a no-op on non-Windows
func (c *DriverClient) SendPong() error {
	return fmt.Errorf("driver client only available on Windows")
}
```

**Step 3: Commit**

```bash
git add internal/platform/windows/driver_client.go
git add internal/platform/windows/driver_client_stub.go
git commit -m "feat(windows): add Go driver client with filter port communication"
```

---

## Task 9: Create Windows Filter Manager Syscalls

**Files:**
- Create: `internal/platform/windows/fltlib_windows.go`

**Step 1: Write the Windows syscall wrappers**

```go
// internal/platform/windows/fltlib_windows.go
//go:build windows

package windows

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modFltLib = windows.NewLazySystemDLL("fltlib.dll")

	procFilterConnectCommunicationPort = modFltLib.NewProc("FilterConnectCommunicationPort")
	procFilterSendMessage              = modFltLib.NewProc("FilterSendMessage")
	procFilterGetMessage               = modFltLib.NewProc("FilterGetMessage")
	procFilterReplyMessage             = modFltLib.NewProc("FilterReplyMessage")
)

// filterConnectCommunicationPort connects to a mini-filter communication port
func filterConnectCommunicationPort(
	portName *uint16,
	options uint32,
	context unsafe.Pointer,
	sizeOfContext uint16,
	securityAttributes *windows.SecurityAttributes,
	port *windows.Handle,
) error {
	r1, _, e1 := syscall.SyscallN(
		procFilterConnectCommunicationPort.Addr(),
		uintptr(unsafe.Pointer(portName)),
		uintptr(options),
		uintptr(context),
		uintptr(sizeOfContext),
		uintptr(unsafe.Pointer(securityAttributes)),
		uintptr(unsafe.Pointer(port)),
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

// filterSendMessage sends a message to the mini-filter driver
func filterSendMessage(
	port windows.Handle,
	inBuffer []byte,
	outBuffer []byte,
) error {
	var outBufPtr unsafe.Pointer
	var outBufSize uint32
	var bytesReturned uint32

	if len(outBuffer) > 0 {
		outBufPtr = unsafe.Pointer(&outBuffer[0])
		outBufSize = uint32(len(outBuffer))
	}

	r1, _, e1 := syscall.SyscallN(
		procFilterSendMessage.Addr(),
		uintptr(port),
		uintptr(unsafe.Pointer(&inBuffer[0])),
		uintptr(len(inBuffer)),
		uintptr(outBufPtr),
		uintptr(outBufSize),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

// FILTER_MESSAGE_HEADER is the header for messages from the driver
type FILTER_MESSAGE_HEADER struct {
	ReplyLength uint32
	MessageId   uint64
}

// filterGetMessage receives a message from the mini-filter driver
func filterGetMessage(
	port windows.Handle,
	messageBuffer []byte,
	messageBufferSize uint32,
	bytesReturned *uint32,
) error {
	// FltLib expects a FILTER_MESSAGE_HEADER at the start
	r1, _, e1 := syscall.SyscallN(
		procFilterGetMessage.Addr(),
		uintptr(port),
		uintptr(unsafe.Pointer(&messageBuffer[0])),
		uintptr(messageBufferSize),
		0, // Overlapped (NULL for synchronous)
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

// filterReplyMessage sends a reply to the mini-filter driver
func filterReplyMessage(
	port windows.Handle,
	replyBuffer []byte,
) error {
	r1, _, e1 := syscall.SyscallN(
		procFilterReplyMessage.Addr(),
		uintptr(port),
		uintptr(unsafe.Pointer(&replyBuffer[0])),
		uintptr(len(replyBuffer)),
	)
	if r1 != 0 {
		return e1
	}
	return nil
}
```

**Step 2: Commit**

```bash
git add internal/platform/windows/fltlib_windows.go
git commit -m "feat(windows): add fltlib.dll syscall wrappers for filter port API"
```

---

## Task 10: Create Driver Client Unit Tests

**Files:**
- Create: `internal/platform/windows/driver_client_test.go`

**Step 1: Write unit tests (cross-platform, mock-based)**

```go
// internal/platform/windows/driver_client_test.go
package windows

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestMessageHeaderEncoding(t *testing.T) {
	// Test that we can encode/decode message headers correctly
	msg := make([]byte, 28)

	// Encode a pong message
	binary.LittleEndian.PutUint32(msg[0:4], MsgPong)
	binary.LittleEndian.PutUint32(msg[4:8], 28)
	binary.LittleEndian.PutUint64(msg[8:16], 12345)
	binary.LittleEndian.PutUint32(msg[16:20], DriverClientVersion)
	binary.LittleEndian.PutUint64(msg[20:28], uint64(time.Now().UnixNano()))

	// Decode and verify
	msgType := binary.LittleEndian.Uint32(msg[0:4])
	size := binary.LittleEndian.Uint32(msg[4:8])
	requestId := binary.LittleEndian.Uint64(msg[8:16])
	version := binary.LittleEndian.Uint32(msg[16:20])

	if msgType != MsgPong {
		t.Errorf("expected MsgPong (%d), got %d", MsgPong, msgType)
	}
	if size != 28 {
		t.Errorf("expected size 28, got %d", size)
	}
	if requestId != 12345 {
		t.Errorf("expected requestId 12345, got %d", requestId)
	}
	if version != DriverClientVersion {
		t.Errorf("expected version 0x%08X, got 0x%08X", DriverClientVersion, version)
	}
}

func TestDriverClientNotConnected(t *testing.T) {
	client := NewDriverClient()

	if client.Connected() {
		t.Error("new client should not be connected")
	}

	err := client.SendPong()
	if err == nil {
		t.Error("SendPong should fail when not connected")
	}
}

func TestDriverClientDisconnectIdempotent(t *testing.T) {
	client := NewDriverClient()

	// Disconnect when not connected should succeed
	err := client.Disconnect()
	if err != nil {
		t.Errorf("Disconnect should succeed when not connected: %v", err)
	}

	// Multiple disconnects should succeed
	err = client.Disconnect()
	if err != nil {
		t.Errorf("Multiple Disconnect calls should succeed: %v", err)
	}
}

func TestMessageConstants(t *testing.T) {
	// Verify message constants match protocol.h
	tests := []struct {
		name     string
		got      uint32
		expected uint32
	}{
		{"MsgPing", MsgPing, 0},
		{"MsgPolicyCheckFile", MsgPolicyCheckFile, 1},
		{"MsgPolicyCheckRegistry", MsgPolicyCheckRegistry, 2},
		{"MsgProcessCreated", MsgProcessCreated, 3},
		{"MsgProcessTerminated", MsgProcessTerminated, 4},
		{"MsgPong", MsgPong, 50},
		{"MsgRegisterSession", MsgRegisterSession, 100},
		{"MsgUnregisterSession", MsgUnregisterSession, 101},
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
cd /home/eran/work/agentsh/.worktrees/feature-windows-minifilter
go test ./internal/platform/windows/... -v
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add internal/platform/windows/driver_client_test.go
git commit -m "test(windows): add driver client unit tests"
```

---

## Task 11: Update Makefile with Driver Targets

**Files:**
- Modify: `Makefile`

**Step 1: Add driver build targets to Makefile**

Add these targets to the existing Makefile:

```makefile
# Windows driver targets (run on Windows with WDK)
.PHONY: build-driver build-driver-debug install-driver uninstall-driver

build-driver:
	@echo "Building Windows driver (Release)..."
	cd drivers/windows/agentsh-minifilter && scripts/build.cmd Release x64

build-driver-debug:
	@echo "Building Windows driver (Debug)..."
	cd drivers/windows/agentsh-minifilter && scripts/build.cmd Debug x64

install-driver:
	@echo "Installing Windows driver..."
	cd drivers/windows/agentsh-minifilter && scripts/install.cmd

uninstall-driver:
	@echo "Uninstalling Windows driver..."
	cd drivers/windows/agentsh-minifilter && scripts/uninstall.cmd

# Full Windows build (Go + driver)
build-windows-full: build-driver
	GOOS=windows GOARCH=amd64 go build -o bin/agentsh.exe ./cmd/agentsh
```

**Step 2: Commit**

```bash
git add Makefile
git commit -m "build: add Windows driver targets to Makefile"
```

---

## Task 12: Final Verification and Summary Commit

**Step 1: Run all tests**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-windows-minifilter
go test ./... -v
go build ./...
```

Expected: All tests pass, build succeeds

**Step 2: Verify driver files are complete**

```bash
ls -la drivers/windows/agentsh-minifilter/
ls -la drivers/windows/agentsh-minifilter/src/
ls -la drivers/windows/agentsh-minifilter/inc/
ls -la drivers/windows/agentsh-minifilter/scripts/
```

Expected: All files present

**Step 3: Create summary commit**

```bash
git log --oneline -10
```

Review commits, then push branch:

```bash
git push -u origin feature/windows-minifilter
```

---

## Phase 1 Complete Checklist

- [ ] Driver directory structure created
- [ ] Protocol header with message types
- [ ] Driver entry with filter registration
- [ ] Communication port handler
- [ ] Visual Studio project files
- [ ] INF installation manifest
- [ ] Build/install/uninstall scripts
- [ ] Go driver client with FilterConnect
- [ ] Fltlib syscall wrappers
- [ ] Unit tests for message encoding
- [ ] Makefile integration

## Next Steps (Phase 2)

After Phase 1 is complete and tested in a Windows VM:
1. Add process tracking (PsSetCreateProcessNotifyRoutineEx)
2. Implement session registration messages
3. Add process table with PID lookup
4. Test child process inheritance
