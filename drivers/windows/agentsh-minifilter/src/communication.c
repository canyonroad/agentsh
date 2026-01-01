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
