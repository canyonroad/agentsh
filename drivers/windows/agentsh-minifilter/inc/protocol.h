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
