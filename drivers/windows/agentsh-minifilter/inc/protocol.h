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

// File operation types
typedef enum _AGENTSH_FILE_OP {
    FILE_OP_CREATE = 1,
    FILE_OP_READ = 2,
    FILE_OP_WRITE = 3,
    FILE_OP_DELETE = 4,
    FILE_OP_RENAME = 5
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

#endif // _AGENTSH_PROTOCOL_H_
