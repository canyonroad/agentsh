package events

// EventType identifies the type of event.
type EventType string

// File operation events.
const (
	EventFileOpen   EventType = "file_open"
	EventFileRead   EventType = "file_read"
	EventFileWrite  EventType = "file_write"
	EventFileCreate EventType = "file_create"
	EventFileDelete EventType = "file_delete"
	EventFileRename EventType = "file_rename"
	EventFileStat   EventType = "file_stat"
	EventFileChmod  EventType = "file_chmod"
	EventDirCreate  EventType = "dir_create"
	EventDirDelete  EventType = "dir_delete"
	EventDirList    EventType = "dir_list"
)

// Network operation events.
const (
	EventDNSQuery   EventType = "dns_query"
	EventNetConnect EventType = "net_connect"
	EventNetListen  EventType = "net_listen"
	EventNetAccept  EventType = "net_accept"
)

// Process operation events.
const (
	EventProcessStart EventType = "process_start"
	EventProcessEnd   EventType = "process_end"
	EventProcessSpawn EventType = "process_spawn"
	EventProcessExit  EventType = "process_exit"
	EventProcessTree  EventType = "process_tree_kill"
)

// Environment operation events.
const (
	EventEnvRead    EventType = "env_read"
	EventEnvWrite   EventType = "env_write"
	EventEnvList    EventType = "env_list"
	EventEnvBlocked EventType = "env_blocked"
)

// Soft delete operation events.
const (
	EventSoftDelete   EventType = "soft_delete"
	EventTrashRestore EventType = "trash_restore"
	EventTrashPurge   EventType = "trash_purge"
)

// Shell shim events.
const (
	EventShellInvoke      EventType = "shell_invoke"
	EventShellPassthrough EventType = "shell_passthrough"
	EventSessionAutostart EventType = "session_autostart"
)

// Command interception events.
const (
	EventCommandIntercept EventType = "command_intercept"
	EventCommandRedirect  EventType = "command_redirect"
	EventCommandBlocked   EventType = "command_blocked"
	EventPathRedirect     EventType = "path_redirect"
)

// Resource limit events.
const (
	EventResourceLimitSet      EventType = "resource_limit_set"
	EventResourceLimitWarning  EventType = "resource_limit_warning"
	EventResourceLimitExceeded EventType = "resource_limit_exceeded"
	EventResourceUsage         EventType = "resource_usage_snapshot"
)

// IPC events.
const (
	EventUnixSocketConnect EventType = "unix_socket_connect"
	EventUnixSocketBind    EventType = "unix_socket_bind"
	EventUnixSocketBlocked EventType = "unix_socket_blocked"
	EventNamedPipeOpen     EventType = "named_pipe_open"
	EventNamedPipeBlocked  EventType = "named_pipe_blocked"
	EventIPCObserved       EventType = "ipc_observed"
)

// Seccomp events.
const (
	EventSeccompBlocked EventType = "seccomp_blocked"
)

// MCP inspection events.
const (
	EventMCPToolSeen    EventType = "mcp_tool_seen"
	EventMCPToolChanged EventType = "mcp_tool_changed"
	EventMCPDetection   EventType = "mcp_detection"
)

// EventCategory maps event types to their categories.
var EventCategory = map[EventType]string{
	// File
	EventFileOpen:   "file",
	EventFileRead:   "file",
	EventFileWrite:  "file",
	EventFileCreate: "file",
	EventFileDelete: "file",
	EventFileRename: "file",
	EventFileStat:   "file",
	EventFileChmod:  "file",
	EventDirCreate:  "file",
	EventDirDelete:  "file",
	EventDirList:    "file",

	// Network
	EventDNSQuery:   "network",
	EventNetConnect: "network",
	EventNetListen:  "network",
	EventNetAccept:  "network",

	// Process
	EventProcessStart: "process",
	EventProcessEnd:   "process",
	EventProcessSpawn: "process",
	EventProcessExit:  "process",
	EventProcessTree:  "process",

	// Environment
	EventEnvRead:    "environment",
	EventEnvWrite:   "environment",
	EventEnvList:    "environment",
	EventEnvBlocked: "environment",

	// Soft delete
	EventSoftDelete:   "trash",
	EventTrashRestore: "trash",
	EventTrashPurge:   "trash",

	// Shell
	EventShellInvoke:      "shell",
	EventShellPassthrough: "shell",
	EventSessionAutostart: "shell",

	// Command
	EventCommandIntercept: "command",
	EventCommandRedirect:  "command",
	EventCommandBlocked:   "command",
	EventPathRedirect:     "command",

	// Resource
	EventResourceLimitSet:      "resource",
	EventResourceLimitWarning:  "resource",
	EventResourceLimitExceeded: "resource",
	EventResourceUsage:         "resource",

	// IPC
	EventUnixSocketConnect: "ipc",
	EventUnixSocketBind:    "ipc",
	EventUnixSocketBlocked: "ipc",
	EventNamedPipeOpen:     "ipc",
	EventNamedPipeBlocked:  "ipc",
	EventIPCObserved:       "ipc",

	// Seccomp
	EventSeccompBlocked: "seccomp",

	// MCP
	EventMCPToolSeen:    "mcp",
	EventMCPToolChanged: "mcp",
	EventMCPDetection:   "mcp",
}

// AllEventTypes lists all event types.
var AllEventTypes = []EventType{
	// File
	EventFileOpen, EventFileRead, EventFileWrite, EventFileCreate,
	EventFileDelete, EventFileRename, EventFileStat, EventFileChmod,
	EventDirCreate, EventDirDelete, EventDirList,
	// Network
	EventDNSQuery, EventNetConnect, EventNetListen, EventNetAccept,
	// Process
	EventProcessStart, EventProcessEnd, EventProcessSpawn, EventProcessExit, EventProcessTree,
	// Environment
	EventEnvRead, EventEnvWrite, EventEnvList, EventEnvBlocked,
	// Soft delete
	EventSoftDelete, EventTrashRestore, EventTrashPurge,
	// Shell
	EventShellInvoke, EventShellPassthrough, EventSessionAutostart,
	// Command
	EventCommandIntercept, EventCommandRedirect, EventCommandBlocked, EventPathRedirect,
	// Resource
	EventResourceLimitSet, EventResourceLimitWarning, EventResourceLimitExceeded, EventResourceUsage,
	// IPC
	EventUnixSocketConnect, EventUnixSocketBind, EventUnixSocketBlocked,
	EventNamedPipeOpen, EventNamedPipeBlocked, EventIPCObserved,
	// Seccomp
	EventSeccompBlocked,
	// MCP
	EventMCPToolSeen, EventMCPToolChanged, EventMCPDetection,
}
