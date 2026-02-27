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
	EventDNSQuery                EventType = "dns_query"
	EventNetConnect              EventType = "net_connect"
	EventNetListen               EventType = "net_listen"
	EventNetAccept               EventType = "net_accept"
	EventDNSRedirect             EventType = "dns_redirect"
	EventConnectRedirect         EventType = "connect_redirect"
	EventConnectRedirectFallback EventType = "connect_redirect_fallback"
)

// Process operation events.
const (
	EventProcessStart EventType = "process_start"
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

// Signal events.
const (
	EventSignalSent       EventType = "signal_sent"
	EventSignalBlocked    EventType = "signal_blocked"
	EventSignalRedirected EventType = "signal_redirected"
	EventSignalAbsorbed   EventType = "signal_absorbed"
	EventSignalApproved   EventType = "signal_approved"
	EventSignalWouldDeny  EventType = "signal_would_deny"
)

// MCP inspection events.
const (
	EventMCPToolSeen              EventType = "mcp_tool_seen"
	EventMCPToolChanged           EventType = "mcp_tool_changed"
	EventMCPToolCalled            EventType = "mcp_tool_called"
	EventMCPDetection             EventType = "mcp_detection"
	EventMCPToolCallIntercepted   EventType = "mcp_tool_call_intercepted"
	EventMCPCrossServerBlocked    EventType = "mcp_cross_server_blocked"
	EventMCPNetworkConnection     EventType = "mcp_network_connection"
	EventMCPServerNameSimilarity  EventType = "mcp_server_name_similarity"
)

// Package check events.
const (
	EventPackageCheckStarted   EventType = "package_check_started"
	EventPackageCheckCompleted EventType = "package_check_completed"
	EventPackageBlocked        EventType = "package_blocked"
	EventPackageApproved       EventType = "package_approved"
	EventPackageWarning        EventType = "package_warning"
	EventProviderError         EventType = "package_provider_error"
)

// Policy events.
const (
	EventPolicyLoaded  EventType = "policy_loaded"
	EventPolicyChanged EventType = "policy_changed"
)

// PolicyLoadedEvent is emitted when a policy is loaded.
type PolicyLoadedEvent struct {
	PolicyName    string `json:"policy_name"`
	PolicyVersion string `json:"policy_version"` // SHA256 of content
	PolicyPath    string `json:"policy_path"`
	LoadedBy      string `json:"loaded_by"` // startup, reload, api
}

// PolicyChangedEvent is emitted when a policy changes.
type PolicyChangedEvent struct {
	PolicyName  string `json:"policy_name"`
	OldVersion  string `json:"old_version"`
	NewVersion  string `json:"new_version"`
	DiffSummary string `json:"diff_summary"` // e.g., "+2 rules, -1 rule"
	ChangedBy   string `json:"changed_by"`
}

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
	EventDNSQuery:                "network",
	EventNetConnect:              "network",
	EventNetListen:               "network",
	EventNetAccept:               "network",
	EventDNSRedirect:             "network",
	EventConnectRedirect:         "network",
	EventConnectRedirectFallback: "network",

	// Process
	EventProcessStart: "process",
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

	// Signal
	EventSignalSent:       "signal",
	EventSignalBlocked:    "signal",
	EventSignalRedirected: "signal",
	EventSignalAbsorbed:   "signal",
	EventSignalApproved:   "signal",
	EventSignalWouldDeny:  "signal",

	// MCP
	EventMCPToolSeen:             "mcp",
	EventMCPToolChanged:          "mcp",
	EventMCPToolCalled:           "mcp",
	EventMCPDetection:            "mcp",
	EventMCPToolCallIntercepted:  "mcp",
	EventMCPCrossServerBlocked:   "mcp",
	EventMCPNetworkConnection:    "mcp",
	EventMCPServerNameSimilarity: "mcp",

	// Package
	EventPackageCheckStarted:   "package",
	EventPackageCheckCompleted: "package",
	EventPackageBlocked:        "package",
	EventPackageApproved:       "package",
	EventPackageWarning:        "package",
	EventProviderError:         "package",

	// Policy
	EventPolicyLoaded:  "policy",
	EventPolicyChanged: "policy",
}

// AllEventTypes lists all event types.
var AllEventTypes = []EventType{
	// File
	EventFileOpen, EventFileRead, EventFileWrite, EventFileCreate,
	EventFileDelete, EventFileRename, EventFileStat, EventFileChmod,
	EventDirCreate, EventDirDelete, EventDirList,
	// Network
	EventDNSQuery, EventNetConnect, EventNetListen, EventNetAccept,
	EventDNSRedirect, EventConnectRedirect, EventConnectRedirectFallback,
	// Process
	EventProcessStart, EventProcessSpawn, EventProcessExit, EventProcessTree,
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
	// Signal
	EventSignalSent, EventSignalBlocked, EventSignalRedirected,
	EventSignalAbsorbed, EventSignalApproved, EventSignalWouldDeny,
	// MCP
	EventMCPToolSeen, EventMCPToolChanged, EventMCPToolCalled, EventMCPDetection,
	EventMCPToolCallIntercepted, EventMCPCrossServerBlocked, EventMCPNetworkConnection,
	EventMCPServerNameSimilarity,
	// Package
	EventPackageCheckStarted, EventPackageCheckCompleted, EventPackageBlocked,
	EventPackageApproved, EventPackageWarning, EventProviderError,
	// Policy
	EventPolicyLoaded, EventPolicyChanged,
}
