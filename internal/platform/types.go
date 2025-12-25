package platform

import (
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

// Capabilities describes what security features this platform supports.
type Capabilities struct {
	// Filesystem interception
	HasFUSE            bool   `json:"has_fuse"`
	FUSEImplementation string `json:"fuse_implementation,omitempty"` // "fuse3", "fuse-t", "winfsp"

	// Network interception
	HasNetworkIntercept   bool   `json:"has_network_intercept"`
	NetworkImplementation string `json:"network_implementation,omitempty"` // "iptables", "pf", "windivert", "wfp"
	CanRedirectTraffic    bool   `json:"can_redirect_traffic"`
	CanInspectTLS         bool   `json:"can_inspect_tls"`

	// Process isolation
	HasMountNamespace   bool           `json:"has_mount_namespace"`
	HasNetworkNamespace bool           `json:"has_network_namespace"`
	HasPIDNamespace     bool           `json:"has_pid_namespace"`
	HasUserNamespace    bool           `json:"has_user_namespace"`
	HasAppContainer     bool           `json:"has_app_container"` // Windows-specific
	IsolationLevel      IsolationLevel `json:"isolation_level"`

	// Syscall filtering
	HasSeccomp bool `json:"has_seccomp"`

	// Resource control
	HasCgroups           bool `json:"has_cgroups"`
	HasJobObjects        bool `json:"has_job_objects"` // Windows-specific
	CanLimitCPU          bool `json:"can_limit_cpu"`
	CanLimitMemory       bool `json:"can_limit_memory"`
	CanLimitDiskIO       bool `json:"can_limit_disk_io"`
	CanLimitNetworkBW    bool `json:"can_limit_network_bw"`
	CanLimitProcessCount bool `json:"can_limit_process_count"`

	// Windows-specific: Registry monitoring
	HasRegistryMonitoring bool `json:"has_registry_monitoring,omitempty"`
	HasRegistryBlocking   bool `json:"has_registry_blocking,omitempty"`

	// macOS-specific: Apple frameworks
	HasEndpointSecurity bool `json:"has_endpoint_security,omitempty"`
	HasNetworkExtension bool `json:"has_network_extension,omitempty"`
}

// IsolationLevel indicates the strength of process isolation available.
type IsolationLevel int

const (
	// IsolationNone means no isolation is available
	IsolationNone IsolationLevel = iota

	// IsolationMinimal provides basic file restrictions only
	IsolationMinimal

	// IsolationPartial provides AppContainer or similar (Windows)
	IsolationPartial

	// IsolationFull provides full namespace isolation (Linux)
	IsolationFull
)

func (l IsolationLevel) String() string {
	switch l {
	case IsolationNone:
		return "none"
	case IsolationMinimal:
		return "minimal"
	case IsolationPartial:
		return "partial"
	case IsolationFull:
		return "full"
	default:
		return "unknown"
	}
}

// Decision re-exports from pkg/types for convenience.
type Decision = types.Decision

// Decision constants re-exported for convenience.
const (
	DecisionAllow    = types.DecisionAllow
	DecisionDeny     = types.DecisionDeny
	DecisionApprove  = types.DecisionApprove
	DecisionRedirect = types.DecisionRedirect
)

// DecisionResponse is returned by InterceptionManager.Intercept().
type DecisionResponse struct {
	// Decision is the policy decision
	Decision Decision `json:"decision"`

	// Redirect contains the redirect target if Decision is DecisionRedirect
	Redirect *RedirectTarget `json:"redirect,omitempty"`

	// ApprovalID is set if the operation is pending approval
	ApprovalID string `json:"approval_id,omitempty"`

	// Error is set if the decision failed
	Error error `json:"error,omitempty"`

	// Rule is the policy rule that matched
	Rule string `json:"rule,omitempty"`

	// HeldDuration is how long the operation was held for decision
	HeldDuration time.Duration `json:"held_duration,omitempty"`
}

// RedirectTarget specifies where to redirect an operation.
type RedirectTarget struct {
	// For file operations
	FilePath string `json:"file_path,omitempty"`

	// For network operations
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`

	// For DNS
	IPAddress string `json:"ip_address,omitempty"`

	// For environment variables
	Value string `json:"value,omitempty"`
}

// InterceptedOperation represents an operation held for decision.
type InterceptedOperation struct {
	// ID uniquely identifies this operation
	ID string `json:"id"`

	// Type is the event type
	Type EventType `json:"type"`

	// Timestamp when the operation started
	Timestamp time.Time `json:"timestamp"`

	// Request contains operation details
	Request OperationRequest `json:"request"`

	// Decision is the current decision state
	Decision Decision `json:"decision"`

	// Redirect is set if redirecting
	Redirect *RedirectTarget `json:"redirect,omitempty"`

	// Timing
	HeldAt    time.Time  `json:"held_at"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	Timeout   time.Duration `json:"timeout"`

	// For manual approval
	ApprovalURL string `json:"approval_url,omitempty"`
	ApprovedBy  string `json:"approved_by,omitempty"`
}

// OperationRequest contains details about the intercepted operation.
type OperationRequest struct {
	// File operations
	Path      string `json:"path,omitempty"`
	Operation string `json:"operation,omitempty"`
	Flags     int    `json:"flags,omitempty"`

	// Network operations
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`

	// DNS operations
	Domain    string `json:"domain,omitempty"`
	QueryType string `json:"query_type,omitempty"`

	// Environment operations
	Variable string `json:"variable,omitempty"`
	Value    string `json:"value,omitempty"`

	// Process info
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
}

// EventType identifies the type of I/O event.
type EventType string

const (
	EventFileOpen    EventType = "file_open"
	EventFileRead    EventType = "file_read"
	EventFileWrite   EventType = "file_write"
	EventFileCreate  EventType = "file_create"
	EventFileDelete  EventType = "file_delete"
	EventFileRename  EventType = "file_rename"
	EventFileStat    EventType = "file_stat"
	EventDirRead     EventType = "dir_read"
	EventDNSQuery    EventType = "dns_query"
	EventNetConnect  EventType = "net_connect"
	EventNetListen   EventType = "net_listen"
	EventNetAccept   EventType = "net_accept"
	EventNetClose    EventType = "net_close"
	EventNetData     EventType = "net_data"
	EventProcessExec EventType = "process_exec"
	EventProcessExit EventType = "process_exit"

	// Environment variable events
	EventEnvRead   EventType = "env_read"
	EventEnvList   EventType = "env_list"
	EventEnvWrite  EventType = "env_write"
	EventEnvDelete EventType = "env_delete"

	// Windows-only: Registry events
	EventRegistryRead   EventType = "registry_read"
	EventRegistryWrite  EventType = "registry_write"
	EventRegistryCreate EventType = "registry_create"
	EventRegistryDelete EventType = "registry_delete"
)

// FileOperation identifies file operation types.
type FileOperation string

const (
	FileOpRead   FileOperation = "read"
	FileOpWrite  FileOperation = "write"
	FileOpCreate FileOperation = "create"
	FileOpDelete FileOperation = "delete"
	FileOpRename FileOperation = "rename"
	FileOpStat   FileOperation = "stat"
	FileOpList   FileOperation = "list"
)

// EnvOperation identifies environment variable operation types.
type EnvOperation string

const (
	EnvOpRead   EnvOperation = "read"
	EnvOpList   EnvOperation = "list"
	EnvOpWrite  EnvOperation = "write"
	EnvOpDelete EnvOperation = "delete"
)

// IOEvent represents an I/O operation event from platform interceptors.
// This extends pkg/types.Event with platform-specific fields.
type IOEvent struct {
	// Timestamp when the event occurred
	Timestamp time.Time `json:"timestamp"`

	// SessionID identifies the session
	SessionID string `json:"session_id"`

	// CommandID identifies the command within the session
	CommandID string `json:"command_id,omitempty"`

	// Type is the event type
	Type EventType `json:"type"`

	// File operations
	Path        string        `json:"path,omitempty"`
	Operation   FileOperation `json:"operation,omitempty"`
	BytesCount  int64         `json:"bytes,omitempty"`
	TargetPath  string        `json:"target_path,omitempty"` // For rename/link

	// Network operations
	Protocol   string `json:"protocol,omitempty"`
	LocalAddr  string `json:"local_addr,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Domain     string `json:"domain,omitempty"`

	// Decision & Interception
	Decision   Decision `json:"decision"`
	PolicyRule string   `json:"policy_rule,omitempty"`
	HeldMs     int64    `json:"held_ms,omitempty"`

	// Redirect (when Decision == "redirect")
	Redirected     bool   `json:"redirected,omitempty"`
	RedirectTarget string `json:"redirect_target,omitempty"`
	OriginalTarget string `json:"original_target,omitempty"`

	// Manual Approval (when Decision == "pending" or was pending)
	ApprovalID      string        `json:"approval_id,omitempty"`
	ApprovedBy      string        `json:"approved_by,omitempty"`
	ApprovalLatency time.Duration `json:"approval_latency_ns,omitempty"`

	// Process info
	ProcessID   int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`

	// Performance
	Latency time.Duration `json:"latency_ns,omitempty"`

	// Error if operation failed
	Error string `json:"error,omitempty"`

	// Platform identifies the platform/implementation
	Platform string `json:"platform,omitempty"`

	// Metadata for additional platform-specific data
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ToEvent converts IOEvent to pkg/types.Event for storage.
func (e *IOEvent) ToEvent() types.Event {
	ev := types.Event{
		Timestamp: e.Timestamp,
		Type:      string(e.Type),
		SessionID: e.SessionID,
		CommandID: e.CommandID,
		PID:       e.ProcessID,
		Path:      e.Path,
		Domain:    e.Domain,
		Remote:    e.RemoteAddr,
		Operation: string(e.Operation),
		Policy: &types.PolicyInfo{
			EffectiveDecision: e.Decision,
			Rule:              e.PolicyRule,
		},
		Fields: make(map[string]any),
	}

	// Copy metadata
	for k, v := range e.Metadata {
		ev.Fields[k] = v
	}

	// Add platform field
	ev.Fields["platform"] = e.Platform

	// Add redirect info if applicable
	if e.Redirected {
		ev.Fields["redirected"] = true
		ev.Fields["redirect_target"] = e.RedirectTarget
		ev.Fields["original_target"] = e.OriginalTarget
	}

	// Add approval info if applicable
	if e.ApprovalID != "" {
		ev.Fields["approval_id"] = e.ApprovalID
		ev.Fields["approved_by"] = e.ApprovedBy
	}

	return ev
}

// PlatformMode allows forcing a specific platform implementation.
type PlatformMode int

const (
	// ModeAuto automatically detects the best platform
	ModeAuto PlatformMode = iota

	// ModeLinuxNative uses Linux native implementation
	ModeLinuxNative

	// ModeDarwinNative uses macOS native implementation
	ModeDarwinNative

	// ModeDarwinLima uses macOS with Lima VM
	ModeDarwinLima

	// ModeWindowsNative uses Windows native implementation
	ModeWindowsNative

	// ModeWindowsWSL2 uses Windows with WSL2
	ModeWindowsWSL2
)

func (m PlatformMode) String() string {
	switch m {
	case ModeAuto:
		return "auto"
	case ModeLinuxNative:
		return "linux-native"
	case ModeDarwinNative:
		return "darwin-native"
	case ModeDarwinLima:
		return "darwin-lima"
	case ModeWindowsNative:
		return "windows-native"
	case ModeWindowsWSL2:
		return "windows-wsl2"
	default:
		return "unknown"
	}
}
