package events

// BaseEvent contains fields common to ALL events.
// Every event is self-contained for independent parsing and analysis.
type BaseEvent struct {
	// Identity & Location
	Hostname         string `json:"hostname"`
	MachineID        string `json:"machine_id"`
	ContainerID      string `json:"container_id,omitempty"`
	ContainerImage   string `json:"container_image,omitempty"`
	ContainerRuntime string `json:"container_runtime,omitempty"`
	K8sNamespace     string `json:"k8s_namespace,omitempty"`
	K8sPod           string `json:"k8s_pod,omitempty"`
	K8sNode          string `json:"k8s_node,omitempty"`
	K8sCluster       string `json:"k8s_cluster,omitempty"`

	// Network Identity
	IPv4Addresses    []string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses    []string `json:"ipv6_addresses,omitempty"`
	PrimaryInterface string   `json:"primary_interface,omitempty"`
	MACAddress       string   `json:"mac_address,omitempty"`

	// Timestamp
	Timestamp       string `json:"timestamp"`
	TimestampUnixUS int64  `json:"timestamp_unix_us"`
	MonotonicNS     int64  `json:"monotonic_ns"`
	Sequence        int64  `json:"sequence"`

	// Operating System
	OS            string `json:"os"`
	OSVersion     string `json:"os_version,omitempty"`
	OSDistro      string `json:"os_distro,omitempty"`
	KernelVersion string `json:"kernel_version,omitempty"`
	Arch          string `json:"arch"`

	// Platform Details
	PlatformVariant string `json:"platform_variant,omitempty"`
	FSBackend       string `json:"fs_backend,omitempty"`
	NetBackend      string `json:"net_backend,omitempty"`
	ProcessBackend  string `json:"process_backend,omitempty"`
	IPCBackend      string `json:"ipc_backend,omitempty"`

	// Versioning
	AgentshVersion     string `json:"agentsh_version,omitempty"`
	AgentshCommit      string `json:"agentsh_commit,omitempty"`
	AgentshBuildTime   string `json:"agentsh_build_time,omitempty"`
	EventSchemaVersion string `json:"event_schema_version"`
	PolicyVersion      string `json:"policy_version,omitempty"`
	PolicyName         string `json:"policy_name,omitempty"`

	// Correlation IDs
	EventID         string `json:"event_id"`
	SessionID       string `json:"session_id"`
	CommandID       string `json:"command_id,omitempty"`
	TraceID         string `json:"trace_id,omitempty"`
	SpanID          string `json:"span_id,omitempty"`
	ParentSpanID    string `json:"parent_span_id,omitempty"`
	TraceFlags      string `json:"trace_flags,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	CausedByEventID string `json:"caused_by_event_id,omitempty"`

	// Process Context
	PID         int      `json:"pid"`
	PPID        int      `json:"ppid,omitempty"`
	ProcessName string   `json:"process_name,omitempty"`
	Executable  string   `json:"executable,omitempty"`
	Cmdline     []string `json:"cmdline,omitempty"`
	UID         int      `json:"uid,omitempty"`
	GID         int      `json:"gid,omitempty"`
	Username    string   `json:"username,omitempty"`
	Groupname   string   `json:"groupname,omitempty"`
	Cwd         string   `json:"cwd,omitempty"`
	TreeDepth   int      `json:"tree_depth,omitempty"`
	RootPID     int      `json:"root_pid,omitempty"`

	// Agent Context
	AgentID        string `json:"agent_id,omitempty"`
	AgentType      string `json:"agent_type,omitempty"`
	AgentFramework string `json:"agent_framework,omitempty"`
	OperatorID     string `json:"operator_id,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
	WorkspaceID    string `json:"workspace_id,omitempty"`

	// Policy & Decision
	Decision         string   `json:"decision,omitempty"`
	PolicyRule       string   `json:"policy_rule,omitempty"`
	RiskLevel        string   `json:"risk_level,omitempty"`
	RiskFactors      []string `json:"risk_factors,omitempty"`
	ApprovalRequired bool     `json:"approval_required,omitempty"`
	ApprovalID       string   `json:"approval_id,omitempty"`
	ApprovedBy       string   `json:"approved_by,omitempty"`

	// Performance Metrics
	LatencyUS    int64 `json:"latency_us,omitempty"`
	QueueTimeUS  int64 `json:"queue_time_us,omitempty"`
	PolicyEvalUS int64 `json:"policy_eval_us,omitempty"`
	InterceptUS  int64 `json:"intercept_us,omitempty"`
	BackendUS    int64 `json:"backend_us,omitempty"`

	// Error Context
	Error         string `json:"error,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	Errno         int    `json:"errno,omitempty"`
	ErrorCategory string `json:"error_category,omitempty"`
	Retryable     bool   `json:"retryable,omitempty"`

	// Event Type
	Type     EventType `json:"type"`
	Category string    `json:"category"`

	// Custom Metadata
	Metadata map[string]string `json:"metadata,omitempty"`
	Tags     []string          `json:"tags,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`

	// Sanitization Info
	SanitizedFields    []string `json:"sanitized_fields,omitempty"`
	SanitizationReason string   `json:"sanitization_reason,omitempty"`
}
