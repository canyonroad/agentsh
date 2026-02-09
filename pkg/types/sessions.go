package types

import "time"

type SessionState string

const (
	SessionStatePending     SessionState = "pending"     // Created, not started
	SessionStateCreating    SessionState = "creating"    // Legacy: alias for starting
	SessionStateStarting    SessionState = "starting"    // Initializing sandbox
	SessionStateReady       SessionState = "ready"       // Legacy: alias for running
	SessionStateRunning     SessionState = "running"     // Agent is executing
	SessionStateBusy        SessionState = "busy"        // Command in progress
	SessionStatePaused      SessionState = "paused"      // Awaiting approval
	SessionStateStopping    SessionState = "stopping"    // Legacy: alias for terminating
	SessionStateTerminating SessionState = "terminating" // Graceful shutdown
	SessionStateCompleted   SessionState = "completed"   // Normal exit
	SessionStateFailed      SessionState = "failed"      // Error/crash
	SessionStateTimedOut    SessionState = "timed_out"   // Exceeded timeout
	SessionStateKilled      SessionState = "killed"      // Force terminated
)

// IsTerminal returns true if the session state is final.
func (s SessionState) IsTerminal() bool {
	switch s {
	case SessionStateCompleted, SessionStateFailed, SessionStateTimedOut, SessionStateKilled:
		return true
	default:
		return false
	}
}

// IsActive returns true if the session is currently active.
func (s SessionState) IsActive() bool {
	switch s {
	case SessionStateStarting, SessionStateCreating, SessionStateRunning, SessionStateReady, SessionStateBusy:
		return true
	default:
		return false
	}
}

type Session struct {
	ID          string       `json:"id"`
	State       SessionState `json:"state"`
	CreatedAt   time.Time    `json:"created_at"`
	Workspace   string       `json:"workspace"`
	Policy      string       `json:"policy"`
	Profile     string       `json:"profile,omitempty"`
	Mounts      []MountInfo  `json:"mounts,omitempty"`
	Cwd         string       `json:"cwd"`
	ProxyURL    string       `json:"proxy_url,omitempty"`
	TOTPSecret  string       `json:"-"` // Hidden from JSON/API, used for TOTP approval mode
	ProjectRoot string       `json:"project_root,omitempty"`
	GitRoot     string       `json:"git_root,omitempty"`
}

// MountInfo describes an active mount in a session.
type MountInfo struct {
	Path       string `json:"path"`
	Policy     string `json:"policy"`
	MountPoint string `json:"mount_point"`
}

// SessionStats tracks metrics for a session.
type SessionStats struct {
	// File operations
	FileReads    int64 `json:"file_reads"`
	FileWrites   int64 `json:"file_writes"`
	BytesRead    int64 `json:"bytes_read"`
	BytesWritten int64 `json:"bytes_written"`

	// Network operations
	NetworkConns   int64 `json:"network_conns"`
	NetworkBytesTx int64 `json:"network_bytes_tx"`
	NetworkBytesRx int64 `json:"network_bytes_rx"`
	DNSQueries     int64 `json:"dns_queries"`

	// Environment operations
	EnvReads int64 `json:"env_reads"`

	// Policy enforcement
	BlockedOps       int64 `json:"blocked_ops"`
	ApprovalsPending int   `json:"approvals_pending"`
	ApprovalsGranted int   `json:"approvals_granted"`
	ApprovalsDenied  int   `json:"approvals_denied"`

	// Resource usage
	CPUTimeMs    int64 `json:"cpu_time_ms"`
	PeakMemoryMB int64 `json:"peak_memory_mb"`

	// Commands
	CommandsExecuted int64 `json:"commands_executed"`
	CommandsFailed   int64 `json:"commands_failed"`
}

// SessionResult contains the final result of a session.
type SessionResult struct {
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
	Stats    SessionStats  `json:"stats"`
	Error    string        `json:"error,omitempty"`
}

type CreateSessionRequest struct {
	ID                string `json:"id,omitempty"`
	Workspace         string `json:"workspace,omitempty"`
	Policy            string `json:"policy,omitempty"`
	Profile           string `json:"profile,omitempty"`
	DetectProjectRoot *bool  `json:"detect_project_root,omitempty"` // Override server default
	ProjectRoot       string `json:"project_root,omitempty"`        // Explicit override
}

type SessionPatchRequest struct {
	Cwd   string            `json:"cwd,omitempty"`
	Env   map[string]string `json:"env,omitempty"`
	Unset []string          `json:"unset,omitempty"`
}

// WrapInitRequest is sent by the CLI to initialize seccomp wrapping for a session.
type WrapInitRequest struct {
	AgentCommand string   `json:"agent_command"`
	AgentArgs    []string `json:"agent_args,omitempty"`
}

// WrapInitResponse returns the seccomp wrapper configuration to the CLI.
type WrapInitResponse struct {
	WrapperBinary string            `json:"wrapper_binary"`
	StubBinary    string            `json:"stub_binary,omitempty"`
	SeccompConfig string            `json:"seccomp_config"`          // JSON-encoded seccomp config
	NotifySocket  string            `json:"notify_socket"`           // Unix socket path for forwarding notify fd
	SignalSocket  string            `json:"signal_socket,omitempty"` // Unix socket path for forwarding signal filter fd
	WrapperEnv    map[string]string `json:"wrapper_env"`             // Extra env vars for the wrapper
}
