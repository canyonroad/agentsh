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
	ID             string       `json:"id"`
	State          SessionState `json:"state"`
	CreatedAt      time.Time    `json:"created_at"`
	Workspace      string       `json:"workspace"`
	WorkspaceMount string       `json:"workspace_mount,omitempty"` // FUSE mount point (if active)
	Policy         string       `json:"policy"`
	Profile        string       `json:"profile,omitempty"`
	Mounts         []MountInfo  `json:"mounts,omitempty"`
	Cwd            string       `json:"cwd"`
	VirtualRoot    string       `json:"virtual_root,omitempty"`
	ProxyURL       string       `json:"proxy_url,omitempty"`
	LLMProxyURL    string       `json:"llm_proxy_url,omitempty"`
	TOTPSecret     string       `json:"-"` // Hidden from JSON/API, used for TOTP approval mode
	ProjectRoot    string       `json:"project_root,omitempty"`
	GitRoot        string       `json:"git_root,omitempty"`
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
	Home              string `json:"home,omitempty"`                // User's home directory for ${HOME} policy expansion
	DetectProjectRoot *bool  `json:"detect_project_root,omitempty"` // Override server default
	ProjectRoot       string `json:"project_root,omitempty"`        // Explicit override
	RealPaths         *bool  `json:"real_paths,omitempty"`          // Use actual host paths instead of /workspace
}

type SessionPatchRequest struct {
	Cwd   string            `json:"cwd,omitempty"`
	Env   map[string]string `json:"env,omitempty"`
	Unset []string          `json:"unset,omitempty"`
}

// WrapInitRequest is sent by the CLI or shim to initialize seccomp wrapping for a session.
type WrapInitRequest struct {
	AgentCommand string   `json:"agent_command"`
	AgentArgs    []string `json:"agent_args,omitempty"`
	CallerUID    int      `json:"caller_uid,omitempty"`
	// Mode selects wrap lifecycle. "agent" (default, used by `agentsh wrap`)
	// keeps the notify listener alive for the session lifetime. "shim"
	// (used by the shell shim) tears the listener down when the wrapped
	// process exits.
	Mode string `json:"mode,omitempty"`
}

// WrapInitResponse returns the seccomp wrapper configuration to the caller.
type WrapInitResponse struct {
	PtraceMode            bool              `json:"ptrace_mode,omitempty"`
	SafeToBypassShellShim bool              `json:"safe_to_bypass_shell_shim"`
	WrapperBinary         string            `json:"wrapper_binary"`
	StubBinary            string            `json:"stub_binary,omitempty"`
	SeccompConfig         string            `json:"seccomp_config"`
	NotifySocket          string            `json:"notify_socket"`
	SignalSocket          string            `json:"signal_socket,omitempty"`
	WrapperEnv            map[string]string `json:"wrapper_env"`
	// InstallRequired reports whether the caller must install kernel
	// filters. False when no enforcement features are enabled server-side
	// (lets shim-mode callers short-circuit without paying setup cost).
	InstallRequired bool `json:"install_required"`
}
