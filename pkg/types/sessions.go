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
	ID               string       `json:"id"`
	State            SessionState `json:"state"`
	CreatedAt        time.Time    `json:"created_at"`
	Workspace        string       `json:"workspace"`
	WorkspaceMount   string       `json:"workspace_mount,omitempty"` // FUSE mount point (if active)
	Policy           string       `json:"policy"`
	Profile          string       `json:"profile,omitempty"`
	Mounts           []MountInfo  `json:"mounts,omitempty"`
	Cwd              string       `json:"cwd"`
	VirtualRoot      string       `json:"virtual_root,omitempty"`
	ProxyURL         string       `json:"proxy_url,omitempty"`
	LLMProxyURL      string       `json:"llm_proxy_url,omitempty"`
	DBProxySocketDir string       `json:"db_proxy_socket_dir,omitempty"`
	TOTPSecret       string       `json:"-"` // Hidden from JSON/API, used for TOTP approval mode
	ProjectRoot      string       `json:"project_root,omitempty"`
	GitRoot          string       `json:"git_root,omitempty"`
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
	// Mode selects wrap lifecycle. Both "agent" (default, used by
	// `agentsh wrap`) and "shim" (used by the shell shim) currently use
	// the server's existing accept-once-then-handler control flow — the
	// listener goroutine accepts a single connection from the wrapper,
	// hands the notify fd to the persistent notify-handler, and exits.
	// The Mode field is plumbed for future use (e.g., distinct cleanup
	// strategies) and as an explicit signal of intent at the call site.
	// An empty string (field absent on the wire) is treated the same as
	// "agent".
	Mode string `json:"mode,omitempty"`
}

// EnvPolicyWire carries the resolved env allow/deny for the client (shell shim
// / CLI wrap) to filter the executed command's inherited environment. Nil/
// omitted means "no filtering" — the field is only populated when
// sandbox.wrap_env_policy.enabled is true, which also makes mixed-version
// deployments degrade safely.
//
// Only allow/deny are carried. block_iteration (replaces environ, incompatible
// with shells) and max_bytes/max_keys are intentionally NOT enforced on the
// wrap path: BuildEnv treats a max_* overflow as a hard error, which under the
// wrap path's fail-open contract would revert to the FULL unfiltered env —
// silently bypassing the very allow/deny stripping the operator wanted. So the
// wrap filter is allow/deny (+ the built-in default-secret-deny) only. Issue #379.
type EnvPolicyWire struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// WrapInitResponse returns the seccomp wrapper configuration to the caller.
//
// To decide whether to install kernel filters, the caller MUST inspect the
// presence of WrapperBinary (and NotifySocket): both populated means
// install; either empty means skip. Do not infer install/skip from a
// single boolean field — it is impossible to distinguish a deliberate
// "skip" from an old server that omits the field, and treating an absent
// field as "skip" would silently bypass enforcement in mixed-version
// deployments. The presence-of-WrapperBinary check is fail-closed: an old
// server that knows nothing about Mode==shim still returns its standard
// populated response, which the caller installs from.
type WrapInitResponse struct {
	PtraceMode            bool              `json:"ptrace_mode,omitempty"`
	SafeToBypassShellShim bool              `json:"safe_to_bypass_shell_shim"`
	WrapperBinary         string            `json:"wrapper_binary"`
	StubBinary            string            `json:"stub_binary,omitempty"`
	SeccompConfig         string            `json:"seccomp_config"`
	NotifySocket          string            `json:"notify_socket"`
	SignalSocket          string            `json:"signal_socket,omitempty"`
	WrapperEnv            map[string]string `json:"wrapper_env"`
	// EnvInject carries operator-configured sandbox.env_inject values for the
	// client (shell shim / CLI wrap) to overlay onto the executed command's
	// environment. On the client-spawned wrap path the server does not build
	// the child env itself, so these must be plumbed through the response and
	// applied client-side; on the server-spawned exec path env_inject is
	// applied directly in internal/api/exec.go instead. Issue #374.
	EnvInject map[string]string `json:"env_inject,omitempty"`
	// EnvPolicy carries the resolved env allow/deny/limits for the client to
	// filter the executed command's inherited environment, when
	// sandbox.wrap_env_policy.enabled is set. Nil ⇒ no filtering. Issue #379.
	EnvPolicy *EnvPolicyWire `json:"env_policy,omitempty"`
}
