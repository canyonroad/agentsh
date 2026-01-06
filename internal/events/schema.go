package events

// ShellInvokeEvent - Shell shim intercepted a shell call.
type ShellInvokeEvent struct {
	BaseEvent

	Shell       string   `json:"shell"`        // "sh", "bash", "zsh", "powershell", "cmd"
	InvokedAs   string   `json:"invoked_as"`   // Actual binary name used
	Args        []string `json:"args"`         // Arguments passed
	Mode        string   `json:"mode"`         // "command" (-c), "script", "interactive"
	Command     string   `json:"command,omitempty"`
	Script      string   `json:"script,omitempty"`
	Intercepted bool     `json:"intercepted"`
	Strategy    string   `json:"strategy"` // "binary_replace", "path", "profile", "terminal"
}

// ShellPassthroughEvent - Shell shim bypassed (not in agentsh mode).
type ShellPassthroughEvent struct {
	BaseEvent

	Shell     string `json:"shell"`
	Reason    string `json:"reason"`     // "no_session", "no_server", "disabled"
	RealShell string `json:"real_shell"` // Path to actual shell used
}

// SessionAutostartEvent - Server auto-started by shim.
type SessionAutostartEvent struct {
	BaseEvent

	StartMethod string `json:"start_method"` // "fork", "systemd", "launchd", "service"
	ConfigPath  string `json:"config_path"`
	NewSession  string `json:"new_session_id"`
	Workspace   string `json:"workspace"`
	StartupMS   int64  `json:"startup_ms"`
}

// CommandInterceptEvent - Command evaluated by policy engine.
type CommandInterceptEvent struct {
	BaseEvent

	Command    string            `json:"command"`
	Args       []string          `json:"args"`
	Executable string            `json:"executable"`
	WorkingDir string            `json:"working_dir"`
	EnvSet     map[string]string `json:"env_set,omitempty"`
	EnvUnset   []string          `json:"env_unset,omitempty"`
}

// CommandRedirectEvent - Command redirected to different binary.
type CommandRedirectEvent struct {
	BaseEvent

	OriginalCommand string   `json:"original_command"`
	OriginalArgs    []string `json:"original_args"`
	NewCommand      string   `json:"new_command"`
	NewArgs         []string `json:"new_args"`
	Reason          string   `json:"reason"`
	Message         string   `json:"message"`
	RedirectRule    string   `json:"redirect_rule"`
}

// CommandBlockedEvent - Command denied by policy.
type CommandBlockedEvent struct {
	BaseEvent

	Command      string   `json:"command"`
	Args         []string `json:"args"`
	Reason       string   `json:"reason"`
	Message      string   `json:"message"`
	Suggestions  []string `json:"suggestions,omitempty"`
	Alternatives []string `json:"alternatives,omitempty"`
}

// PathRedirectEvent - File path redirected to different location.
type PathRedirectEvent struct {
	BaseEvent

	OriginalPath  string `json:"original_path"`
	RedirectPath  string `json:"redirect_path"`
	Operation     string `json:"operation"` // "write", "create", "mkdir"
	RedirectRule  string `json:"redirect_rule"`
	ParentCreated bool   `json:"parent_created"`
}

// ResourceLimits contains resource limit values.
type ResourceLimits struct {
	MaxMemoryMB      int64 `json:"max_memory_mb,omitempty"`
	MaxSwapMB        int64 `json:"max_swap_mb,omitempty"`
	CPUQuotaPercent  int   `json:"cpu_quota_percent,omitempty"`
	MaxProcesses     int   `json:"max_processes,omitempty"`
	MaxDiskReadMBps  int64 `json:"max_disk_read_mbps,omitempty"`
	MaxDiskWriteMBps int64 `json:"max_disk_write_mbps,omitempty"`
	CommandTimeoutS  int   `json:"command_timeout_s,omitempty"`
}

// LinuxCgroupInfo contains Linux cgroup details.
type LinuxCgroupInfo struct {
	Path        string   `json:"path"`
	Controllers []string `json:"controllers"`
	Version     int      `json:"version"`
}

// DarwinRlimitInfo contains macOS rlimit details.
type DarwinRlimitInfo struct {
	LimitsSet []string `json:"limits_set"`
	NiceValue int      `json:"nice_value,omitempty"`
}

// WindowsJobInfo contains Windows Job Object details.
type WindowsJobInfo struct {
	JobHandle    uint64 `json:"job_handle"`
	LimitFlags   uint32 `json:"limit_flags"`
	CPURateFlags uint32 `json:"cpu_rate_flags,omitempty"`
}

// ResourceLimitSetEvent - Limits applied to process/session.
type ResourceLimitSetEvent struct {
	BaseEvent

	TargetPID    int              `json:"target_pid"`
	TargetType   string           `json:"target_type"` // "session", "command", "process"
	Limits       ResourceLimits   `json:"limits"`
	LinuxCgroup  *LinuxCgroupInfo `json:"linux_cgroup,omitempty"`
	DarwinRlimit *DarwinRlimitInfo `json:"darwin_rlimit,omitempty"`
	WindowsJob   *WindowsJobInfo  `json:"windows_job,omitempty"`
}

// ResourceLimitWarningEvent - Usage approaching threshold.
type ResourceLimitWarningEvent struct {
	BaseEvent

	Resource    string  `json:"resource"` // "memory", "cpu", "disk", "processes"
	Current     int64   `json:"current"`
	CurrentUnit string  `json:"current_unit"` // "MB", "percent", "count"
	Limit       int64   `json:"limit"`
	Percentage  float64 `json:"percentage"`
	Threshold   float64 `json:"threshold"`
}

// ResourceLimitExceededEvent - Limit hit.
type ResourceLimitExceededEvent struct {
	BaseEvent

	Resource   string `json:"resource"`
	Current    int64  `json:"current"`
	Limit      int64  `json:"limit"`
	Unit       string `json:"unit"`
	Action     string `json:"action"` // "throttle", "kill", "deny", "warn"
	Terminated bool   `json:"terminated"`
	TermSignal int    `json:"term_signal,omitempty"`
}

// ResourceUsageEvent - Periodic usage snapshot.
type ResourceUsageEvent struct {
	BaseEvent

	MemoryMB      int64   `json:"memory_mb"`
	MemoryPercent float64 `json:"memory_percent"`
	CPUPercent    float64 `json:"cpu_percent"`
	DiskReadMB    int64   `json:"disk_read_mb"`
	DiskWriteMB   int64   `json:"disk_write_mb"`
	NetSentMB     int64   `json:"net_sent_mb"`
	NetReceivedMB int64   `json:"net_received_mb"`
	ProcessCount  int     `json:"process_count"`
	ThreadCount   int     `json:"thread_count"`
	OpenFiles     int     `json:"open_files"`
	IntervalMS    int64   `json:"interval_ms"`
}

// ProcessAncestry contains process ancestry info.
type ProcessAncestry struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
}

// ProcessSpawnEvent - Child process created.
type ProcessSpawnEvent struct {
	BaseEvent

	ChildPID         int               `json:"child_pid"`
	ChildComm        string            `json:"child_comm"`
	ChildExe         string            `json:"child_exe"`
	ChildArgs        []string          `json:"child_args"`
	ParentPID        int               `json:"parent_pid"`
	ParentComm       string            `json:"parent_comm"`
	Ancestry         []ProcessAncestry `json:"ancestry,omitempty"`
	Depth            int               `json:"depth"`
	LinuxCgroupPath  string            `json:"linux_cgroup_path,omitempty"`
	WindowsJobHandle uint64            `json:"windows_job_handle,omitempty"`
	Expected         bool              `json:"expected"`
}

// ProcessExitEvent - Process exited.
type ProcessExitEvent struct {
	BaseEvent

	ExitPID          int    `json:"exit_pid"`
	ExitComm         string `json:"exit_comm"`
	ExitCode         int    `json:"exit_code"`
	ExitSignal       int    `json:"exit_signal,omitempty"`
	ExitReason       string `json:"exit_reason"` // "normal", "signal", "oom", "timeout"
	RuntimeMS        int64  `json:"runtime_ms"`
	CPUTimeMS        int64  `json:"cpu_time_ms"`
	MaxMemoryMB      int64  `json:"max_memory_mb"`
	OrphanedChildren []int  `json:"orphaned_children,omitempty"`
}

// ProcessKillInfo contains info about a killed process.
type ProcessKillInfo struct {
	PID      int    `json:"pid"`
	Comm     string `json:"comm"`
	ExitCode int    `json:"exit_code"`
}

// ProcessTreeKillEvent - Entire tree terminated.
type ProcessTreeKillEvent struct {
	BaseEvent

	Reason          string            `json:"reason"` // "timeout", "limit_exceeded", "session_end", "manual", "policy"
	Signal          int               `json:"signal"`
	ProcessesKilled []ProcessKillInfo `json:"processes_killed"`
	TotalKilled     int               `json:"total_killed"`
	Survivors       []int             `json:"survivors,omitempty"`
	KillDurationMS  int64             `json:"kill_duration_ms"`
}

// UnixSocketEvent - Unix domain socket operation.
type UnixSocketEvent struct {
	BaseEvent

	Operation    string `json:"operation"` // "connect", "bind", "listen", "accept"
	SocketType   string `json:"socket_type"` // "stream", "dgram", "seqpacket"
	Path         string `json:"path,omitempty"`
	AbstractName string `json:"abstract_name,omitempty"`
	IsAbstract   bool   `json:"is_abstract"`
	PeerPID      int    `json:"peer_pid,omitempty"`
	PeerUID      int    `json:"peer_uid,omitempty"`
	PeerGID      int    `json:"peer_gid,omitempty"`
	PeerComm     string `json:"peer_comm,omitempty"`
	Service      string `json:"service,omitempty"` // "docker", "ssh-agent", "dbus", etc.
	Method       string `json:"method"`            // "seccomp", "dtrace", "poll"
}

// NamedPipeEvent - Windows named pipe operation.
type NamedPipeEvent struct {
	BaseEvent

	Operation  string `json:"operation"`   // "open", "create", "connect"
	Path       string `json:"path"`        // \\.\pipe\NAME
	PipeMode   string `json:"pipe_mode"`   // "byte", "message"
	AccessMode string `json:"access_mode"` // "read", "write", "readwrite"
	IsServer   bool   `json:"is_server"`
	Service    string `json:"service,omitempty"`
	Method     string `json:"method"` // "etw", "minifilter", "poll"
}

// IPCEndpoint contains IPC endpoint info.
type IPCEndpoint struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
	Role string `json:"role"` // "server", "client", "unknown"
}

// IPCObservedEvent - Audit-only detection (no enforcement).
type IPCObservedEvent struct {
	BaseEvent

	IPCType    string        `json:"ipc_type"` // "unix_socket", "named_pipe", "shm", "mqueue"
	Path       string        `json:"path"`
	Method     string        `json:"method"`     // "proc_net_unix", "lsof", "pipe_enum"
	Limitation string        `json:"limitation"` // "no_seccomp", "no_root", "audit_only"
	Endpoints  []IPCEndpoint `json:"endpoints,omitempty"`
}

// SeccompBlockedEvent - Seccomp killed process for blocked syscall.
type SeccompBlockedEvent struct {
	BaseEvent

	PID       int    `json:"pid"`
	Comm      string `json:"comm"`
	Syscall   string `json:"syscall"`
	SyscallNr int    `json:"syscall_nr"`
	Reason    string `json:"reason"` // "blocked_by_policy"
	Action    string `json:"action"` // "killed"
}

// XPCConnectEvent - XPC/Mach service connection attempt (macOS).
// Captured via ES_EVENT_TYPE_NOTIFY_XPC_CONNECT (macOS 14+) or sandbox violation logs.
type XPCConnectEvent struct {
	BaseEvent

	// Process info
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	Comm      string `json:"comm"`
	Exe       string `json:"exe"`
	SigningID string `json:"signing_id,omitempty"`

	// XPC connection details
	ServiceName   string `json:"service_name"`
	ServiceDomain string `json:"service_domain,omitempty"` // system, user, per-pid

	// Decision
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"` // allowlist, blocklist, default_allow, default_deny

	// For blocked connections
	BlockedBy string `json:"blocked_by,omitempty"` // sandbox_profile, esf_policy

	// Source of detection
	Source string `json:"source"` // esf, sandbox_log
}

// XPCSandboxViolationEvent - Sandbox denied mach-lookup (from system.log).
type XPCSandboxViolationEvent struct {
	BaseEvent

	PID         int    `json:"pid"`
	Comm        string `json:"comm"`
	ServiceName string `json:"service_name"`
	Operation   string `json:"operation"` // mach-lookup, mach-register
	Profile     string `json:"profile,omitempty"`
}
