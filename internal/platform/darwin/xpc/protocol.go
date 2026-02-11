package xpc

// RequestType identifies the type of policy check.
type RequestType string

const (
	RequestTypeFile      RequestType = "file"
	RequestTypeNetwork   RequestType = "network"
	RequestTypeCommand   RequestType = "command"
	RequestTypeSession   RequestType = "session"
	RequestTypeEvent     RequestType = "event"
	RequestTypeExecCheck RequestType = "exec_check"

	// PNACL (Process Network ACL) request types
	RequestTypePNACLCheck        RequestType = "pnacl_check"
	RequestTypePNACLEvent        RequestType = "pnacl_event"
	RequestTypePNACLGetApprovals RequestType = "get_pending_approvals"
	RequestTypePNACLSubmit       RequestType = "submit_approval"
	RequestTypePNACLConfigure    RequestType = "pnacl_configure"

	// Session management request types
	RequestTypeRegisterSession   RequestType = "register_session"
	RequestTypeUnregisterSession RequestType = "unregister_session"

	// Process muting request type
	RequestTypeMuteProcess RequestType = "mute_process"
)

// PolicyRequest is sent from the XPC bridge to the Go policy server.
type PolicyRequest struct {
	Type      RequestType `json:"type"`
	Path      string      `json:"path,omitempty"`      // file path or command path
	Operation string      `json:"operation,omitempty"` // read, write, delete, exec
	PID       int32       `json:"pid"`
	SessionID string      `json:"session_id,omitempty"`

	// Network-specific fields
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"` // Valid range: 0-65535
	Domain string `json:"domain,omitempty"`

	// Command-specific fields
	Args []string `json:"args,omitempty"`

	// Event emission
	EventData []byte `json:"event_data,omitempty"`

	// PNACL-specific fields
	Protocol       string `json:"protocol,omitempty"`        // "tcp" or "udp"
	BundleID       string `json:"bundle_id,omitempty"`       // macOS bundle identifier
	ExecutablePath string `json:"executable_path,omitempty"` // Full path to executable
	ProcessName    string `json:"process_name,omitempty"`    // Process name
	ParentPID      int32  `json:"parent_pid,omitempty"`      // Parent process ID

	// PNACL event fields
	EventType string `json:"event_type,omitempty"` // connection_allowed, connection_denied, etc.
	Decision  string `json:"decision,omitempty"`   // Policy decision for events
	RuleID    string `json:"rule_id,omitempty"`    // Rule that matched

	// PNACL approval fields
	RequestID string `json:"request_id,omitempty"` // Approval request ID
	Permanent bool   `json:"permanent,omitempty"`  // Whether to create permanent rule

	// PNACL configuration fields
	BlockingEnabled bool    `json:"blocking_enabled,omitempty"` // Enable actual blocking
	DecisionTimeout float64 `json:"decision_timeout,omitempty"` // Timeout in seconds
	FailOpen        bool    `json:"fail_open,omitempty"`        // Allow on timeout/error

	// Session management fields
	RootPID int32 `json:"root_pid,omitempty"` // Root PID for session registration

	// Exec context fields (from ESF event)
	TTYPath string `json:"tty_path,omitempty"` // Controlling terminal path
	CWDPath string `json:"cwd_path,omitempty"` // Working directory of the exec'ing process
}

// PolicyResponse is returned from the Go policy server.
type PolicyResponse struct {
	Allow     bool   `json:"allow"`
	Rule      string `json:"rule,omitempty"`
	Message   string `json:"message,omitempty"`
	SessionID string `json:"session_id,omitempty"` // for session lookups

	// Exec pipeline response fields
	Action       string `json:"action,omitempty"`        // "continue", "redirect", "deny" (exec pipeline action)
	ExecDecision string `json:"exec_decision,omitempty"` // "allow", "deny", "approve", "redirect", "audit"

	// PNACL-specific response fields
	Decision  string             `json:"decision,omitempty"`  // allow, deny, approve, audit, etc.
	RuleID    string             `json:"rule_id,omitempty"`   // Matched rule identifier
	Success   bool               `json:"success,omitempty"`   // For operations that return success/fail
	Approvals []ApprovalResponse `json:"approvals,omitempty"` // Pending approval requests
}

// ExecContext carries process context from the ESF event for exec redirect.
type ExecContext struct {
	TTYPath string // Controlling terminal path (e.g. /dev/ttys001)
	CWDPath string // Working directory of the exec'ing process
}

// ApprovalResponse represents a pending approval request returned to the client.
type ApprovalResponse struct {
	RequestID      string  `json:"request_id"`
	ProcessName    string  `json:"process_name"`
	BundleID       string  `json:"bundle_id,omitempty"`
	PID            int32   `json:"pid"`
	TargetHost     string  `json:"target_host"`
	TargetPort     int     `json:"target_port"`
	TargetProtocol string  `json:"target_protocol"`
	Timestamp      string  `json:"timestamp"`       // ISO 8601
	Timeout        float64 `json:"timeout"`         // Seconds until auto-deny
	ExecutablePath string  `json:"executable_path"` // Full path to executable
}
