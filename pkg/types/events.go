package types

import "time"

type PolicyInfo struct {
	Decision          Decision      `json:"decision,omitempty"`
	EffectiveDecision Decision      `json:"effective_decision,omitempty"`
	Rule              string        `json:"rule,omitempty"`
	Message           string        `json:"message,omitempty"`
	Approval          *ApprovalInfo `json:"approval,omitempty"`
	Redirect          *RedirectInfo `json:"redirect,omitempty"`
}

type ApprovalInfo struct {
	Required bool         `json:"required"`
	Mode     ApprovalMode `json:"mode,omitempty"`
	ID       string       `json:"id,omitempty"`
}

type Event struct {
	ID        string      `json:"id,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	Type      string      `json:"type"`
	SessionID string      `json:"session_id"`
	CommandID string      `json:"command_id,omitempty"`
	Source    string      `json:"source,omitempty"`
	PID       int         `json:"pid,omitempty"`
	Policy    *PolicyInfo `json:"policy,omitempty"`

	// Process context (for execve events)
	ParentPID int `json:"parent_pid,omitempty"`
	Depth     int `json:"depth,omitempty"`

	// Execve details
	Filename  string   `json:"filename,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`

	// Common convenience fields for indexing/search.
	Path      string `json:"path,omitempty"`
	Abstract  bool   `json:"abstract,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Remote    string `json:"remote,omitempty"`
	Operation string `json:"operation,omitempty"`
	// Unix socket remote or peer may reuse Remote field; kept for compatibility.

	// Policy result
	EffectiveAction string `json:"effective_action,omitempty"`

	Fields map[string]any `json:"fields,omitempty"`
}

type EventQuery struct {
	SessionID string
	CommandID string
	Types     []string
	Since     *time.Time
	Until     *time.Time

	Decision *Decision

	PathLike   string
	DomainLike string
	TextLike   string

	Limit  int
	Offset int
	Asc    bool
}
