package types

import "time"

type ExecRequest struct {
	Command      string            `json:"command"`
	Argv0        string            `json:"argv0,omitempty"`
	Args         []string          `json:"args,omitempty"`
	Timeout      string            `json:"timeout,omitempty"`
	WorkingDir   string            `json:"working_dir,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	Stdin        string            `json:"stdin,omitempty"`
	StreamOutput bool              `json:"stream_output,omitempty"`

	// IncludeEvents controls how much event detail is returned in the ExecResponse.
	// Valid values: "all" (default), "summary", "blocked", "none".
	IncludeEvents string `json:"include_events,omitempty"`
}

type ExecResponse struct {
	CommandID string    `json:"command_id"`
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`

	Request ExecRequest `json:"request"`
	Result  ExecResult  `json:"result"`

	Events ExecEvents `json:"events"`

	Resources *ExecResources `json:"resources,omitempty"`

	// Guidance provides small, actionable context for agents (blocked vs failed, retryability, substitutions).
	Guidance *ExecGuidance `json:"guidance,omitempty"`
}

type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`

	StdoutTruncated  bool  `json:"stdout_truncated,omitempty"`
	StderrTruncated  bool  `json:"stderr_truncated,omitempty"`
	StdoutTotalBytes int64 `json:"stdout_total_bytes,omitempty"`
	StderrTotalBytes int64 `json:"stderr_total_bytes,omitempty"`

	DurationMs int64       `json:"duration_ms"`
	Error      *ExecError  `json:"error,omitempty"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

type Pagination struct {
	CurrentOffset int64  `json:"current_offset"`
	CurrentLimit  int64  `json:"current_limit"`
	HasMore       bool   `json:"has_more"`
	NextCommand   string `json:"next_command,omitempty"`
}

type ExecError struct {
	Code        string         `json:"code"`
	Message     string         `json:"message"`
	PolicyRule  string         `json:"policy_rule,omitempty"`
	Suggestions []Suggestion   `json:"suggestions,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
}

type Suggestion struct {
	Action  string `json:"action"`
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

type ExecEvents struct {
	FileOperations    []Event `json:"file_operations"`
	NetworkOperations []Event `json:"network_operations"`
	BlockedOperations []Event `json:"blocked_operations"`
	Other             []Event `json:"other,omitempty"`

	// Counts are reported even when events are omitted for response-size reasons.
	FileOperationsCount    int `json:"file_operations_count,omitempty"`
	NetworkOperationsCount int `json:"network_operations_count,omitempty"`
	BlockedOperationsCount int `json:"blocked_operations_count,omitempty"`
	OtherCount             int `json:"other_count,omitempty"`

	// Truncated indicates the response omitted some events due to include_events settings or caps.
	Truncated bool `json:"truncated,omitempty"`
}

type ExecResources struct {
	CPUUserMs    int64 `json:"cpu_user_ms,omitempty"`
	CPUSystemMs  int64 `json:"cpu_system_ms,omitempty"`
	MemoryPeakKB int64 `json:"memory_peak_kb,omitempty"`
}

type ExecGuidance struct {
	// Status is an agent-friendly classification: "ok", "failed", or "blocked".
	Status string `json:"status,omitempty"`

	Blocked   bool   `json:"blocked,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
	Reason    string `json:"reason,omitempty"`

	PolicyRule       string `json:"policy_rule,omitempty"`
	BlockedOperation string `json:"blocked_operation,omitempty"`
	BlockedTarget    string `json:"blocked_target,omitempty"`

	// Substitutions are ordered "do this instead" options.
	Substitutions []Suggestion `json:"substitutions,omitempty"`
	// Suggestions are remediation steps when substitution isn't available.
	Suggestions []Suggestion `json:"suggestions,omitempty"`
}
