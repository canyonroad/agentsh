package types

import "time"

type ExecRequest struct {
	Command      string            `json:"command"`
	Args         []string          `json:"args,omitempty"`
	Timeout      string            `json:"timeout,omitempty"`
	WorkingDir   string            `json:"working_dir,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	Stdin        string            `json:"stdin,omitempty"`
	StreamOutput bool              `json:"stream_output,omitempty"`
}

type ExecResponse struct {
	CommandID string    `json:"command_id"`
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`

	Request ExecRequest `json:"request"`
	Result  ExecResult  `json:"result"`

	Events ExecEvents `json:"events"`
}

type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`

	StdoutTruncated bool  `json:"stdout_truncated,omitempty"`
	StderrTruncated bool  `json:"stderr_truncated,omitempty"`
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
	Suggestions []Suggestion    `json:"suggestions,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
}

type Suggestion struct {
	Action string `json:"action"`
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

type ExecEvents struct {
	FileOperations    []Event `json:"file_operations"`
	NetworkOperations []Event `json:"network_operations"`
	BlockedOperations []Event `json:"blocked_operations"`
	Other             []Event `json:"other,omitempty"`
}

