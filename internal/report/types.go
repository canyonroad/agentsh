package report

import (
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

// Level specifies the detail level of a report.
type Level string

const (
	LevelSummary  Level = "summary"
	LevelDetailed Level = "detailed"
)

// Severity indicates the importance of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical" // Blocked ops, denied approvals
	SeverityWarning  Severity = "warning"  // Anomalies, soft-deletes
	SeverityInfo     Severity = "info"     // Redirects, granted approvals
)

// Finding represents a notable event or pattern detected in the session.
type Finding struct {
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`    // e.g., "blocked", "redirect", "anomaly"
	Title       string   `json:"title"`       // Short description
	Description string   `json:"description"` // Detailed explanation
	Count       int      `json:"count"`       // Number of occurrences
	Events      []string `json:"events"`      // Related event IDs
}

// DecisionCounts tracks counts by policy decision.
type DecisionCounts struct {
	Allowed    int `json:"allowed"`
	Blocked    int `json:"blocked"`
	Redirected int `json:"redirected"`
	SoftDelete int `json:"soft_delete"`
	Approved   int `json:"approved"`
	Denied     int `json:"denied"`
	Pending    int `json:"pending"`
}

// ActivitySummary summarizes activity by category.
type ActivitySummary struct {
	FileOps    int            `json:"file_ops"`
	NetworkOps int            `json:"network_ops"`
	Commands   int            `json:"commands"`
	TopPaths   map[string]int `json:"top_paths"` // path -> count
	TopHosts   map[string]int `json:"top_hosts"` // host -> count
	TopCmds    map[string]int `json:"top_cmds"`  // command -> count
}

// CommandDetail captures info about an executed command.
type CommandDetail struct {
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
	ExitCode  int       `json:"exit_code"`
	Duration  string    `json:"duration"`
}

// BlockedDetail captures info about a blocked operation.
type BlockedDetail struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Target    string    `json:"target"` // path, domain, command
	Rule      string    `json:"rule"`
	Message   string    `json:"message"`
}

// RedirectDetail captures info about a redirected operation.
type RedirectDetail struct {
	Timestamp  time.Time `json:"timestamp"`
	Original   string    `json:"original"`
	RedirectTo string    `json:"redirect_to"`
	Rule       string    `json:"rule"`
}

// Report contains all data for a session report.
type Report struct {
	// Header
	SessionID   string    `json:"session_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Level       Level     `json:"level"`

	// Overview
	Session  types.Session `json:"session"`
	Duration time.Duration `json:"duration"`

	// Decisions
	Decisions DecisionCounts `json:"decisions"`

	// Findings
	Findings []Finding `json:"findings"`

	// Activity
	Activity ActivitySummary `json:"activity"`

	// Detailed sections (only populated for LevelDetailed)
	Timeline        []types.Event    `json:"timeline,omitempty"`
	BlockedOps      []BlockedDetail  `json:"blocked_ops,omitempty"`
	Redirects       []RedirectDetail `json:"redirects,omitempty"`
	CommandHistory  []CommandDetail  `json:"command_history,omitempty"`
	AllFilePaths    map[string]int   `json:"all_file_paths,omitempty"`
	AllNetworkHosts map[string]int   `json:"all_network_hosts,omitempty"`

	// Resources
	Resources types.SessionStats `json:"resources"`

	// LLM Usage (only populated when llm-requests.jsonl is available)
	LLMUsage *LLMUsageStats `json:"llm_usage,omitempty"`

	// DLP Events (only populated when llm-requests.jsonl has DLP data)
	DLPEvents *DLPEventStats `json:"dlp_events,omitempty"`
}

// LLMUsageStats contains aggregated LLM usage statistics.
type LLMUsageStats struct {
	Providers []ProviderUsage `json:"providers"`
	Total     UsageTotals     `json:"total"`
}

// ProviderUsage contains usage statistics for a single LLM provider.
type ProviderUsage struct {
	Provider   string `json:"provider"`
	Requests   int    `json:"requests"`
	TokensIn   int    `json:"tokens_in"`
	TokensOut  int    `json:"tokens_out"`
	Errors     int    `json:"errors"`
	DurationMs int64  `json:"duration_ms"`
}

// UsageTotals contains aggregated totals across all providers.
type UsageTotals struct {
	Requests   int   `json:"requests"`
	TokensIn   int   `json:"tokens_in"`
	TokensOut  int   `json:"tokens_out"`
	Errors     int   `json:"errors"`
	DurationMs int64 `json:"duration_ms"`
}

// DLPEventStats contains aggregated DLP redaction statistics.
type DLPEventStats struct {
	Redactions []RedactionCount `json:"redactions"`
	Total      int              `json:"total"`
}

// RedactionCount represents the count of a specific redaction type.
type RedactionCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}
