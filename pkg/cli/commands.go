package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// Client interface for interacting with agentsh server.
type Client interface {
	// Session operations
	ListSessions(ctx context.Context, opts ListSessionsOpts) ([]SessionInfo, error)
	GetSession(ctx context.Context, id string) (*SessionDetail, error)
	GetSessionLogs(ctx context.Context, id string, follow bool) (io.ReadCloser, error)
	GetSessionEvents(ctx context.Context, id string, opts EventsOpts) ([]Event, error)
	TerminateSession(ctx context.Context, id string, force bool, reason string) error

	// Policy operations
	ValidatePolicy(ctx context.Context, path string) (*ValidationResult, error)
	TestPolicy(ctx context.Context, policyDir, testDir string) (*TestResults, error)
	DiffPolicies(ctx context.Context, oldPath, newPath string) (*PolicyDiff, error)
	LintPolicy(ctx context.Context, path string) ([]LintIssue, error)

	// Debug operations
	TraceSession(ctx context.Context, id string, duration time.Duration) (io.ReadCloser, error)
	SimulateRecording(ctx context.Context, recordingPath, policyDir string) (*SimulationResult, error)

	// Status operations
	GetStatus(ctx context.Context) (*Status, error)
	GetMetrics(ctx context.Context) (*Metrics, error)

	// Config operations
	ValidateConfig(ctx context.Context) error
	GetConfig(ctx context.Context, effective bool) (map[string]any, error)
	SetConfig(ctx context.Context, key, value string) error
}

// ListSessionsOpts are options for listing sessions.
type ListSessionsOpts struct {
	Tenant string
	State  string
	Limit  int
}

// EventsOpts are options for getting events.
type EventsOpts struct {
	Type  string
	Since time.Time
	Limit int
}

// SessionInfo is summary information about a session.
type SessionInfo struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id,omitempty"`
	TenantID  string    `json:"tenant_id,omitempty"`
	State     string    `json:"state"`
	StartTime time.Time `json:"start_time"`
	Duration  string    `json:"duration,omitempty"`
}

// SessionDetail is detailed information about a session.
type SessionDetail struct {
	SessionInfo
	Workspace     string            `json:"workspace,omitempty"`
	PolicyRef     string            `json:"policy_ref,omitempty"`
	EventCount    int64             `json:"event_count"`
	LastActivity  time.Time         `json:"last_activity,omitempty"`
	ResourceUsage *ResourceUsage    `json:"resource_usage,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ResourceUsage tracks resource consumption.
type ResourceUsage struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryMB      int64   `json:"memory_mb"`
	DiskReadMB    int64   `json:"disk_read_mb"`
	DiskWriteMB   int64   `json:"disk_write_mb"`
	NetworkRxMB   int64   `json:"network_rx_mb"`
	NetworkTxMB   int64   `json:"network_tx_mb"`
	ProcessCount  int     `json:"process_count"`
}

// Event is an operation event.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Path      string    `json:"path,omitempty"`
	Decision  string    `json:"decision"`
	Latency   string    `json:"latency,omitempty"`
}

// ValidationResult is the result of policy validation.
type ValidationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// TestResults contains policy test results.
type TestResults struct {
	Passed  int           `json:"passed"`
	Failed  int           `json:"failed"`
	Skipped int           `json:"skipped"`
	Total   int           `json:"total"`
	Errors  []TestFailure `json:"errors,omitempty"`
}

// TestFailure describes a failed test.
type TestFailure struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Got      string `json:"got"`
	Error    string `json:"error,omitempty"`
}

// PolicyDiff describes differences between policies.
type PolicyDiff struct {
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
	Modified []string `json:"modified,omitempty"`
}

// LintIssue is a policy lint issue.
type LintIssue struct {
	Level   string `json:"level"` // error, warning, info
	Path    string `json:"path"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

// SimulationResult is the result of simulating a recording.
type SimulationResult struct {
	TotalEvents int          `json:"total_events"`
	Matched     int          `json:"matched"`
	Differences []Difference `json:"differences,omitempty"`
}

// Difference describes a decision difference.
type Difference struct {
	EventIndex  int    `json:"event_index"`
	Type        string `json:"type"`
	OldDecision string `json:"old_decision"`
	NewDecision string `json:"new_decision"`
}

// Status is the agentsh status.
type Status struct {
	Version        string    `json:"version"`
	Uptime         string    `json:"uptime"`
	StartTime      time.Time `json:"start_time"`
	ActiveSessions int       `json:"active_sessions"`
	Platform       string    `json:"platform"`
	PolicyLoaded   bool      `json:"policy_loaded"`
	Healthy        bool      `json:"healthy"`
}

// Metrics contains operational metrics.
type Metrics struct {
	SessionsTotal     int64              `json:"sessions_total"`
	SessionsActive    int64              `json:"sessions_active"`
	OperationsTotal   int64              `json:"operations_total"`
	OperationsByType  map[string]int64   `json:"operations_by_type"`
	DecisionsByType   map[string]int64   `json:"decisions_by_type"`
	AvgLatencyMs      float64            `json:"avg_latency_ms"`
	PolicyReloads     int64              `json:"policy_reloads"`
	ErrorsTotal       int64              `json:"errors_total"`
}

// Commander executes CLI commands.
type Commander struct {
	client Client
	output io.Writer
	json   bool
}

// NewCommander creates a new commander.
func NewCommander(client Client, output io.Writer) *Commander {
	return &Commander{
		client: client,
		output: output,
	}
}

// SetJSONOutput enables JSON output mode.
func (c *Commander) SetJSONOutput(enabled bool) {
	c.json = enabled
}

// SessionList lists sessions.
func (c *Commander) SessionList(ctx context.Context, opts ListSessionsOpts) error {
	sessions, err := c.client.ListSessions(ctx, opts)
	if err != nil {
		return fmt.Errorf("listing sessions: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(sessions)
	}

	if len(sessions) == 0 {
		fmt.Fprintln(c.output, "No sessions found")
		return nil
	}

	w := tabwriter.NewWriter(c.output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAGENT\tSTATE\tDURATION\tSTARTED")
	for _, s := range sessions {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			s.ID, s.AgentID, s.State, s.Duration,
			s.StartTime.Format(time.RFC3339))
	}
	return w.Flush()
}

// SessionGet gets session details.
func (c *Commander) SessionGet(ctx context.Context, id string) error {
	session, err := c.client.GetSession(ctx, id)
	if err != nil {
		return fmt.Errorf("getting session: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(session)
	}

	fmt.Fprintf(c.output, "Session: %s\n", session.ID)
	fmt.Fprintf(c.output, "State: %s\n", session.State)
	fmt.Fprintf(c.output, "Agent: %s\n", session.AgentID)
	if session.TenantID != "" {
		fmt.Fprintf(c.output, "Tenant: %s\n", session.TenantID)
	}
	fmt.Fprintf(c.output, "Started: %s\n", session.StartTime.Format(time.RFC3339))
	fmt.Fprintf(c.output, "Events: %d\n", session.EventCount)

	if session.ResourceUsage != nil {
		fmt.Fprintln(c.output, "\nResource Usage:")
		fmt.Fprintf(c.output, "  CPU: %.1f%%\n", session.ResourceUsage.CPUPercent)
		fmt.Fprintf(c.output, "  Memory: %d MB\n", session.ResourceUsage.MemoryMB)
		fmt.Fprintf(c.output, "  Processes: %d\n", session.ResourceUsage.ProcessCount)
	}

	return nil
}

// SessionEvents shows session events.
func (c *Commander) SessionEvents(ctx context.Context, id string, opts EventsOpts) error {
	events, err := c.client.GetSessionEvents(ctx, id, opts)
	if err != nil {
		return fmt.Errorf("getting events: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(events)
	}

	if len(events) == 0 {
		fmt.Fprintln(c.output, "No events found")
		return nil
	}

	w := tabwriter.NewWriter(c.output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tPATH\tDECISION\tLATENCY")
	for _, e := range events {
		path := e.Path
		if len(path) > 40 {
			path = "..." + path[len(path)-37:]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			e.Type, path, e.Decision, e.Latency)
	}
	return w.Flush()
}

// SessionTerminate terminates a session.
func (c *Commander) SessionTerminate(ctx context.Context, id string, force bool, reason string) error {
	if err := c.client.TerminateSession(ctx, id, force, reason); err != nil {
		return fmt.Errorf("terminating session: %w", err)
	}

	fmt.Fprintf(c.output, "Session %s terminated\n", id)
	return nil
}

// PolicyValidate validates a policy file.
func (c *Commander) PolicyValidate(ctx context.Context, path string) error {
	result, err := c.client.ValidatePolicy(ctx, path)
	if err != nil {
		return fmt.Errorf("validating policy: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(result)
	}

	if result.Valid {
		fmt.Fprintln(c.output, "✓ Policy is valid")
		return nil
	}

	fmt.Fprintln(c.output, "✗ Policy validation failed:")
	for _, e := range result.Errors {
		fmt.Fprintf(c.output, "  - %s\n", e)
	}
	return fmt.Errorf("validation failed")
}

// PolicyTest runs policy tests.
func (c *Commander) PolicyTest(ctx context.Context, policyDir, testDir string) error {
	results, err := c.client.TestPolicy(ctx, policyDir, testDir)
	if err != nil {
		return fmt.Errorf("running tests: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(results)
	}

	status := "PASS"
	if results.Failed > 0 {
		status = "FAIL"
	}

	fmt.Fprintf(c.output, "%s: %d/%d tests passed (%d failed, %d skipped)\n",
		status, results.Passed, results.Total, results.Failed, results.Skipped)

	if len(results.Errors) > 0 {
		fmt.Fprintln(c.output, "\nFailures:")
		for _, f := range results.Errors {
			fmt.Fprintf(c.output, "  %s: expected %s, got %s\n",
				f.Name, f.Expected, f.Got)
		}
	}

	if results.Failed > 0 {
		return fmt.Errorf("tests failed")
	}
	return nil
}

// PolicyDiff shows policy differences.
func (c *Commander) PolicyDiff(ctx context.Context, oldPath, newPath string) error {
	diff, err := c.client.DiffPolicies(ctx, oldPath, newPath)
	if err != nil {
		return fmt.Errorf("diffing policies: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(diff)
	}

	if len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Modified) == 0 {
		fmt.Fprintln(c.output, "No differences found")
		return nil
	}

	for _, a := range diff.Added {
		fmt.Fprintf(c.output, "+ %s\n", a)
	}
	for _, r := range diff.Removed {
		fmt.Fprintf(c.output, "- %s\n", r)
	}
	for _, m := range diff.Modified {
		fmt.Fprintf(c.output, "~ %s\n", m)
	}

	return nil
}

// PolicyLint lints a policy file.
func (c *Commander) PolicyLint(ctx context.Context, path string) error {
	issues, err := c.client.LintPolicy(ctx, path)
	if err != nil {
		return fmt.Errorf("linting policy: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(issues)
	}

	if len(issues) == 0 {
		fmt.Fprintln(c.output, "✓ No issues found")
		return nil
	}

	hasErrors := false
	for _, i := range issues {
		prefix := "info"
		if i.Level == "error" {
			prefix = "error"
			hasErrors = true
		} else if i.Level == "warning" {
			prefix = "warning"
		}

		if i.Line > 0 {
			fmt.Fprintf(c.output, "%s:%d: %s: %s\n", i.Path, i.Line, prefix, i.Message)
		} else {
			fmt.Fprintf(c.output, "%s: %s: %s\n", i.Path, prefix, i.Message)
		}
	}

	if hasErrors {
		return fmt.Errorf("lint errors found")
	}
	return nil
}

// DebugSimulate simulates a recording against a policy.
func (c *Commander) DebugSimulate(ctx context.Context, recordingPath, policyDir string) error {
	result, err := c.client.SimulateRecording(ctx, recordingPath, policyDir)
	if err != nil {
		return fmt.Errorf("simulating recording: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(result)
	}

	if result.TotalEvents == 0 {
		fmt.Fprintln(c.output, "No events to simulate")
		return nil
	}

	if len(result.Differences) == 0 {
		fmt.Fprintf(c.output, "MATCH: All %d events matched\n", result.TotalEvents)
		return nil
	}

	fmt.Fprintf(c.output, "DIFF: %d/%d events differ (%d matched)\n",
		len(result.Differences), result.TotalEvents, result.Matched)

	fmt.Fprintln(c.output, "\nDifferences:")
	w := tabwriter.NewWriter(c.output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "INDEX\tTYPE\tOLD\tNEW")
	for _, d := range result.Differences {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			d.EventIndex, d.Type, d.OldDecision, d.NewDecision)
	}
	w.Flush()

	return nil
}

// StatusShow shows agentsh status.
func (c *Commander) StatusShow(ctx context.Context) error {
	status, err := c.client.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("getting status: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(status)
	}

	healthy := "✓"
	if !status.Healthy {
		healthy = "✗"
	}

	fmt.Fprintf(c.output, "agentsh %s %s\n", status.Version, healthy)
	fmt.Fprintf(c.output, "Uptime: %s\n", status.Uptime)
	fmt.Fprintf(c.output, "Platform: %s\n", status.Platform)
	fmt.Fprintf(c.output, "Active Sessions: %d\n", status.ActiveSessions)
	fmt.Fprintf(c.output, "Policy Loaded: %v\n", status.PolicyLoaded)

	return nil
}

// MetricsShow shows metrics.
func (c *Commander) MetricsShow(ctx context.Context) error {
	metrics, err := c.client.GetMetrics(ctx)
	if err != nil {
		return fmt.Errorf("getting metrics: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(metrics)
	}

	fmt.Fprintln(c.output, "Sessions:")
	fmt.Fprintf(c.output, "  Total: %d\n", metrics.SessionsTotal)
	fmt.Fprintf(c.output, "  Active: %d\n", metrics.SessionsActive)

	fmt.Fprintln(c.output, "\nOperations:")
	fmt.Fprintf(c.output, "  Total: %d\n", metrics.OperationsTotal)
	fmt.Fprintf(c.output, "  Avg Latency: %.2fms\n", metrics.AvgLatencyMs)

	if len(metrics.OperationsByType) > 0 {
		fmt.Fprintln(c.output, "\n  By Type:")
		for t, count := range metrics.OperationsByType {
			fmt.Fprintf(c.output, "    %s: %d\n", t, count)
		}
	}

	if len(metrics.DecisionsByType) > 0 {
		fmt.Fprintln(c.output, "\n  By Decision:")
		for d, count := range metrics.DecisionsByType {
			fmt.Fprintf(c.output, "    %s: %d\n", d, count)
		}
	}

	fmt.Fprintf(c.output, "\nPolicy Reloads: %d\n", metrics.PolicyReloads)
	fmt.Fprintf(c.output, "Errors: %d\n", metrics.ErrorsTotal)

	return nil
}

// ConfigValidate validates the configuration.
func (c *Commander) ConfigValidate(ctx context.Context) error {
	if err := c.client.ValidateConfig(ctx); err != nil {
		fmt.Fprintf(c.output, "✗ Configuration invalid: %v\n", err)
		return err
	}

	fmt.Fprintln(c.output, "✓ Configuration is valid")
	return nil
}

// ConfigShow shows the configuration.
func (c *Commander) ConfigShow(ctx context.Context, effective bool) error {
	config, err := c.client.GetConfig(ctx, effective)
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	if c.json {
		return json.NewEncoder(c.output).Encode(config)
	}

	return c.printConfig(config, "")
}

func (c *Commander) printConfig(config map[string]any, prefix string) error {
	for k, v := range config {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		switch val := v.(type) {
		case map[string]any:
			c.printConfig(val, key)
		default:
			fmt.Fprintf(c.output, "%s = %v\n", key, val)
		}
	}
	return nil
}

// ConfigSet sets a configuration value.
func (c *Commander) ConfigSet(ctx context.Context, key, value string) error {
	if err := c.client.SetConfig(ctx, key, value); err != nil {
		return fmt.Errorf("setting config: %w", err)
	}

	fmt.Fprintf(c.output, "Set %s = %s\n", key, value)
	return nil
}

// FormatDuration formats a duration nicely.
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hours)
}

// TruncatePath truncates a path for display.
func TruncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	return "..." + path[len(path)-(maxLen-3):]
}

// ParseKeyValue parses a key=value string.
func ParseKeyValue(s string) (string, string, error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid format, expected key=value")
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}
