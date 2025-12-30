# Session Report Command Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement `agentsh report` CLI command that generates markdown reports summarizing session activity for human operators.

**Architecture:** New `internal/report` package handles report generation with findings detection. CLI command in `internal/cli/report.go` wires it up. Reports query events from SQLite store and format as markdown.

**Tech Stack:** Go, Cobra CLI, SQLite event store, markdown output

---

## Task 1: Report Data Types

**Files:**
- Create: `internal/report/types.go`
- Test: `internal/report/types_test.go`

**Step 1: Write the test for report types**

```go
package report

import (
	"testing"
	"time"
)

func TestFindingSeverity(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityWarning, "warning"},
		{SeverityInfo, "info"},
	}
	for _, tc := range tests {
		if string(tc.sev) != tc.want {
			t.Errorf("Severity %v != %q", tc.sev, tc.want)
		}
	}
}

func TestReportLevel(t *testing.T) {
	if LevelSummary != "summary" {
		t.Error("LevelSummary should be 'summary'")
	}
	if LevelDetailed != "detailed" {
		t.Error("LevelDetailed should be 'detailed'")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/report/... -v -run TestFinding`
Expected: FAIL with "no Go files in internal/report"

**Step 3: Write the types implementation**

```go
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
	FileOps    int               `json:"file_ops"`
	NetworkOps int               `json:"network_ops"`
	Commands   int               `json:"commands"`
	TopPaths   map[string]int    `json:"top_paths"`   // path -> count
	TopHosts   map[string]int    `json:"top_hosts"`   // host -> count
	TopCmds    map[string]int    `json:"top_cmds"`    // command -> count
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
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/report/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/report/types.go internal/report/types_test.go
git commit -m "feat(report): add report data types"
```

---

## Task 2: Findings Detection

**Files:**
- Create: `internal/report/findings.go`
- Test: `internal/report/findings_test.go`

**Step 1: Write tests for findings detection**

```go
package report

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestDetectBlockedFindings(t *testing.T) {
	deny := types.DecisionDeny
	events := []types.Event{
		{ID: "1", Type: "file_write", Path: "/etc/hosts", Policy: &types.PolicyInfo{Decision: deny, Rule: "no-system"}},
		{ID: "2", Type: "file_write", Path: "/etc/passwd", Policy: &types.PolicyInfo{Decision: deny, Rule: "no-system"}},
	}

	findings := detectFindings(events)

	var blocked *Finding
	for i := range findings {
		if findings[i].Category == "blocked" {
			blocked = &findings[i]
			break
		}
	}

	if blocked == nil {
		t.Fatal("expected blocked finding")
	}
	if blocked.Severity != SeverityCritical {
		t.Errorf("blocked should be critical, got %s", blocked.Severity)
	}
	if blocked.Count != 2 {
		t.Errorf("expected count 2, got %d", blocked.Count)
	}
}

func TestDetectRedirectFindings(t *testing.T) {
	redirect := types.DecisionRedirect
	events := []types.Event{
		{ID: "1", Type: "command_redirect", Policy: &types.PolicyInfo{Decision: redirect}},
	}

	findings := detectFindings(events)

	var redir *Finding
	for i := range findings {
		if findings[i].Category == "redirect" {
			redir = &findings[i]
			break
		}
	}

	if redir == nil {
		t.Fatal("expected redirect finding")
	}
	if redir.Severity != SeverityInfo {
		t.Errorf("redirect should be info, got %s", redir.Severity)
	}
}

func TestDetectSensitivePathAnomaly(t *testing.T) {
	allow := types.DecisionAllow
	events := []types.Event{
		{ID: "1", Type: "file_read", Path: "/home/user/.ssh/id_rsa", Policy: &types.PolicyInfo{Decision: allow}},
	}

	findings := detectFindings(events)

	var anomaly *Finding
	for i := range findings {
		if findings[i].Category == "anomaly" {
			anomaly = &findings[i]
			break
		}
	}

	if anomaly == nil {
		t.Fatal("expected anomaly finding for sensitive path")
	}
	if anomaly.Severity != SeverityWarning {
		t.Errorf("anomaly should be warning, got %s", anomaly.Severity)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/report/... -v -run TestDetect`
Expected: FAIL with "undefined: detectFindings"

**Step 3: Write the findings detection implementation**

```go
package report

import (
	"regexp"
	"strings"

	"github.com/agentsh/agentsh/pkg/types"
)

// Sensitive path patterns for anomaly detection.
var sensitivePaths = []*regexp.Regexp{
	regexp.MustCompile(`^/etc/`),
	regexp.MustCompile(`^/usr/`),
	regexp.MustCompile(`\.ssh/`),
	regexp.MustCompile(`\.aws/`),
	regexp.MustCompile(`\.gnupg/`),
	regexp.MustCompile(`credentials`),
	regexp.MustCompile(`\.env$`),
	regexp.MustCompile(`\.pem$`),
	regexp.MustCompile(`\.key$`),
}

// detectFindings analyzes events and returns notable findings.
func detectFindings(events []types.Event) []Finding {
	var findings []Finding

	// Track counts for various categories
	var blockedEvents []string
	var redirectEvents []string
	var softDeleteEvents []string
	var approvedEvents []string
	var deniedEvents []string
	var sensitivePathEvents []string
	var failedCmdEvents []string
	var directIPEvents []string
	var unusualPortEvents []string

	uniqueHosts := make(map[string]bool)

	for _, ev := range events {
		if ev.Policy == nil {
			continue
		}

		decision := ev.Policy.Decision
		if ev.Policy.EffectiveDecision != "" {
			decision = ev.Policy.EffectiveDecision
		}

		// Policy violations
		switch decision {
		case types.DecisionDeny:
			blockedEvents = append(blockedEvents, ev.ID)
		case types.DecisionRedirect:
			redirectEvents = append(redirectEvents, ev.ID)
		case types.DecisionSoftDelete:
			softDeleteEvents = append(softDeleteEvents, ev.ID)
		}

		// Check for approvals
		if ev.Policy.Approval != nil {
			if ev.Policy.Decision == types.DecisionApprove {
				approvedEvents = append(approvedEvents, ev.ID)
			}
			// Note: denied approvals typically result in DecisionDeny
		}

		// Anomaly: sensitive path access
		if ev.Path != "" {
			for _, re := range sensitivePaths {
				if re.MatchString(ev.Path) {
					sensitivePathEvents = append(sensitivePathEvents, ev.ID)
					break
				}
			}
		}

		// Anomaly: direct IP connections (not domain)
		if ev.Remote != "" && ev.Domain == "" && ev.Type == "net_connect" {
			directIPEvents = append(directIPEvents, ev.ID)
		}

		// Anomaly: unusual ports (not 80/443)
		if ev.Remote != "" && ev.Type == "net_connect" {
			parts := strings.Split(ev.Remote, ":")
			if len(parts) == 2 && parts[1] != "80" && parts[1] != "443" {
				unusualPortEvents = append(unusualPortEvents, ev.ID)
			}
		}

		// Track unique hosts
		if ev.Domain != "" {
			uniqueHosts[ev.Domain] = true
		}

		// Failed commands
		if ev.Type == "process_exit" || ev.Type == "command_exit" {
			if exitCode, ok := ev.Fields["exit_code"].(float64); ok && exitCode != 0 {
				failedCmdEvents = append(failedCmdEvents, ev.ID)
			}
		}
	}

	// Build findings from collected data
	if len(blockedEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Category:    "blocked",
			Title:       "Operations blocked",
			Description: "Operations were denied by policy",
			Count:       len(blockedEvents),
			Events:      blockedEvents,
		})
	}

	if len(deniedEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Category:    "denied_approval",
			Title:       "Approvals denied",
			Description: "Requested operations were denied by operator",
			Count:       len(deniedEvents),
			Events:      deniedEvents,
		})
	}

	if len(softDeleteEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "soft_delete",
			Title:       "Files soft-deleted",
			Description: "Files were moved to trash (recoverable via agentsh trash)",
			Count:       len(softDeleteEvents),
			Events:      softDeleteEvents,
		})
	}

	if len(sensitivePathEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "anomaly",
			Title:       "Sensitive path access",
			Description: "Access to sensitive paths detected (credentials, SSH keys, etc.)",
			Count:       len(sensitivePathEvents),
			Events:      sensitivePathEvents,
		})
	}

	if len(directIPEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "anomaly",
			Title:       "Direct IP connections",
			Description: "Network connections to IP addresses instead of domains",
			Count:       len(directIPEvents),
			Events:      directIPEvents,
		})
	}

	if len(unusualPortEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "anomaly",
			Title:       "Unusual port connections",
			Description: "Network connections to non-standard ports (not 80/443)",
			Count:       len(unusualPortEvents),
			Events:      unusualPortEvents,
		})
	}

	if len(uniqueHosts) > 10 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "anomaly",
			Title:       "High host diversity",
			Description: "Connections to many unique hosts detected",
			Count:       len(uniqueHosts),
		})
	}

	if len(redirectEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityInfo,
			Category:    "redirect",
			Title:       "Operations redirected",
			Description: "Commands or paths were substituted per policy",
			Count:       len(redirectEvents),
			Events:      redirectEvents,
		})
	}

	if len(approvedEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityInfo,
			Category:    "approved",
			Title:       "Approvals granted",
			Description: "Operations required and received human approval",
			Count:       len(approvedEvents),
			Events:      approvedEvents,
		})
	}

	if len(failedCmdEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityInfo,
			Category:    "failed_command",
			Title:       "Commands failed",
			Description: "Commands exited with non-zero status",
			Count:       len(failedCmdEvents),
			Events:      failedCmdEvents,
		})
	}

	return findings
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/report/... -v -run TestDetect`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/report/findings.go internal/report/findings_test.go
git commit -m "feat(report): add findings detection logic"
```

---

## Task 3: Report Generator

**Files:**
- Create: `internal/report/generator.go`
- Test: `internal/report/generator_test.go`

**Step 1: Write tests for report generator**

```go
package report

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

type mockEventStore struct {
	events []types.Event
}

func (m *mockEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return m.events, nil
}

func (m *mockEventStore) AppendEvent(ctx context.Context, ev types.Event) error { return nil }
func (m *mockEventStore) Close() error                                         { return nil }

func TestGenerateSummaryReport(t *testing.T) {
	store := &mockEventStore{
		events: []types.Event{
			{ID: "1", Type: "file_read", Path: "/workspace/main.go", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
			{ID: "2", Type: "file_write", Path: "/workspace/main.go", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
			{ID: "3", Type: "net_connect", Domain: "api.github.com", Remote: "api.github.com:443", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		},
	}

	sess := types.Session{
		ID:        "test-session",
		State:     types.SessionStateCompleted,
		CreatedAt: time.Now().Add(-10 * time.Minute),
		Policy:    "default",
	}

	gen := NewGenerator(store)
	report, err := gen.Generate(context.Background(), sess, LevelSummary)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if report.SessionID != "test-session" {
		t.Errorf("wrong session ID: %s", report.SessionID)
	}
	if report.Level != LevelSummary {
		t.Errorf("wrong level: %s", report.Level)
	}
	if report.Decisions.Allowed != 3 {
		t.Errorf("expected 3 allowed, got %d", report.Decisions.Allowed)
	}
	if report.Activity.FileOps != 2 {
		t.Errorf("expected 2 file ops, got %d", report.Activity.FileOps)
	}
	if report.Activity.NetworkOps != 1 {
		t.Errorf("expected 1 network op, got %d", report.Activity.NetworkOps)
	}
}

func TestGenerateDetailedReport(t *testing.T) {
	store := &mockEventStore{
		events: []types.Event{
			{ID: "1", Type: "file_read", Path: "/workspace/main.go", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		},
	}

	sess := types.Session{
		ID:        "test-session",
		State:     types.SessionStateCompleted,
		CreatedAt: time.Now().Add(-10 * time.Minute),
	}

	gen := NewGenerator(store)
	report, err := gen.Generate(context.Background(), sess, LevelDetailed)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(report.Timeline) != 1 {
		t.Errorf("expected timeline with 1 event, got %d", len(report.Timeline))
	}
	if report.AllFilePaths == nil {
		t.Error("expected AllFilePaths to be populated")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/report/... -v -run TestGenerate`
Expected: FAIL with "undefined: NewGenerator"

**Step 3: Write the generator implementation**

```go
package report

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/pkg/types"
)

// Generator creates reports from session data.
type Generator struct {
	store store.EventStore
}

// NewGenerator creates a new report generator.
func NewGenerator(s store.EventStore) *Generator {
	return &Generator{store: s}
}

// Generate creates a report for the given session.
func (g *Generator) Generate(ctx context.Context, sess types.Session, level Level) (*Report, error) {
	// Query all events for this session
	events, err := g.store.QueryEvents(ctx, types.EventQuery{
		SessionID: sess.ID,
		Asc:       true,
	})
	if err != nil {
		return nil, err
	}

	report := &Report{
		SessionID:   sess.ID,
		GeneratedAt: time.Now().UTC(),
		Level:       level,
		Session:     sess,
	}

	// Calculate duration
	if len(events) > 0 {
		first := events[0].Timestamp
		last := events[len(events)-1].Timestamp
		report.Duration = last.Sub(first)
	}

	// Count decisions and build activity summary
	report.Decisions = countDecisions(events)
	report.Activity = buildActivitySummary(events)
	report.Findings = detectFindings(events)

	// For detailed reports, include full data
	if level == LevelDetailed {
		report.Timeline = events
		report.BlockedOps = extractBlockedOps(events)
		report.Redirects = extractRedirects(events)
		report.CommandHistory = extractCommands(events)
		report.AllFilePaths = buildFullPathMap(events)
		report.AllNetworkHosts = buildFullHostMap(events)
	}

	return report, nil
}

func countDecisions(events []types.Event) DecisionCounts {
	var counts DecisionCounts
	for _, ev := range events {
		if ev.Policy == nil {
			continue
		}
		decision := ev.Policy.Decision
		if ev.Policy.EffectiveDecision != "" {
			decision = ev.Policy.EffectiveDecision
		}
		switch decision {
		case types.DecisionAllow, types.DecisionAudit:
			counts.Allowed++
		case types.DecisionDeny:
			counts.Blocked++
		case types.DecisionRedirect:
			counts.Redirected++
		case types.DecisionSoftDelete:
			counts.SoftDelete++
		case types.DecisionApprove:
			if ev.Policy.Approval != nil && ev.Policy.Approval.Required {
				counts.Approved++
			}
		}
	}
	return counts
}

func buildActivitySummary(events []types.Event) ActivitySummary {
	summary := ActivitySummary{
		TopPaths: make(map[string]int),
		TopHosts: make(map[string]int),
		TopCmds:  make(map[string]int),
	}

	pathCounts := make(map[string]int)
	hostCounts := make(map[string]int)
	cmdCounts := make(map[string]int)

	for _, ev := range events {
		switch {
		case strings.HasPrefix(ev.Type, "file_") || strings.HasPrefix(ev.Type, "dir_"):
			summary.FileOps++
			if ev.Path != "" {
				// Group by directory for top paths
				dir := filepath.Dir(ev.Path)
				pathCounts[dir]++
			}
		case ev.Type == "net_connect" || ev.Type == "dns_query":
			summary.NetworkOps++
			if ev.Domain != "" {
				hostCounts[ev.Domain]++
			}
		case ev.Type == "command_intercept" || ev.Type == "process_start":
			summary.Commands++
			if cmd, ok := ev.Fields["command"].(string); ok {
				// Extract base command name
				parts := strings.Fields(cmd)
				if len(parts) > 0 {
					base := filepath.Base(parts[0])
					cmdCounts[base]++
				}
			}
		}
	}

	// Get top N entries
	summary.TopPaths = topN(pathCounts, 5)
	summary.TopHosts = topN(hostCounts, 5)
	summary.TopCmds = topN(cmdCounts, 5)

	return summary
}

func topN(m map[string]int, n int) map[string]int {
	if len(m) <= n {
		return m
	}
	result := make(map[string]int)
	for i := 0; i < n; i++ {
		maxKey := ""
		maxVal := 0
		for k, v := range m {
			if _, exists := result[k]; !exists && v > maxVal {
				maxKey = k
				maxVal = v
			}
		}
		if maxKey != "" {
			result[maxKey] = maxVal
		}
	}
	return result
}

func extractBlockedOps(events []types.Event) []BlockedDetail {
	var blocked []BlockedDetail
	for _, ev := range events {
		if ev.Policy == nil {
			continue
		}
		decision := ev.Policy.Decision
		if ev.Policy.EffectiveDecision != "" {
			decision = ev.Policy.EffectiveDecision
		}
		if decision == types.DecisionDeny {
			target := ev.Path
			if target == "" {
				target = ev.Domain
			}
			if target == "" {
				target = ev.Remote
			}
			blocked = append(blocked, BlockedDetail{
				Timestamp: ev.Timestamp,
				Type:      ev.Type,
				Target:    target,
				Rule:      ev.Policy.Rule,
				Message:   ev.Policy.Message,
			})
		}
	}
	return blocked
}

func extractRedirects(events []types.Event) []RedirectDetail {
	var redirects []RedirectDetail
	for _, ev := range events {
		if ev.Policy == nil || ev.Policy.Redirect == nil {
			continue
		}
		if ev.Policy.Decision == types.DecisionRedirect || ev.Policy.EffectiveDecision == types.DecisionRedirect {
			redirects = append(redirects, RedirectDetail{
				Timestamp:  ev.Timestamp,
				Original:   ev.Policy.Redirect.Original,
				RedirectTo: ev.Policy.Redirect.Target,
				Rule:       ev.Policy.Rule,
			})
		}
	}
	return redirects
}

func extractCommands(events []types.Event) []CommandDetail {
	var cmds []CommandDetail
	for _, ev := range events {
		if ev.Type != "command_intercept" && ev.Type != "process_start" {
			continue
		}
		cmd := ""
		if c, ok := ev.Fields["command"].(string); ok {
			cmd = c
		}
		cmds = append(cmds, CommandDetail{
			Timestamp: ev.Timestamp,
			Command:   cmd,
		})
	}
	return cmds
}

func buildFullPathMap(events []types.Event) map[string]int {
	m := make(map[string]int)
	for _, ev := range events {
		if ev.Path != "" {
			m[ev.Path]++
		}
	}
	return m
}

func buildFullHostMap(events []types.Event) map[string]int {
	m := make(map[string]int)
	for _, ev := range events {
		if ev.Domain != "" {
			m[ev.Domain]++
		}
	}
	return m
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/report/... -v -run TestGenerate`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/report/generator.go internal/report/generator_test.go
git commit -m "feat(report): add report generator"
```

---

## Task 4: Markdown Formatter

**Files:**
- Create: `internal/report/markdown.go`
- Test: `internal/report/markdown_test.go`

**Step 1: Write tests for markdown formatter**

```go
package report

import (
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestFormatSummaryMarkdown(t *testing.T) {
	report := &Report{
		SessionID:   "test-123",
		GeneratedAt: time.Date(2025, 12, 30, 14, 0, 0, 0, time.UTC),
		Level:       LevelSummary,
		Session: types.Session{
			ID:     "test-123",
			State:  types.SessionStateCompleted,
			Policy: "production",
		},
		Duration: 10 * time.Minute,
		Decisions: DecisionCounts{
			Allowed: 100,
			Blocked: 2,
		},
		Findings: []Finding{
			{Severity: SeverityCritical, Title: "Operations blocked", Count: 2},
		},
		Activity: ActivitySummary{
			FileOps:    50,
			NetworkOps: 10,
			Commands:   20,
		},
	}

	md := FormatMarkdown(report)

	// Check header
	if !strings.Contains(md, "# Session Report: test-123") {
		t.Error("missing header")
	}
	if !strings.Contains(md, "2025-12-30") {
		t.Error("missing date")
	}

	// Check overview section
	if !strings.Contains(md, "10m0s") {
		t.Error("missing duration")
	}
	if !strings.Contains(md, "production") {
		t.Error("missing policy")
	}

	// Check decisions
	if !strings.Contains(md, "100") {
		t.Error("missing allowed count")
	}

	// Check findings
	if !strings.Contains(md, "Operations blocked") {
		t.Error("missing finding")
	}
}

func TestFormatDetailedMarkdown(t *testing.T) {
	report := &Report{
		SessionID:   "test-123",
		GeneratedAt: time.Now(),
		Level:       LevelDetailed,
		Session:     types.Session{ID: "test-123"},
		BlockedOps: []BlockedDetail{
			{Timestamp: time.Now(), Type: "file_write", Target: "/etc/hosts", Rule: "no-system"},
		},
	}

	md := FormatMarkdown(report)

	if !strings.Contains(md, "Blocked Operations") {
		t.Error("missing blocked operations section")
	}
	if !strings.Contains(md, "/etc/hosts") {
		t.Error("missing blocked path")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/report/... -v -run TestFormat`
Expected: FAIL with "undefined: FormatMarkdown"

**Step 3: Write the markdown formatter**

```go
package report

import (
	"fmt"
	"sort"
	"strings"
)

// FormatMarkdown renders a report as markdown.
func FormatMarkdown(r *Report) string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("# Session Report: %s\n", r.SessionID))
	if r.Level == LevelDetailed {
		sb.WriteString(" (Detailed)\n")
	}
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", r.GeneratedAt.Format("2006-01-02 15:04:05 UTC")))

	// Overview
	sb.WriteString("## Overview\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Duration | %s |\n", r.Duration.String()))
	sb.WriteString(fmt.Sprintf("| Commands | %d |\n", r.Activity.Commands))
	sb.WriteString(fmt.Sprintf("| Policy | %s |\n", r.Session.Policy))
	sb.WriteString(fmt.Sprintf("| Status | %s |\n", r.Session.State))
	sb.WriteString("\n")

	// Decision Summary
	sb.WriteString("## Decision Summary\n")
	sb.WriteString("| Decision | Count |\n")
	sb.WriteString("|----------|-------|\n")
	if r.Decisions.Allowed > 0 {
		sb.WriteString(fmt.Sprintf("| Allowed | %d |\n", r.Decisions.Allowed))
	}
	if r.Decisions.Blocked > 0 {
		sb.WriteString(fmt.Sprintf("| Blocked | %d |\n", r.Decisions.Blocked))
	}
	if r.Decisions.Redirected > 0 {
		sb.WriteString(fmt.Sprintf("| Redirected | %d |\n", r.Decisions.Redirected))
	}
	if r.Decisions.SoftDelete > 0 {
		sb.WriteString(fmt.Sprintf("| Soft-deleted | %d |\n", r.Decisions.SoftDelete))
	}
	if r.Decisions.Approved > 0 {
		sb.WriteString(fmt.Sprintf("| Approved | %d |\n", r.Decisions.Approved))
	}
	if r.Decisions.Denied > 0 {
		sb.WriteString(fmt.Sprintf("| Denied | %d |\n", r.Decisions.Denied))
	}
	sb.WriteString("\n")

	// Findings
	if len(r.Findings) > 0 {
		sb.WriteString("## Findings\n")
		for _, f := range r.Findings {
			icon := severityIcon(f.Severity)
			sb.WriteString(fmt.Sprintf("%s **%s** (%d) - %s\n", icon, f.Title, f.Count, f.Description))
		}
		sb.WriteString("\n")
	}

	// Top Activity (summary level)
	sb.WriteString("## Top Activity\n")
	if len(r.Activity.TopPaths) > 0 {
		sb.WriteString(fmt.Sprintf("**Files (%d ops):** %s\n", r.Activity.FileOps, formatTopN(r.Activity.TopPaths)))
	}
	if len(r.Activity.TopHosts) > 0 {
		sb.WriteString(fmt.Sprintf("**Network (%d conns):** %s\n", r.Activity.NetworkOps, formatTopN(r.Activity.TopHosts)))
	}
	if len(r.Activity.TopCmds) > 0 {
		sb.WriteString(fmt.Sprintf("**Commands (%d):** %s\n", r.Activity.Commands, formatTopN(r.Activity.TopCmds)))
	}
	sb.WriteString("\n")

	// Detailed sections
	if r.Level == LevelDetailed {
		// Blocked Operations
		if len(r.BlockedOps) > 0 {
			sb.WriteString("## Blocked Operations\n")
			sb.WriteString("| Time | Type | Target | Rule | Message |\n")
			sb.WriteString("|------|------|--------|------|--------|\n")
			for _, b := range r.BlockedOps {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
					b.Timestamp.Format("15:04:05"), b.Type, b.Target, b.Rule, b.Message))
			}
			sb.WriteString("\n")
		}

		// Redirects
		if len(r.Redirects) > 0 {
			sb.WriteString("## Redirects\n")
			sb.WriteString("| Time | Original | Redirected To | Rule |\n")
			sb.WriteString("|------|----------|---------------|------|\n")
			for _, rd := range r.Redirects {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					rd.Timestamp.Format("15:04:05"), rd.Original, rd.RedirectTo, rd.Rule))
			}
			sb.WriteString("\n")
		}

		// Event Timeline
		if len(r.Timeline) > 0 {
			sb.WriteString("## Event Timeline\n")
			sb.WriteString("| Time | Type | Decision | Summary |\n")
			sb.WriteString("|------|------|----------|--------|\n")
			for _, ev := range r.Timeline {
				decision := ""
				if ev.Policy != nil {
					decision = string(ev.Policy.Decision)
				}
				summary := ev.Path
				if summary == "" {
					summary = ev.Domain
				}
				if summary == "" {
					summary = ev.Remote
				}
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					ev.Timestamp.Format("15:04:05"), ev.Type, decision, truncate(summary, 50)))
			}
			sb.WriteString("\n")
		}

		// Command History
		if len(r.CommandHistory) > 0 {
			sb.WriteString("## Command History\n")
			for i, cmd := range r.CommandHistory {
				sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, cmd.Timestamp.Format("15:04:05"), cmd.Command))
			}
			sb.WriteString("\n")
		}

		// All File Paths
		if len(r.AllFilePaths) > 0 {
			sb.WriteString("## All File Paths\n")
			paths := sortedKeys(r.AllFilePaths)
			for _, p := range paths {
				sb.WriteString(fmt.Sprintf("- %s (%d)\n", p, r.AllFilePaths[p]))
			}
			sb.WriteString("\n")
		}

		// All Network Hosts
		if len(r.AllNetworkHosts) > 0 {
			sb.WriteString("## All Network Hosts\n")
			hosts := sortedKeys(r.AllNetworkHosts)
			for _, h := range hosts {
				sb.WriteString(fmt.Sprintf("- %s (%d)\n", h, r.AllNetworkHosts[h]))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func severityIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityWarning:
		return "⚠️"
	case SeverityInfo:
		return "ℹ️"
	default:
		return ""
	}
}

func formatTopN(m map[string]int) string {
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("`%s` (%d)", k, v))
	}
	return strings.Join(parts, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/report/... -v -run TestFormat`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/report/markdown.go internal/report/markdown_test.go
git commit -m "feat(report): add markdown formatter"
```

---

## Task 5: CLI Report Command

**Files:**
- Create: `internal/cli/report.go`
- Test: `internal/cli/report_test.go`
- Modify: `internal/cli/root.go` (add report command)

**Step 1: Write tests for CLI command**

```go
package cli

import (
	"bytes"
	"testing"
)

func TestReportCmdFlags(t *testing.T) {
	cmd := newReportCmd()

	// Check required flags exist
	levelFlag := cmd.Flag("level")
	if levelFlag == nil {
		t.Error("missing --level flag")
	}

	outputFlag := cmd.Flag("output")
	if outputFlag == nil {
		t.Error("missing --output flag")
	}
}

func TestReportCmdArgs(t *testing.T) {
	cmd := newReportCmd()

	// Test requires exactly 1 arg
	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("should require session ID argument")
	}

	err = cmd.Args(cmd, []string{"session-123"})
	if err != nil {
		t.Errorf("should accept 1 arg: %v", err)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -v -run TestReportCmd`
Expected: FAIL with "undefined: newReportCmd"

**Step 3: Write the CLI command**

```go
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/report"
	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	var (
		level    string
		output   string
		directDB bool
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "report <session-id|latest>",
		Short: "Generate a session report",
		Long: `Generate a markdown report summarizing session activity.

Examples:
  # Quick summary of latest session
  agentsh report latest --level=summary

  # Detailed report saved to file
  agentsh report abc123 --level=detailed --output=report.md

  # Offline mode using local database
  agentsh report latest --level=summary --direct-db`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate level
			reportLevel := report.Level(level)
			if reportLevel != report.LevelSummary && reportLevel != report.LevelDetailed {
				return fmt.Errorf("invalid level %q: must be 'summary' or 'detailed'", level)
			}

			sessionArg := args[0]
			ctx := cmd.Context()

			var sess types.Session
			var events []types.Event
			var err error

			if directDB {
				// Direct database access (offline mode)
				if dbPath == "" {
					dbPath = "/var/lib/agentsh/events.db"
				}
				sess, events, err = loadFromDB(ctx, dbPath, sessionArg)
			} else {
				// Use API client
				cfg := getClientConfig(cmd)
				sess, events, err = loadFromAPI(ctx, cfg, sessionArg)
			}

			if err != nil {
				return err
			}

			// Create mock store for generator
			store := &memoryEventStore{events: events}
			gen := report.NewGenerator(store)

			rpt, err := gen.Generate(ctx, sess, reportLevel)
			if err != nil {
				return fmt.Errorf("generate report: %w", err)
			}

			md := report.FormatMarkdown(rpt)

			// Output to file or stdout
			if output != "" {
				if err := os.WriteFile(output, []byte(md), 0644); err != nil {
					return fmt.Errorf("write output file: %w", err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Report written to %s\n", output)
			} else {
				fmt.Fprint(cmd.OutOrStdout(), md)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&level, "level", "", "Report level: summary or detailed (required)")
	cmd.Flags().StringVar(&output, "output", "", "Output file path (default: stdout)")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local database directly (offline mode)")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "Path to events database (default: /var/lib/agentsh/events.db)")
	_ = cmd.MarkFlagRequired("level")

	return cmd
}

// memoryEventStore wraps pre-loaded events for the generator.
type memoryEventStore struct {
	events []types.Event
}

func (m *memoryEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return m.events, nil
}
func (m *memoryEventStore) AppendEvent(ctx context.Context, ev types.Event) error { return nil }
func (m *memoryEventStore) Close() error                                          { return nil }

func loadFromAPI(ctx context.Context, cfg clientConfig, sessionArg string) (types.Session, []types.Event, error) {
	c, err := client.NewForCLI(client.CLIOptions{
		HTTPBaseURL: cfg.serverAddr,
		GRPCAddr:    cfg.grpcAddr,
		APIKey:      cfg.apiKey,
		Transport:   cfg.transport,
	})
	if err != nil {
		return types.Session{}, nil, err
	}

	// Resolve "latest" to actual session ID
	sessionID := sessionArg
	if sessionArg == "latest" {
		sessions, err := c.ListSessions(ctx)
		if err != nil {
			return types.Session{}, nil, fmt.Errorf("list sessions: %w", err)
		}
		if len(sessions) == 0 {
			return types.Session{}, nil, fmt.Errorf("no sessions found")
		}
		// Find most recent by CreatedAt
		latest := sessions[0]
		for _, s := range sessions[1:] {
			if s.CreatedAt.After(latest.CreatedAt) {
				latest = s
			}
		}
		sessionID = latest.ID
	}

	sess, err := c.GetSession(ctx, sessionID)
	if err != nil {
		return types.Session{}, nil, fmt.Errorf("get session: %w (hint: run 'agentsh session list')", err)
	}

	events, err := c.QueryEvents(ctx, types.EventQuery{SessionID: sessionID, Asc: true})
	if err != nil {
		return types.Session{}, nil, fmt.Errorf("query events: %w", err)
	}

	return sess, events, nil
}

func loadFromDB(ctx context.Context, dbPath, sessionArg string) (types.Session, []types.Event, error) {
	store, err := sqlite.Open(dbPath)
	if err != nil {
		return types.Session{}, nil, fmt.Errorf("open database: %w", err)
	}
	defer store.Close()

	// For direct DB mode, we need to get session info from events
	// Query events to find sessions
	sessionID := sessionArg
	if sessionArg == "latest" {
		// Query recent events to find latest session
		events, err := store.QueryEvents(ctx, types.EventQuery{Limit: 1000})
		if err != nil {
			return types.Session{}, nil, fmt.Errorf("query events: %w", err)
		}
		if len(events) == 0 {
			return types.Session{}, nil, fmt.Errorf("no sessions found in database")
		}
		// Group by session, find most recent
		sessions := make(map[string]types.Event)
		for _, ev := range events {
			if _, ok := sessions[ev.SessionID]; !ok {
				sessions[ev.SessionID] = ev
			}
		}
		var latestID string
		var latestTime = events[0].Timestamp
		for sid, ev := range sessions {
			if ev.Timestamp.After(latestTime) {
				latestTime = ev.Timestamp
				latestID = sid
			}
		}
		sessionID = latestID
	}

	events, err := store.QueryEvents(ctx, types.EventQuery{SessionID: sessionID, Asc: true})
	if err != nil {
		return types.Session{}, nil, fmt.Errorf("query events: %w", err)
	}
	if len(events) == 0 {
		return types.Session{}, nil, fmt.Errorf("session %q not found", sessionID)
	}

	// Build minimal session from events
	sess := types.Session{
		ID:        sessionID,
		State:     types.SessionStateCompleted,
		CreatedAt: events[0].Timestamp,
	}

	return sess, events, nil
}
```

**Step 4: Modify root.go to add report command**

In `internal/cli/root.go`, find where commands are added (look for `AddCommand` calls) and add:

```go
rootCmd.AddCommand(newReportCmd())
```

**Step 5: Run test to verify it passes**

Run: `go test ./internal/cli/... -v -run TestReportCmd`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/cli/report.go internal/cli/report_test.go internal/cli/root.go
git commit -m "feat(cli): add report command"
```

---

## Task 6: Integration Test

**Files:**
- Create: `internal/report/integration_test.go`

**Step 1: Write integration test**

```go
//go:build integration

package report

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestReportIntegration(t *testing.T) {
	// Create temp database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Insert test events
	sessionID := "integration-test-session"
	now := time.Now()

	events := []types.Event{
		{ID: "1", SessionID: sessionID, Timestamp: now, Type: "file_read", Path: "/workspace/main.go", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{ID: "2", SessionID: sessionID, Timestamp: now.Add(time.Second), Type: "file_write", Path: "/workspace/main.go", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{ID: "3", SessionID: sessionID, Timestamp: now.Add(2 * time.Second), Type: "file_write", Path: "/etc/hosts", Policy: &types.PolicyInfo{Decision: types.DecisionDeny, Rule: "no-system", Message: "System file write blocked"}},
		{ID: "4", SessionID: sessionID, Timestamp: now.Add(3 * time.Second), Type: "net_connect", Domain: "api.github.com", Remote: "api.github.com:443", Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
	}

	for _, ev := range events {
		if err := store.AppendEvent(ctx, ev); err != nil {
			t.Fatalf("append event: %v", err)
		}
	}

	// Generate report
	gen := NewGenerator(store)
	sess := types.Session{
		ID:        sessionID,
		State:     types.SessionStateCompleted,
		CreatedAt: now,
		Policy:    "test-policy",
	}

	report, err := gen.Generate(ctx, sess, LevelDetailed)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Verify report content
	if report.Decisions.Allowed != 3 {
		t.Errorf("expected 3 allowed, got %d", report.Decisions.Allowed)
	}
	if report.Decisions.Blocked != 1 {
		t.Errorf("expected 1 blocked, got %d", report.Decisions.Blocked)
	}

	// Should have a critical finding for blocked op
	hasCritical := false
	for _, f := range report.Findings {
		if f.Severity == SeverityCritical && f.Category == "blocked" {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected critical finding for blocked operation")
	}

	// Format as markdown and verify
	md := FormatMarkdown(report)
	if md == "" {
		t.Error("empty markdown output")
	}
	if !contains(md, "/etc/hosts") {
		t.Error("markdown should contain blocked path")
	}
	if !contains(md, "api.github.com") {
		t.Error("markdown should contain network host")
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || contains(s[1:], substr)))
}
```

**Step 2: Run integration test**

Run: `go test ./internal/report/... -v -tags=integration -run TestReportIntegration`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/report/integration_test.go
git commit -m "test(report): add integration test"
```

---

## Task 7: Documentation - CLI Reference

**Files:**
- Modify: `docs/spec.md` or create `docs/cli-reference.md`

**Step 1: Add report command documentation**

Add the following section to CLI documentation:

```markdown
## agentsh report

Generate a markdown report summarizing session activity.

### Synopsis

```
agentsh report <session-id|latest> --level=<summary|detailed> [--output=<path>]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `session-id` | Session UUID to report on |
| `latest` | Use the most recent session |

### Flags

| Flag | Description |
|------|-------------|
| `--level` | Report detail level: `summary` (1 page) or `detailed` (full investigation) |
| `--output` | Write report to file instead of stdout |
| `--direct-db` | Query local database directly (offline mode) |
| `--db-path` | Path to events database (default: /var/lib/agentsh/events.db) |

### Examples

```bash
# Quick summary of latest session
agentsh report latest --level=summary

# Detailed investigation, save to file
agentsh report abc123-def4-5678 --level=detailed --output=report.md

# Pipe to pager
agentsh report latest --level=summary | less

# Offline mode (no server required)
agentsh report latest --level=summary --direct-db
```

### Report Levels

**Summary** (~1 page):
- Session overview (duration, policy, status)
- Decision counts (allowed, blocked, redirected, etc.)
- Key findings with severity indicators
- Top activity by category (files, network, commands)

**Detailed** (full investigation):
- Everything in summary
- Full event timeline
- Blocked operations table with rules and messages
- Redirect history
- Complete command history
- All file paths accessed
- All network hosts contacted

### Findings Detection

Reports automatically detect and highlight:

| Finding | Severity | Description |
|---------|----------|-------------|
| Blocked operations | Critical | Operations denied by policy |
| Denied approvals | Critical | Requests rejected by operator |
| Soft-deleted files | Warning | Files moved to trash |
| Sensitive path access | Warning | Access to credentials, SSH keys, etc. |
| Direct IP connections | Warning | Network to IPs instead of domains |
| Unusual ports | Warning | Connections to non-80/443 ports |
| High host diversity | Warning | >10 unique network destinations |
| Redirected operations | Info | Commands/paths substituted by policy |
| Granted approvals | Info | Operations approved by operator |
| Failed commands | Info | Non-zero exit codes |
```

**Step 2: Commit**

```bash
git add docs/
git commit -m "docs: add report command reference"
```

---

## Task 8: Documentation - CI/CD Integration Guide

**Files:**
- Create: `docs/cicd-integration.md`

**Step 1: Write CI/CD integration guide**

```markdown
# CI/CD Integration Guide

This guide shows how to integrate agentsh session reports into your CI/CD pipelines.

## Overview

When running AI agents in CI/CD pipelines, agentsh captures all activity for auditing. After the agent completes, generate a report to:

- Verify the agent behaved as expected
- Detect policy violations or anomalies
- Create an audit trail for compliance
- Debug failed runs

## GitHub Actions Example

```yaml
name: AI Agent Task

on:
  workflow_dispatch:
    inputs:
      task:
        description: 'Task for the AI agent'
        required: true

jobs:
  run-agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install agentsh
        run: |
          curl -fsSL https://agentsh.dev/install.sh | bash
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Start agentsh server
        run: |
          agentsh server start --background
          sleep 2

      - name: Create session
        id: session
        run: |
          SESSION=$(agentsh session create --workspace . --policy ci-agent | jq -r '.id')
          echo "id=$SESSION" >> $GITHUB_OUTPUT

      - name: Run AI agent
        env:
          AGENTSH_SESSION: ${{ steps.session.outputs.id }}
        run: |
          # Your AI agent command here
          agentsh exec $AGENTSH_SESSION -- your-agent-cli "${{ inputs.task }}"

      - name: Generate session report
        if: always()
        run: |
          agentsh report ${{ steps.session.outputs.id }} \
            --level=detailed \
            --output=session-report.md

      - name: Upload report as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agentsh-session-report
          path: session-report.md

      - name: Add report to job summary
        if: always()
        run: |
          echo "## Session Report" >> $GITHUB_STEP_SUMMARY
          cat session-report.md >> $GITHUB_STEP_SUMMARY

      - name: Cleanup session
        if: always()
        run: agentsh session destroy ${{ steps.session.outputs.id }}
```

## GitLab CI Example

```yaml
ai-agent-task:
  stage: build
  image: ubuntu:22.04
  variables:
    AGENTSH_SESSION: ""
  before_script:
    - curl -fsSL https://agentsh.dev/install.sh | bash
    - export PATH="$HOME/.local/bin:$PATH"
    - agentsh server start --background
    - sleep 2
    - export AGENTSH_SESSION=$(agentsh session create --workspace . --policy ci-agent | jq -r '.id')
  script:
    - agentsh exec $AGENTSH_SESSION -- your-agent-cli "do the task"
  after_script:
    - agentsh report $AGENTSH_SESSION --level=detailed --output=session-report.md
    - agentsh session destroy $AGENTSH_SESSION || true
  artifacts:
    when: always
    paths:
      - session-report.md
    reports:
      dotenv: agent.env
```

## CircleCI Example

```yaml
version: 2.1

jobs:
  run-agent:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install agentsh
          command: |
            curl -fsSL https://agentsh.dev/install.sh | bash
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> $BASH_ENV
      - run:
          name: Start server and create session
          command: |
            agentsh server start --background
            sleep 2
            SESSION=$(agentsh session create --workspace . | jq -r '.id')
            echo "export AGENTSH_SESSION=$SESSION" >> $BASH_ENV
      - run:
          name: Run AI agent
          command: |
            agentsh exec $AGENTSH_SESSION -- your-agent-cli "complete the task"
      - run:
          name: Generate report
          when: always
          command: |
            agentsh report $AGENTSH_SESSION --level=detailed --output=session-report.md
      - store_artifacts:
          path: session-report.md
          destination: session-report

workflows:
  agent-workflow:
    jobs:
      - run-agent
```

## Best Practices

### 1. Always Generate Reports

Use `if: always()` or `when: always` to ensure reports are generated even when the agent fails. Failed runs often have the most interesting findings.

### 2. Use Detailed Level for Artifacts

For artifact storage, use `--level=detailed` to capture the full investigation data. You can always skim the summary section.

### 3. Add to Job Summary (GitHub Actions)

Append the report to `$GITHUB_STEP_SUMMARY` for inline viewing without downloading artifacts.

### 4. Fail on Critical Findings

Add a step to parse the report and fail the build if critical findings are detected:

```yaml
- name: Check for violations
  run: |
    if grep -q "🔴" session-report.md; then
      echo "Critical findings detected!"
      exit 1
    fi
```

### 5. Policy Per Environment

Use different policies for different CI contexts:

```yaml
# For PR checks - stricter
agentsh session create --policy pr-check

# For deployment agents - more permissive but audited
agentsh session create --policy deploy-agent
```

### 6. Archive Reports for Compliance

Store reports in a compliance-friendly location:

```yaml
- name: Archive for compliance
  run: |
    DATE=$(date +%Y-%m-%d)
    aws s3 cp session-report.md s3://audit-logs/agentsh/$DATE/${{ github.run_id }}.md
```

## Troubleshooting

### "No sessions found"

The agentsh server may have restarted or the session timed out. Use `--direct-db` for offline access:

```bash
agentsh report latest --level=summary --direct-db --db-path=/path/to/events.db
```

### Report is empty or minimal

Check that your agent is actually running through agentsh:

```bash
# Wrong - agent runs outside agentsh
./my-agent

# Right - agent runs through agentsh
agentsh exec $SESSION -- ./my-agent
```

### Large reports

For very active sessions, the detailed report can be large. Consider:

```bash
# Summary for quick checks
agentsh report latest --level=summary

# Detailed only when investigating issues
agentsh report $SESSION --level=detailed --output=full-report.md
```
```

**Step 2: Commit**

```bash
git add docs/cicd-integration.md
git commit -m "docs: add CI/CD integration guide"
```

---

## Task 9: Update README

**Files:**
- Modify: `README.md`

**Step 1: Add report command to features/CLI section**

Find the CLI commands section and add:

```markdown
### Session Reports

Generate markdown reports summarizing session activity:

```bash
# Quick summary
agentsh report latest --level=summary

# Detailed investigation
agentsh report <session-id> --level=detailed --output=report.md
```

Reports include:
- Decision summary (allowed, blocked, redirected)
- Automatic findings detection (violations, anomalies)
- Activity breakdown by category
- Full event timeline (detailed mode)

See [CI/CD Integration Guide](docs/cicd-integration.md) for pipeline examples.
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add report command to README"
```

---

## Task 10: Final Verification

**Step 1: Run all tests**

```bash
go test ./... -v
```

Expected: All tests pass

**Step 2: Build and verify**

```bash
go build ./...
./agentsh report --help
```

Expected: Shows help with usage, flags, examples

**Step 3: Run linter (if configured)**

```bash
golangci-lint run ./...
```

Expected: No errors

**Step 4: Final commit and push**

```bash
git log --oneline -10  # Review commits
git push origin feature/session-report
```

---

## Summary

This plan creates the `agentsh report` command with:

1. **Data types** (`internal/report/types.go`) - Report structure and findings
2. **Findings detection** (`internal/report/findings.go`) - Anomaly and violation detection
3. **Report generator** (`internal/report/generator.go`) - Builds report from events
4. **Markdown formatter** (`internal/report/markdown.go`) - Renders report as markdown
5. **CLI command** (`internal/cli/report.go`) - User-facing command
6. **Integration tests** - End-to-end verification
7. **Documentation** - CLI reference and CI/CD guide
8. **README update** - Feature visibility

Total: 10 tasks, ~50 bite-sized steps
