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
