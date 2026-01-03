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

func TestFormatMarkdown_LLMUsage(t *testing.T) {
	report := &Report{
		SessionID:   "test-123",
		GeneratedAt: time.Now(),
		Level:       LevelSummary,
		Session:     types.Session{ID: "test-123"},
		LLMUsage: &LLMUsageStats{
			Providers: []ProviderUsage{
				{Provider: "Anthropic", Requests: 45, TokensIn: 12450, TokensOut: 34200, Errors: 0},
				{Provider: "OpenAI", Requests: 3, TokensIn: 600, TokensOut: 1500, Errors: 1},
			},
			Total: UsageTotals{
				Requests:  48,
				TokensIn:  13050,
				TokensOut: 35700,
				Errors:    1,
			},
		},
	}

	md := FormatMarkdown(report)

	// Check LLM Usage section exists
	if !strings.Contains(md, "## LLM Usage") {
		t.Error("missing LLM Usage section")
	}

	// Check table headers
	if !strings.Contains(md, "| Provider | Requests | Tokens In | Tokens Out | Errors |") {
		t.Error("missing LLM Usage table headers")
	}

	// Check Anthropic row with formatted numbers
	if !strings.Contains(md, "| Anthropic |") {
		t.Error("missing Anthropic provider row")
	}
	if !strings.Contains(md, "12,450") {
		t.Error("missing formatted tokens in for Anthropic")
	}
	if !strings.Contains(md, "34,200") {
		t.Error("missing formatted tokens out for Anthropic")
	}

	// Check OpenAI row
	if !strings.Contains(md, "| OpenAI |") {
		t.Error("missing OpenAI provider row")
	}

	// Check totals row (should exist since multiple providers)
	if !strings.Contains(md, "| **Total** |") {
		t.Error("missing totals row")
	}
}

func TestFormatMarkdown_DLPEvents(t *testing.T) {
	report := &Report{
		SessionID:   "test-123",
		GeneratedAt: time.Now(),
		Level:       LevelSummary,
		Session:     types.Session{ID: "test-123"},
		DLPEvents: &DLPEventStats{
			Redactions: []RedactionCount{
				{Type: "email", Count: 12},
				{Type: "phone", Count: 3},
			},
			Total: 15,
		},
	}

	md := FormatMarkdown(report)

	// Check DLP Events section exists
	if !strings.Contains(md, "## DLP Events") {
		t.Error("missing DLP Events section")
	}

	// Check table headers
	if !strings.Contains(md, "| Type | Redactions |") {
		t.Error("missing DLP Events table headers")
	}

	// Check redaction types
	if !strings.Contains(md, "| email | 12 |") {
		t.Error("missing email redaction row")
	}
	if !strings.Contains(md, "| phone | 3 |") {
		t.Error("missing phone redaction row")
	}

	// Check total row (should exist since multiple types)
	if !strings.Contains(md, "| **Total** | **15** |") {
		t.Error("missing DLP total row")
	}
}

func TestFormatMarkdown_NoLLMStats(t *testing.T) {
	report := &Report{
		SessionID:   "test-123",
		GeneratedAt: time.Now(),
		Level:       LevelSummary,
		Session:     types.Session{ID: "test-123"},
		// No LLMUsage or DLPEvents
	}

	md := FormatMarkdown(report)

	// Should not contain these sections
	if strings.Contains(md, "## LLM Usage") {
		t.Error("should not contain LLM Usage section when no data")
	}
	if strings.Contains(md, "## DLP Events") {
		t.Error("should not contain DLP Events section when no data")
	}
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{12, "12"},
		{123, "123"},
		{999, "999"},
		{1000, "1,000"},
		{1234, "1,234"},
		{12345, "12,345"},
		{123456, "123,456"},
		{1234567, "1,234,567"},
		{12345678, "12,345,678"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := formatNumber(tc.input)
			if got != tc.want {
				t.Errorf("formatNumber(%d) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
