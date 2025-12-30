//go:build integration

package report

import (
	"context"
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
