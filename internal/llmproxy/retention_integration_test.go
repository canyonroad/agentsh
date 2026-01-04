//go:build integration

package llmproxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionIntegration_RealCleanup(t *testing.T) {
	// Create a temp sessions directory
	sessionsDir := t.TempDir()

	// Create sessions with various ages
	sessions := []struct {
		name    string
		ageDays int
		sizeMB  float64
	}{
		{"session-very-old", 60, 0.1},    // 60 days old, 100KB
		{"session-old", 35, 0.2},          // 35 days old, 200KB
		{"session-recent", 10, 0.15},      // 10 days old, 150KB
		{"session-new", 1, 0.05},          // 1 day old, 50KB
		{"session-current", 0, 0.1},       // current session
	}

	for _, s := range sessions {
		sessionPath := filepath.Join(sessionsDir, s.name)
		if err := os.MkdirAll(sessionPath, 0755); err != nil {
			t.Fatalf("create session dir: %v", err)
		}

		// Create llm-requests.jsonl with some data
		dataFile := filepath.Join(sessionPath, "llm-requests.jsonl")
		dataSize := int(s.sizeMB * 1024 * 1024)
		data := make([]byte, dataSize)
		if err := os.WriteFile(dataFile, data, 0644); err != nil {
			t.Fatalf("write data file: %v", err)
		}

		// Set modification time
		mtime := time.Now().Add(-time.Duration(s.ageDays) * 24 * time.Hour)
		if err := os.Chtimes(sessionPath, mtime, mtime); err != nil {
			t.Fatalf("set mtime: %v", err)
		}
	}

	// Verify all sessions exist
	entries, _ := os.ReadDir(sessionsDir)
	t.Logf("Before cleanup: %d sessions", len(entries))
	for _, e := range entries {
		info, _ := e.Info()
		t.Logf("  - %s (mtime: %s)", e.Name(), info.ModTime().Format("2006-01-02"))
	}

	// Run retention with 30-day max age
	config := RetentionConfig{
		MaxAgeDays: 30,
		Eviction:   "oldest_first",
	}

	result, err := RunRetention(sessionsDir, config, "session-current", nil)
	if err != nil {
		t.Fatalf("RunRetention: %v", err)
	}

	t.Logf("Cleanup result: removed=%d, reclaimed=%d bytes",
		result.SessionsRemoved, result.BytesReclaimed)
	t.Logf("Removed sessions: %v", result.Sessions)

	// Verify results
	if result.SessionsRemoved != 2 {
		t.Errorf("expected 2 sessions removed (very-old and old), got %d", result.SessionsRemoved)
	}

	// Verify old sessions are gone
	if _, err := os.Stat(filepath.Join(sessionsDir, "session-very-old")); !os.IsNotExist(err) {
		t.Error("session-very-old should have been removed")
	}
	if _, err := os.Stat(filepath.Join(sessionsDir, "session-old")); !os.IsNotExist(err) {
		t.Error("session-old should have been removed")
	}

	// Verify recent sessions still exist
	if _, err := os.Stat(filepath.Join(sessionsDir, "session-recent")); os.IsNotExist(err) {
		t.Error("session-recent should still exist")
	}
	if _, err := os.Stat(filepath.Join(sessionsDir, "session-new")); os.IsNotExist(err) {
		t.Error("session-new should still exist")
	}
	if _, err := os.Stat(filepath.Join(sessionsDir, "session-current")); os.IsNotExist(err) {
		t.Error("session-current should still exist (protected)")
	}

	// Final state
	entries, _ = os.ReadDir(sessionsDir)
	t.Logf("After cleanup: %d sessions", len(entries))
	for _, e := range entries {
		t.Logf("  - %s", e.Name())
	}
}

func TestRetentionIntegration_SizeBasedCleanup(t *testing.T) {
	sessionsDir := t.TempDir()

	// Create sessions with different sizes
	// Total: 2.5MB, quota: 1MB
	sessions := []struct {
		name    string
		ageDays int
		sizeMB  float64
	}{
		{"session-a", 5, 0.5},   // oldest, 0.5MB
		{"session-b", 3, 1.0},   // middle, 1MB
		{"session-c", 1, 1.0},   // newest, 1MB
	}

	for _, s := range sessions {
		sessionPath := filepath.Join(sessionsDir, s.name)
		if err := os.MkdirAll(sessionPath, 0755); err != nil {
			t.Fatalf("create session dir: %v", err)
		}

		dataFile := filepath.Join(sessionPath, "data.jsonl")
		dataSize := int(s.sizeMB * 1024 * 1024)
		if err := os.WriteFile(dataFile, make([]byte, dataSize), 0644); err != nil {
			t.Fatalf("write data: %v", err)
		}

		mtime := time.Now().Add(-time.Duration(s.ageDays) * 24 * time.Hour)
		if err := os.Chtimes(sessionPath, mtime, mtime); err != nil {
			t.Fatalf("set mtime: %v", err)
		}
	}

	t.Log("Before cleanup:")
	for _, s := range sessions {
		t.Logf("  - %s: %.1fMB, %d days old", s.name, s.sizeMB, s.ageDays)
	}

	// Run with 1MB quota and oldest_first eviction
	config := RetentionConfig{
		MaxSizeMB: 1,
		Eviction:  "oldest_first",
	}

	result, err := RunRetention(sessionsDir, config, "", nil)
	if err != nil {
		t.Fatalf("RunRetention: %v", err)
	}

	t.Logf("Removed %d sessions, reclaimed %.2fMB",
		result.SessionsRemoved, float64(result.BytesReclaimed)/(1024*1024))

	// Should remove oldest (session-a: 0.5MB) then session-b (1MB)
	// Leaving session-c (1MB) which is under quota
	entries, _ := os.ReadDir(sessionsDir)
	t.Logf("Remaining sessions: %d", len(entries))
	for _, e := range entries {
		t.Logf("  - %s", e.Name())
	}

	// session-c should remain
	if _, err := os.Stat(filepath.Join(sessionsDir, "session-c")); os.IsNotExist(err) {
		t.Error("session-c (newest) should still exist")
	}
}

func TestRetentionIntegration_LargestFirstEviction(t *testing.T) {
	sessionsDir := t.TempDir()

	// Create sessions: total 3MB, quota 1.5MB
	sessions := []struct {
		name   string
		sizeMB float64
	}{
		{"small", 0.5},
		{"medium", 1.0},
		{"large", 1.5},
	}

	for _, s := range sessions {
		sessionPath := filepath.Join(sessionsDir, s.name)
		os.MkdirAll(sessionPath, 0755)
		dataFile := filepath.Join(sessionPath, "data.jsonl")
		os.WriteFile(dataFile, make([]byte, int(s.sizeMB*1024*1024)), 0644)
	}

	config := RetentionConfig{
		MaxSizeMB: 1, // 1MB quota - need to remove large (1.5MB) and medium (1MB) to get to small (0.5MB)
		Eviction:  "largest_first",
	}

	result, err := RunRetention(sessionsDir, config, "", nil)
	if err != nil {
		t.Fatalf("RunRetention: %v", err)
	}

	t.Logf("Removed: %v", result.Sessions)

	// With largest_first: should remove "large" first, then "medium"
	// Leaving "small" (0.5MB) under 1MB quota
	if _, err := os.Stat(filepath.Join(sessionsDir, "small")); os.IsNotExist(err) {
		t.Error("small session should remain")
	}
}
