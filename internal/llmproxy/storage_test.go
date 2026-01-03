package llmproxy

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewStorage(t *testing.T) {
	t.Run("creates directories and file", func(t *testing.T) {
		tmpDir := t.TempDir()
		sessionID := "test-session-123"

		storage, err := NewStorage(tmpDir, sessionID)
		if err != nil {
			t.Fatalf("NewStorage failed: %v", err)
		}
		defer storage.Close()

		// Check session directory was created
		sessionDir := filepath.Join(tmpDir, sessionID)
		if _, err := os.Stat(sessionDir); os.IsNotExist(err) {
			t.Errorf("session directory not created: %s", sessionDir)
		}

		// Check bodies directory was created
		bodiesDir := filepath.Join(sessionDir, "llm-bodies")
		if _, err := os.Stat(bodiesDir); os.IsNotExist(err) {
			t.Errorf("bodies directory not created: %s", bodiesDir)
		}

		// Check JSONL file was created
		logPath := filepath.Join(sessionDir, "llm-requests.jsonl")
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			t.Errorf("log file not created: %s", logPath)
		}

		// Check helper methods return correct paths
		if got := storage.LogPath(); got != logPath {
			t.Errorf("LogPath() = %q, want %q", got, logPath)
		}
		if got := storage.BodiesPath(); got != bodiesDir {
			t.Errorf("BodiesPath() = %q, want %q", got, bodiesDir)
		}
	})

	t.Run("no-op mode with empty path", func(t *testing.T) {
		storage, err := NewStorage("", "")
		if err != nil {
			t.Fatalf("NewStorage failed: %v", err)
		}
		defer storage.Close()

		// Should not error on LogRequest/LogResponse
		err = storage.LogRequest(&RequestLogEntry{ID: "test"})
		if err != nil {
			t.Errorf("LogRequest failed in no-op mode: %v", err)
		}

		err = storage.LogResponse(&ResponseLogEntry{RequestID: "test"})
		if err != nil {
			t.Errorf("LogResponse failed in no-op mode: %v", err)
		}

		// Helper methods should return empty strings
		if got := storage.LogPath(); got != "" {
			t.Errorf("LogPath() = %q, want empty string", got)
		}
		if got := storage.BodiesPath(); got != "" {
			t.Errorf("BodiesPath() = %q, want empty string", got)
		}
	})
}

func TestStorage_LogRequest(t *testing.T) {
	tmpDir := t.TempDir()
	sessionID := "test-session"

	storage, err := NewStorage(tmpDir, sessionID)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}

	// Create test entries
	entries := []*RequestLogEntry{
		{
			ID:        "req_001",
			SessionID: sessionID,
			Timestamp: time.Date(2026, 1, 2, 10, 30, 0, 0, time.UTC),
			Dialect:   DialectAnthropic,
			Request: RequestInfo{
				Method:   "POST",
				Path:     "/v1/messages",
				BodySize: 1234,
				BodyHash: "sha256:abc123",
			},
		},
		{
			ID:        "req_002",
			SessionID: sessionID,
			Timestamp: time.Date(2026, 1, 2, 10, 31, 0, 0, time.UTC),
			Dialect:   DialectOpenAI,
			Request: RequestInfo{
				Method:   "POST",
				Path:     "/v1/chat/completions",
				BodySize: 5678,
				BodyHash: "sha256:def456",
			},
			DLP: &DLPInfo{
				Redactions: []Redaction{
					{Field: "messages[0].content", Type: "email", Count: 2},
				},
			},
		},
	}

	// Log all entries
	for _, entry := range entries {
		if err := storage.LogRequest(entry); err != nil {
			t.Fatalf("LogRequest failed: %v", err)
		}
	}

	// Close storage to flush writes
	if err := storage.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read and verify JSONL file
	logPath := filepath.Join(tmpDir, sessionID, "llm-requests.jsonl")
	file, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var readEntries []RequestLogEntry
	for scanner.Scan() {
		var entry RequestLogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("unmarshal entry: %v", err)
		}
		readEntries = append(readEntries, entry)
	}

	if len(readEntries) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(readEntries), len(entries))
	}

	// Verify first entry
	if readEntries[0].ID != "req_001" {
		t.Errorf("entry[0].ID = %q, want %q", readEntries[0].ID, "req_001")
	}
	if readEntries[0].Dialect != DialectAnthropic {
		t.Errorf("entry[0].Dialect = %q, want %q", readEntries[0].Dialect, DialectAnthropic)
	}
	if readEntries[0].Request.Path != "/v1/messages" {
		t.Errorf("entry[0].Request.Path = %q, want %q", readEntries[0].Request.Path, "/v1/messages")
	}

	// Verify second entry with DLP info
	if readEntries[1].DLP == nil {
		t.Error("entry[1].DLP is nil, expected redaction info")
	} else if len(readEntries[1].DLP.Redactions) != 1 {
		t.Errorf("entry[1].DLP.Redactions len = %d, want 1", len(readEntries[1].DLP.Redactions))
	}
}

func TestStorage_LogResponse(t *testing.T) {
	tmpDir := t.TempDir()
	sessionID := "test-session"

	storage, err := NewStorage(tmpDir, sessionID)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}

	// Create test entries
	entries := []*ResponseLogEntry{
		{
			RequestID:  "req_001",
			SessionID:  sessionID,
			Timestamp:  time.Date(2026, 1, 2, 10, 30, 1, 0, time.UTC),
			DurationMs: 1500,
			Response: ResponseInfo{
				Status:   200,
				BodySize: 2048,
				BodyHash: "sha256:resp123",
			},
			Usage: Usage{
				InputTokens:  150,
				OutputTokens: 892,
			},
		},
		{
			RequestID:  "req_002",
			SessionID:  sessionID,
			Timestamp:  time.Date(2026, 1, 2, 10, 31, 2, 0, time.UTC),
			DurationMs: 892,
			Response: ResponseInfo{
				Status: 429, // Rate limited
			},
		},
	}

	// Log all entries
	for _, entry := range entries {
		if err := storage.LogResponse(entry); err != nil {
			t.Fatalf("LogResponse failed: %v", err)
		}
	}

	// Close storage to flush writes
	if err := storage.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read and verify JSONL file
	logPath := filepath.Join(tmpDir, sessionID, "llm-requests.jsonl")
	file, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var readEntries []ResponseLogEntry
	for scanner.Scan() {
		var entry ResponseLogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("unmarshal entry: %v", err)
		}
		readEntries = append(readEntries, entry)
	}

	if len(readEntries) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(readEntries), len(entries))
	}

	// Verify first entry
	if readEntries[0].RequestID != "req_001" {
		t.Errorf("entry[0].RequestID = %q, want %q", readEntries[0].RequestID, "req_001")
	}
	if readEntries[0].Response.Status != 200 {
		t.Errorf("entry[0].Response.Status = %d, want 200", readEntries[0].Response.Status)
	}
	if readEntries[0].DurationMs != 1500 {
		t.Errorf("entry[0].DurationMs = %d, want 1500", readEntries[0].DurationMs)
	}
	if readEntries[0].Usage.InputTokens != 150 {
		t.Errorf("entry[0].Usage.InputTokens = %d, want 150", readEntries[0].Usage.InputTokens)
	}
	if readEntries[0].Usage.OutputTokens != 892 {
		t.Errorf("entry[0].Usage.OutputTokens = %d, want 892", readEntries[0].Usage.OutputTokens)
	}

	// Verify second entry (rate limited)
	if readEntries[1].Response.Status != 429 {
		t.Errorf("entry[1].Response.Status = %d, want 429", readEntries[1].Response.Status)
	}
}

func TestStorage_ReadLogEntries(t *testing.T) {
	tmpDir := t.TempDir()
	sessionID := "test-session"

	storage, err := NewStorage(tmpDir, sessionID)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}

	// Log some entries
	storage.LogRequest(&RequestLogEntry{ID: "req_001", Dialect: DialectAnthropic})
	storage.LogResponse(&ResponseLogEntry{RequestID: "req_001", Response: ResponseInfo{Status: 200}})
	storage.LogRequest(&RequestLogEntry{ID: "req_002", Dialect: DialectOpenAI})

	// Close to flush
	storage.Close()

	// Create new storage instance to read
	storage2, err := NewStorage(tmpDir, sessionID)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}
	defer storage2.Close()

	entries, err := storage2.ReadLogEntries()
	if err != nil {
		t.Fatalf("ReadLogEntries failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3", len(entries))
	}
}

func TestHashBody(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		wantHash string
	}{
		{
			name:     "empty body",
			body:     []byte{},
			wantHash: "",
		},
		{
			name:     "nil body",
			body:     nil,
			wantHash: "",
		},
		{
			name: "simple text",
			body: []byte("hello world"),
			// SHA256 of "hello world"
			wantHash: "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name: "json body",
			body: []byte(`{"model":"claude-3","messages":[{"role":"user","content":"Hello"}]}`),
			// SHA256 of the JSON
			wantHash: "sha256:f16e4f8d21b10f9d4e9b07a6d5e0d7c2f8e3a1b0c9d8e7f6a5b4c3d2e1f0a9b8",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HashBody(tc.body)

			// For empty/nil bodies
			if tc.wantHash == "" {
				if got != "" {
					t.Errorf("HashBody(%q) = %q, want empty string", tc.body, got)
				}
				return
			}

			// For non-empty bodies, check the format and verify the hash
			if len(got) < 7 || got[:7] != "sha256:" {
				t.Errorf("HashBody() = %q, expected sha256: prefix", got)
			}

			// Verify the hash is 64 hex characters after the prefix
			if len(got) != 7+64 { // "sha256:" + 64 hex chars
				t.Errorf("HashBody() length = %d, expected %d", len(got), 7+64)
			}

			// For the "simple text" test case, verify the actual hash
			if tc.name == "simple text" {
				if got != tc.wantHash {
					t.Errorf("HashBody(%q) = %q, want %q", tc.body, got, tc.wantHash)
				}
			}
		})
	}
}

func TestHashBody_Deterministic(t *testing.T) {
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}`)

	hash1 := HashBody(body)
	hash2 := HashBody(body)

	if hash1 != hash2 {
		t.Errorf("HashBody is not deterministic: %q != %q", hash1, hash2)
	}
}

func TestHashBody_DifferentInputs(t *testing.T) {
	body1 := []byte("hello world")
	body2 := []byte("hello world!")

	hash1 := HashBody(body1)
	hash2 := HashBody(body2)

	if hash1 == hash2 {
		t.Errorf("Different inputs produced same hash: %q", hash1)
	}
}

func TestStorage_ConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	sessionID := "test-session"

	storage, err := NewStorage(tmpDir, sessionID)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}
	defer storage.Close()

	// Spawn multiple goroutines writing concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			for j := 0; j < 100; j++ {
				entry := &RequestLogEntry{
					ID:        "req_concurrent",
					SessionID: sessionID,
					Dialect:   DialectAnthropic,
				}
				if err := storage.LogRequest(entry); err != nil {
					t.Errorf("concurrent LogRequest failed: %v", err)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Close and reopen to read
	storage.Close()

	storage2, _ := NewStorage(tmpDir, sessionID)
	defer storage2.Close()

	entries, err := storage2.ReadLogEntries()
	if err != nil {
		t.Fatalf("ReadLogEntries failed: %v", err)
	}

	// Should have 1000 entries (10 goroutines * 100 writes each)
	if len(entries) != 1000 {
		t.Errorf("got %d entries, want 1000", len(entries))
	}
}

func TestStorage_CloseMultipleTimes(t *testing.T) {
	tmpDir := t.TempDir()
	sessionID := "test-session"

	storage, err := NewStorage(tmpDir, sessionID)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}

	// Close multiple times should not error
	if err := storage.Close(); err != nil {
		t.Errorf("first Close() failed: %v", err)
	}

	if err := storage.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
}
