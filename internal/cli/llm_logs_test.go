package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadLLMLogs(t *testing.T) {
	t.Run("empty reader returns nil", func(t *testing.T) {
		rows, err := ReadLLMLogs(strings.NewReader(""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("expected 0 rows, got %d", len(rows))
		}
	})

	t.Run("parses request and response entries", func(t *testing.T) {
		input := `{"id":"req_001","timestamp":"2026-01-04T10:30:01Z","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"}}
{"request_id":"req_001","timestamp":"2026-01-04T10:30:02Z","duration_ms":1200,"response":{"status":200},"usage":{"input_tokens":150,"output_tokens":892}}
`
		rows, err := ReadLLMLogs(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}

		row := rows[0]
		if row.ID != "req_001" {
			t.Errorf("expected ID req_001, got %s", row.ID)
		}
		if row.Dialect != "anthropic" {
			t.Errorf("expected dialect anthropic, got %s", row.Dialect)
		}
		if row.Path != "/v1/messages" {
			t.Errorf("expected path /v1/messages, got %s", row.Path)
		}
		if row.Status != 200 {
			t.Errorf("expected status 200, got %d", row.Status)
		}
		if row.DurationMs != 1200 {
			t.Errorf("expected duration 1200ms, got %d", row.DurationMs)
		}
		if row.InputTokens != 150 {
			t.Errorf("expected 150 input tokens, got %d", row.InputTokens)
		}
		if row.OutputTokens != 892 {
			t.Errorf("expected 892 output tokens, got %d", row.OutputTokens)
		}
	})

	t.Run("counts redactions", func(t *testing.T) {
		input := `{"id":"req_001","timestamp":"2026-01-04T10:30:01Z","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"},"dlp":{"redactions":[{"type":"email","count":3},{"type":"phone","count":2}]}}
{"request_id":"req_001","timestamp":"2026-01-04T10:30:02Z","duration_ms":1000,"response":{"status":200},"usage":{"input_tokens":100,"output_tokens":500}}
`
		rows, err := ReadLLMLogs(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}

		if rows[0].Redactions != 5 {
			t.Errorf("expected 5 redactions (3+2), got %d", rows[0].Redactions)
		}
	})

	t.Run("handles multiple requests", func(t *testing.T) {
		input := `{"id":"req_001","timestamp":"2026-01-04T10:30:01Z","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"}}
{"request_id":"req_001","timestamp":"2026-01-04T10:30:02Z","duration_ms":1200,"response":{"status":200},"usage":{"input_tokens":150,"output_tokens":892}}
{"id":"req_002","timestamp":"2026-01-04T10:30:15Z","dialect":"openai","request":{"method":"POST","path":"/v1/chat/completions"}}
{"request_id":"req_002","timestamp":"2026-01-04T10:30:17Z","duration_ms":2100,"response":{"status":200},"usage":{"input_tokens":200,"output_tokens":1024}}
`
		rows, err := ReadLLMLogs(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(rows) != 2 {
			t.Fatalf("expected 2 rows, got %d", len(rows))
		}

		if rows[0].ID != "req_001" || rows[0].Dialect != "anthropic" {
			t.Errorf("row 0: expected req_001/anthropic, got %s/%s", rows[0].ID, rows[0].Dialect)
		}
		if rows[1].ID != "req_002" || rows[1].Dialect != "openai" {
			t.Errorf("row 1: expected req_002/openai, got %s/%s", rows[1].ID, rows[1].Dialect)
		}
	})

	t.Run("handles orphan response", func(t *testing.T) {
		input := `{"request_id":"orphan","timestamp":"2026-01-04T10:30:02Z","duration_ms":1000,"response":{"status":200},"usage":{"input_tokens":100,"output_tokens":500}}
`
		rows, err := ReadLLMLogs(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}

		if rows[0].ID != "orphan" {
			t.Errorf("expected ID orphan, got %s", rows[0].ID)
		}
		if rows[0].Dialect != "unknown" {
			t.Errorf("expected dialect unknown, got %s", rows[0].Dialect)
		}
	})

	t.Run("skips malformed lines", func(t *testing.T) {
		input := `{"id":"req_001","timestamp":"2026-01-04T10:30:01Z","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"}}
{malformed json}
{"request_id":"req_001","timestamp":"2026-01-04T10:30:02Z","duration_ms":1000,"response":{"status":200},"usage":{"input_tokens":100,"output_tokens":500}}
`
		rows, err := ReadLLMLogs(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row (malformed line skipped), got %d", len(rows))
		}
	})
}

func TestFormatLLMLogRow(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339, "2026-01-04T10:30:01Z")

	t.Run("basic format", func(t *testing.T) {
		row := LLMLogRow{
			ID:           "req_001",
			Timestamp:    ts,
			Dialect:      "anthropic",
			Path:         "/v1/messages",
			Status:       200,
			DurationMs:   1200,
			InputTokens:  150,
			OutputTokens: 892,
		}

		result := FormatLLMLogRow(row)

		if !strings.Contains(result, "req_001") {
			t.Errorf("expected req_001 in output: %s", result)
		}
		if !strings.Contains(result, "10:30:01") {
			t.Errorf("expected 10:30:01 in output: %s", result)
		}
		if !strings.Contains(result, "anthropic") {
			t.Errorf("expected anthropic in output: %s", result)
		}
		if !strings.Contains(result, "/v1/messages") {
			t.Errorf("expected /v1/messages in output: %s", result)
		}
		if !strings.Contains(result, "200") {
			t.Errorf("expected 200 in output: %s", result)
		}
		if !strings.Contains(result, "1.2s") {
			t.Errorf("expected 1.2s in output: %s", result)
		}
		if !strings.Contains(result, "150→892 tokens") {
			t.Errorf("expected 150→892 tokens in output: %s", result)
		}
		if strings.Contains(result, "redactions") {
			t.Errorf("should not contain redactions when 0: %s", result)
		}
	})

	t.Run("with redactions", func(t *testing.T) {
		row := LLMLogRow{
			ID:           "req_002",
			Timestamp:    ts,
			Dialect:      "anthropic",
			Path:         "/v1/messages",
			Status:       200,
			DurationMs:   800,
			InputTokens:  892,
			OutputTokens: 456,
			Redactions:   5,
		}

		result := FormatLLMLogRow(row)

		if !strings.Contains(result, "[5 redactions]") {
			t.Errorf("expected [5 redactions] in output: %s", result)
		}
	})
}

func TestReadLLMLogsFromFile(t *testing.T) {
	t.Run("file not found returns nil", func(t *testing.T) {
		rows, err := ReadLLMLogsFromFile("/nonexistent/path/file.jsonl")
		if err != nil {
			t.Fatalf("expected nil error for missing file, got: %v", err)
		}
		if rows != nil {
			t.Error("expected nil rows for missing file")
		}
	})

	t.Run("reads from file", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "llm-requests.jsonl")

		content := `{"id":"req_001","timestamp":"2026-01-04T10:30:01Z","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"}}
{"request_id":"req_001","timestamp":"2026-01-04T10:30:02Z","duration_ms":1200,"response":{"status":200},"usage":{"input_tokens":150,"output_tokens":892}}
`
		if err := os.WriteFile(logPath, []byte(content), 0600); err != nil {
			t.Fatalf("write test file: %v", err)
		}

		rows, err := ReadLLMLogsFromFile(logPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
	})
}

func TestDisplayLLMLogs(t *testing.T) {
	t.Run("session not found", func(t *testing.T) {
		var buf bytes.Buffer
		err := DisplayLLMLogs(&buf, "nonexistent-session", false)
		if err == nil {
			t.Error("expected error for nonexistent session")
		}
	})
}

func TestTruncatePath(t *testing.T) {
	tests := []struct {
		path   string
		maxLen int
		want   string
	}{
		{"/v1/messages", 25, "/v1/messages"},
		{"/v1/chat/completions", 25, "/v1/chat/completions"},
		{"/very/long/path/that/exceeds/limit", 20, ".../that/exceeds/limit"},
	}

	for _, tt := range tests {
		got := truncatePath(tt.path, tt.maxLen)
		if len(got) > tt.maxLen {
			t.Errorf("truncatePath(%q, %d) = %q (len %d), exceeds maxLen", tt.path, tt.maxLen, got, len(got))
		}
	}
}
