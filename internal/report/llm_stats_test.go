package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLLMRequestsFile(t *testing.T) {
	t.Run("file not found returns nil stats", func(t *testing.T) {
		llmStats, dlpStats, err := ParseLLMRequestsFile("/nonexistent/file.jsonl")
		if err != nil {
			t.Errorf("expected nil error for missing file, got: %v", err)
		}
		if llmStats != nil {
			t.Error("expected nil llmStats for missing file")
		}
		if dlpStats != nil {
			t.Error("expected nil dlpStats for missing file")
		}
	})

	t.Run("empty file returns nil stats", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "llm-requests.jsonl")
		if err := os.WriteFile(logPath, []byte(""), 0600); err != nil {
			t.Fatalf("write test file: %v", err)
		}

		llmStats, dlpStats, err := ParseLLMRequestsFile(logPath)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if llmStats != nil {
			t.Error("expected nil llmStats for empty file")
		}
		if dlpStats != nil {
			t.Error("expected nil dlpStats for empty file")
		}
	})

	t.Run("parses request and response entries", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "llm-requests.jsonl")

		// Write test data - request followed by response
		testData := `{"id":"req_001","session_id":"sess_123","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"}}
{"request_id":"req_001","session_id":"sess_123","duration_ms":1500,"response":{"status":200},"usage":{"input_tokens":150,"output_tokens":892}}
{"id":"req_002","session_id":"sess_123","dialect":"openai","request":{"method":"POST","path":"/v1/chat/completions"}}
{"request_id":"req_002","session_id":"sess_123","duration_ms":892,"response":{"status":200},"usage":{"input_tokens":100,"output_tokens":500}}
`
		if err := os.WriteFile(logPath, []byte(testData), 0600); err != nil {
			t.Fatalf("write test file: %v", err)
		}

		llmStats, dlpStats, err := ParseLLMRequestsFile(logPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if llmStats == nil {
			t.Fatal("expected llmStats to be populated")
		}

		// Should have 2 providers
		if len(llmStats.Providers) != 2 {
			t.Errorf("expected 2 providers, got %d", len(llmStats.Providers))
		}

		// Check totals
		if llmStats.Total.Requests != 2 {
			t.Errorf("expected 2 total requests, got %d", llmStats.Total.Requests)
		}
		if llmStats.Total.TokensIn != 250 {
			t.Errorf("expected 250 total tokens in, got %d", llmStats.Total.TokensIn)
		}
		if llmStats.Total.TokensOut != 1392 {
			t.Errorf("expected 1392 total tokens out, got %d", llmStats.Total.TokensOut)
		}
		if llmStats.Total.Errors != 0 {
			t.Errorf("expected 0 errors, got %d", llmStats.Total.Errors)
		}

		// No DLP events in this test
		if dlpStats != nil {
			t.Error("expected nil dlpStats for data without DLP")
		}
	})

	t.Run("counts errors correctly", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "llm-requests.jsonl")

		testData := `{"id":"req_001","session_id":"sess_123","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"}}
{"request_id":"req_001","session_id":"sess_123","duration_ms":100,"response":{"status":429}}
{"id":"req_002","session_id":"sess_123","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"}}
{"request_id":"req_002","session_id":"sess_123","duration_ms":1500,"response":{"status":200},"usage":{"input_tokens":150,"output_tokens":892}}
{"id":"req_003","session_id":"sess_123","dialect":"openai","request":{"method":"POST","path":"/v1/chat/completions"}}
{"request_id":"req_003","session_id":"sess_123","duration_ms":50,"response":{"status":500}}
`
		if err := os.WriteFile(logPath, []byte(testData), 0600); err != nil {
			t.Fatalf("write test file: %v", err)
		}

		llmStats, _, err := ParseLLMRequestsFile(logPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if llmStats == nil {
			t.Fatal("expected llmStats to be populated")
		}

		// Check total errors
		if llmStats.Total.Errors != 2 {
			t.Errorf("expected 2 total errors, got %d", llmStats.Total.Errors)
		}

		// Check per-provider errors
		for _, p := range llmStats.Providers {
			if p.Provider == "Anthropic" && p.Errors != 1 {
				t.Errorf("expected 1 Anthropic error, got %d", p.Errors)
			}
			if p.Provider == "OpenAI" && p.Errors != 1 {
				t.Errorf("expected 1 OpenAI error, got %d", p.Errors)
			}
		}
	})

	t.Run("parses DLP redactions", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "llm-requests.jsonl")

		testData := `{"id":"req_001","session_id":"sess_123","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"},"dlp":{"redactions":[{"type":"email","count":5},{"type":"phone","count":2}]}}
{"request_id":"req_001","session_id":"sess_123","duration_ms":1500,"response":{"status":200},"usage":{"input_tokens":150,"output_tokens":892}}
{"id":"req_002","session_id":"sess_123","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"},"dlp":{"redactions":[{"type":"email","count":3}]}}
{"request_id":"req_002","session_id":"sess_123","duration_ms":1000,"response":{"status":200},"usage":{"input_tokens":100,"output_tokens":500}}
`
		if err := os.WriteFile(logPath, []byte(testData), 0600); err != nil {
			t.Fatalf("write test file: %v", err)
		}

		_, dlpStats, err := ParseLLMRequestsFile(logPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if dlpStats == nil {
			t.Fatal("expected dlpStats to be populated")
		}

		// Check total redactions
		if dlpStats.Total != 10 {
			t.Errorf("expected 10 total redactions, got %d", dlpStats.Total)
		}

		// Check redaction counts by type
		if len(dlpStats.Redactions) != 2 {
			t.Fatalf("expected 2 redaction types, got %d", len(dlpStats.Redactions))
		}

		for _, r := range dlpStats.Redactions {
			switch r.Type {
			case "email":
				if r.Count != 8 { // 5 + 3
					t.Errorf("expected 8 email redactions, got %d", r.Count)
				}
			case "phone":
				if r.Count != 2 {
					t.Errorf("expected 2 phone redactions, got %d", r.Count)
				}
			default:
				t.Errorf("unexpected redaction type: %s", r.Type)
			}
		}
	})

	t.Run("handles malformed lines gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "llm-requests.jsonl")

		testData := `{"id":"req_001","session_id":"sess_123","dialect":"anthropic","request":{"method":"POST","path":"/v1/messages"}}
{malformed json line}
{"request_id":"req_001","session_id":"sess_123","duration_ms":1500,"response":{"status":200},"usage":{"input_tokens":150,"output_tokens":892}}
`
		if err := os.WriteFile(logPath, []byte(testData), 0600); err != nil {
			t.Fatalf("write test file: %v", err)
		}

		llmStats, _, err := ParseLLMRequestsFile(logPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should still parse the valid entries
		if llmStats == nil {
			t.Fatal("expected llmStats to be populated despite malformed line")
		}
		if llmStats.Total.Requests != 1 {
			t.Errorf("expected 1 request, got %d", llmStats.Total.Requests)
		}
	})

	t.Run("response without matching request uses unknown provider", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "llm-requests.jsonl")

		// Response without a corresponding request
		testData := `{"request_id":"orphan_req","session_id":"sess_123","duration_ms":1500,"response":{"status":200},"usage":{"input_tokens":150,"output_tokens":892}}
`
		if err := os.WriteFile(logPath, []byte(testData), 0600); err != nil {
			t.Fatalf("write test file: %v", err)
		}

		llmStats, _, err := ParseLLMRequestsFile(logPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if llmStats == nil {
			t.Fatal("expected llmStats to be populated")
		}

		// Should be categorized as "Unknown"
		if len(llmStats.Providers) != 1 {
			t.Fatalf("expected 1 provider, got %d", len(llmStats.Providers))
		}
		if llmStats.Providers[0].Provider != "Unknown" {
			t.Errorf("expected 'Unknown' provider, got %s", llmStats.Providers[0].Provider)
		}
	})
}

func TestFormatProviderName(t *testing.T) {
	tests := []struct {
		dialect string
		want    string
	}{
		{"anthropic", "Anthropic"},
		{"openai", "OpenAI"},
		{"chatgpt", "ChatGPT"},
		{"unknown", "Unknown"},
		{"", "Unknown"},
		{"custom-provider", "custom-provider"},
	}

	for _, tc := range tests {
		t.Run(tc.dialect, func(t *testing.T) {
			got := formatProviderName(tc.dialect)
			if got != tc.want {
				t.Errorf("formatProviderName(%q) = %q, want %q", tc.dialect, got, tc.want)
			}
		})
	}
}
