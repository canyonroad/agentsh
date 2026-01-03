package llmproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

// TestProxy_AnthropicPassthrough tests that requests are correctly
// proxied to an Anthropic-compatible upstream server.
func TestProxy_AnthropicPassthrough(t *testing.T) {
	// Create a mock upstream server that returns an Anthropic-style response
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request was correctly rewritten
		if r.URL.Path != "/v1/messages" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		// Check that the API key header was passed through
		if r.Header.Get("x-api-key") == "" {
			t.Error("x-api-key header not passed through")
		}

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}

		// Verify the body contains the expected message
		if !strings.Contains(string(body), "Hello, Claude") {
			t.Errorf("unexpected request body: %s", string(body))
		}

		// Return an Anthropic-style response with usage info
		resp := map[string]interface{}{
			"id":   "msg_01XFDUDYJgAACzvnptvVoYEL",
			"type": "message",
			"role": "assistant",
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": "Hello! How can I assist you today?",
				},
			},
			"model":        "claude-sonnet-4-20250514",
			"stop_reason":  "end_turn",
			"stop_sequence": nil,
			"usage": map[string]int{
				"input_tokens":  10,
				"output_tokens": 25,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer upstream.Close()

	// Create temp directory for storage
	storageDir := t.TempDir()

	// Create proxy with upstream override pointing to our mock server
	cfg := Config{
		SessionID: "test-session-123",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0, // Auto-select port
			Upstreams: config.ProxyUpstreamsConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DefaultDLPConfig(),
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := proxy.Stop(shutdownCtx); err != nil {
			t.Errorf("failed to stop proxy: %v", err)
		}
	}()

	// Wait for proxy to be ready
	time.Sleep(10 * time.Millisecond)

	// Make a request to the proxy
	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	reqBody := `{"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": "Hello, Claude!"}]}`
	req, err := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test-key")
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Read and parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify the response content
	if result["type"] != "message" {
		t.Errorf("unexpected response type: %v", result["type"])
	}

	usage, ok := result["usage"].(map[string]interface{})
	if !ok {
		t.Fatal("usage not found in response")
	}
	if usage["input_tokens"].(float64) != 10 {
		t.Errorf("unexpected input_tokens: %v", usage["input_tokens"])
	}
	if usage["output_tokens"].(float64) != 25 {
		t.Errorf("unexpected output_tokens: %v", usage["output_tokens"])
	}

	// Allow time for async logging
	time.Sleep(50 * time.Millisecond)

	// Verify storage logged the request and response
	entries, err := proxy.storage.ReadLogEntries()
	if err != nil {
		t.Fatalf("failed to read log entries: %v", err)
	}

	if len(entries) < 2 {
		t.Fatalf("expected at least 2 log entries (request + response), got %d", len(entries))
	}

	// Verify the response entry contains usage data
	var responseEntry ResponseLogEntry
	if err := json.Unmarshal(entries[1], &responseEntry); err != nil {
		t.Fatalf("failed to parse response entry: %v", err)
	}

	if responseEntry.Usage.InputTokens != 10 {
		t.Errorf("expected input_tokens 10 in log, got %d", responseEntry.Usage.InputTokens)
	}
	if responseEntry.Usage.OutputTokens != 25 {
		t.Errorf("expected output_tokens 25 in log, got %d", responseEntry.Usage.OutputTokens)
	}
}

// TestProxy_DLPRedaction tests that DLP correctly redacts PII from requests.
func TestProxy_DLPRedaction(t *testing.T) {
	var receivedBody []byte

	// Create a mock upstream server that captures the request body
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}
		receivedBody = body

		// Return a minimal response
		resp := map[string]interface{}{
			"id":   "msg_test",
			"type": "message",
			"usage": map[string]int{
				"input_tokens":  5,
				"output_tokens": 10,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	// Create temp directory for storage
	storageDir := t.TempDir()

	// Create proxy with DLP enabled
	cfg := Config{
		SessionID: "test-session-dlp",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Upstreams: config.ProxyUpstreamsConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{
			Mode: "redact",
			Patterns: config.DLPPatternsConfig{
				Email:      true,
				Phone:      true,
				CreditCard: true,
				SSN:        true,
				APIKeys:    false, // Disable API key detection to avoid false positives
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	// Wait for proxy to be ready
	time.Sleep(10 * time.Millisecond)

	// Request body with PII that should be redacted
	originalEmail := "john.doe@example.com"
	originalPhone := "555-123-4567"
	originalSSN := "123-45-6789"

	reqBody := map[string]interface{}{
		"model": "claude-sonnet-4-20250514",
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": "Please contact john.doe@example.com or call 555-123-4567. My SSN is 123-45-6789.",
			},
		},
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	req, err := http.NewRequest(http.MethodPost, proxyURL, bytes.NewReader(reqJSON))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test-key")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Verify the upstream received redacted content
	receivedStr := string(receivedBody)

	// Check that original PII is NOT in the received body
	if strings.Contains(receivedStr, originalEmail) {
		t.Error("email was NOT redacted - found in upstream request")
	}
	if strings.Contains(receivedStr, originalPhone) {
		t.Error("phone was NOT redacted - found in upstream request")
	}
	if strings.Contains(receivedStr, originalSSN) {
		t.Error("SSN was NOT redacted - found in upstream request")
	}

	// Check that redaction markers ARE in the received body
	if !strings.Contains(receivedStr, "[REDACTED:email]") {
		t.Error("email redaction marker not found")
	}
	if !strings.Contains(receivedStr, "[REDACTED:phone]") {
		t.Error("phone redaction marker not found")
	}
	if !strings.Contains(receivedStr, "[REDACTED:ssn]") {
		t.Error("SSN redaction marker not found")
	}

	// Allow time for async logging
	time.Sleep(50 * time.Millisecond)

	// Verify DLP info was logged
	entries, err := proxy.storage.ReadLogEntries()
	if err != nil {
		t.Fatalf("failed to read log entries: %v", err)
	}

	if len(entries) < 1 {
		t.Fatal("expected at least 1 log entry")
	}

	// Check the request entry for DLP info
	var requestEntry RequestLogEntry
	if err := json.Unmarshal(entries[0], &requestEntry); err != nil {
		t.Fatalf("failed to parse request entry: %v", err)
	}

	if requestEntry.DLP == nil {
		t.Fatal("DLP info not logged in request entry")
	}

	// Verify redactions were recorded
	redactionTypes := make(map[string]bool)
	for _, r := range requestEntry.DLP.Redactions {
		redactionTypes[r.Type] = true
	}

	if !redactionTypes["email"] {
		t.Error("email redaction not recorded in log")
	}
	if !redactionTypes["phone"] {
		t.Error("phone redaction not recorded in log")
	}
	if !redactionTypes["ssn"] {
		t.Error("ssn redaction not recorded in log")
	}
}

// TestProxy_New tests the New function with various configurations.
func TestProxy_New(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		storagePath string
		wantErr     bool
	}{
		{
			name: "default config",
			cfg: Config{
				SessionID: "test-session",
				Proxy:     config.DefaultProxyConfig(),
				DLP:       config.DefaultDLPConfig(),
				Storage:   config.DefaultLLMStorageConfig(),
			},
			storagePath: t.TempDir(),
			wantErr:     false,
		},
		{
			name: "empty session and storage - noop storage",
			cfg: Config{
				SessionID: "",
				Proxy:     config.DefaultProxyConfig(),
				DLP:       config.DefaultDLPConfig(),
			},
			storagePath: "",
			wantErr:     false,
		},
		{
			name: "custom upstream overrides",
			cfg: Config{
				SessionID: "test-session",
				Proxy: config.ProxyConfig{
					Mode: "embedded",
					Port: 0,
					Upstreams: config.ProxyUpstreamsConfig{
						Anthropic: "https://custom.anthropic.example.com",
						OpenAI:    "https://custom.openai.example.com",
					},
				},
				DLP: config.DefaultDLPConfig(),
			},
			storagePath: t.TempDir(),
			wantErr:     false,
		},
		{
			name: "DLP disabled",
			cfg: Config{
				SessionID: "test-session",
				Proxy:     config.DefaultProxyConfig(),
				DLP: config.DLPConfig{
					Mode: "disabled",
				},
			},
			storagePath: t.TempDir(),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			proxy, err := New(tt.cfg, tt.storagePath, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && proxy == nil {
				t.Error("New() returned nil proxy without error")
			}
		})
	}
}

// TestProxy_EnvVars tests the EnvVars method.
func TestProxy_EnvVars(t *testing.T) {
	storageDir := t.TempDir()

	cfg := Config{
		SessionID: "test-session-env",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
		},
		DLP: config.DefaultDLPConfig(),
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	// Before starting, Addr should be nil
	if proxy.Addr() != nil {
		t.Error("expected nil Addr before Start")
	}

	// EnvVars should return nil when not started
	if vars := proxy.EnvVars(); vars != nil {
		t.Errorf("expected nil EnvVars before Start, got %v", vars)
	}

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	// After starting, EnvVars should return the expected values
	vars := proxy.EnvVars()
	if vars == nil {
		t.Fatal("expected EnvVars after Start")
	}

	if vars["ANTHROPIC_BASE_URL"] == "" {
		t.Error("ANTHROPIC_BASE_URL not set")
	}
	if vars["OPENAI_BASE_URL"] == "" {
		t.Error("OPENAI_BASE_URL not set")
	}
	if vars["AGENTSH_SESSION_ID"] != "test-session-env" {
		t.Errorf("unexpected AGENTSH_SESSION_ID: %s", vars["AGENTSH_SESSION_ID"])
	}

	// Verify the base URLs point to the proxy
	expectedPrefix := "http://127.0.0.1:"
	if !strings.HasPrefix(vars["ANTHROPIC_BASE_URL"], expectedPrefix) {
		t.Errorf("ANTHROPIC_BASE_URL should start with %s, got %s", expectedPrefix, vars["ANTHROPIC_BASE_URL"])
	}
}

// TestProxy_StorageLogging tests that requests and responses are logged correctly.
func TestProxy_StorageLogging(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"id":   "msg_test",
			"type": "message",
			"usage": map[string]int{
				"input_tokens":  100,
				"output_tokens": 200,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	sessionID := "test-storage-logging"

	cfg := Config{
		SessionID: sessionID,
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Upstreams: config.ProxyUpstreamsConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	time.Sleep(10 * time.Millisecond)

	// Make a request
	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	req, _ := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(`{"test": true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	time.Sleep(50 * time.Millisecond)

	// Verify log file was created
	logPath := filepath.Join(storageDir, sessionID, "llm-requests.jsonl")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatalf("log file not created at %s", logPath)
	}

	// Read and verify entries
	entries, err := proxy.storage.ReadLogEntries()
	if err != nil {
		t.Fatalf("failed to read log entries: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(entries))
	}

	// Parse and verify request entry
	var reqEntry RequestLogEntry
	if err := json.Unmarshal(entries[0], &reqEntry); err != nil {
		t.Fatalf("failed to parse request entry: %v", err)
	}

	if reqEntry.SessionID != sessionID {
		t.Errorf("expected session_id %s, got %s", sessionID, reqEntry.SessionID)
	}
	if reqEntry.Request.Method != http.MethodPost {
		t.Errorf("expected method POST, got %s", reqEntry.Request.Method)
	}
	if reqEntry.Request.Path != "/v1/messages" {
		t.Errorf("expected path /v1/messages, got %s", reqEntry.Request.Path)
	}
	if reqEntry.Dialect != DialectAnthropic {
		t.Errorf("expected dialect anthropic, got %s", reqEntry.Dialect)
	}

	// Check that API key was redacted in headers
	if apiKey := reqEntry.Request.Headers["X-Api-Key"]; len(apiKey) > 0 && apiKey[0] != "[REDACTED]" {
		t.Errorf("API key was not redacted: %v", apiKey)
	}

	// Parse and verify response entry
	var respEntry ResponseLogEntry
	if err := json.Unmarshal(entries[1], &respEntry); err != nil {
		t.Fatalf("failed to parse response entry: %v", err)
	}

	if respEntry.RequestID != reqEntry.ID {
		t.Errorf("response request_id %s doesn't match request id %s", respEntry.RequestID, reqEntry.ID)
	}
	if respEntry.Response.Status != http.StatusOK {
		t.Errorf("expected status 200, got %d", respEntry.Response.Status)
	}
	if respEntry.Usage.InputTokens != 100 {
		t.Errorf("expected input_tokens 100, got %d", respEntry.Usage.InputTokens)
	}
	if respEntry.Usage.OutputTokens != 200 {
		t.Errorf("expected output_tokens 200, got %d", respEntry.Usage.OutputTokens)
	}
	if respEntry.DurationMs < 0 {
		t.Errorf("expected non-negative duration, got %d", respEntry.DurationMs)
	}
}
