//go:build integration

package llmproxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

// TestIntegration_FullFlowAnthropic verifies the complete proxy flow for Anthropic:
// 1. Request with PII is redacted before reaching upstream
// 2. Upstream response with usage is extracted and logged
// 3. Storage contains correct log entries
func TestIntegration_FullFlowAnthropic(t *testing.T) {
	// 1. Start mock Anthropic upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream: failed to read body: %v", err)
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}

		// Verify DLP was applied - email should be redacted
		bodyStr := string(body)
		if strings.Contains(bodyStr, "john@example.com") {
			t.Error("email should have been redacted before reaching upstream")
		}

		// Verify the redaction placeholder is present
		if !strings.Contains(bodyStr, "[REDACTED:email]") {
			t.Error("expected [REDACTED:email] in upstream request body")
		}

		// Return an Anthropic-style response with usage
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"content": [{"text": "OK"}],
			"usage": {"input_tokens": 50, "output_tokens": 100}
		}`))
	}))
	defer upstream.Close()

	// 2. Configure and start proxy
	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "integration-test-anthropic",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.Proxy.Port = 0 // Let OS assign port
	cfg.Proxy.Providers.Anthropic = upstream.URL

	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	// 3. Send request with PII to proxy (Anthropic dialect)
	reqBody := `{"content":"Contact john@example.com please"}`
	req, err := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("x-api-key", "test-key") // Anthropic auth header
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// 4. Verify response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(respBody))
	}

	// Verify response contains expected content
	if !strings.Contains(string(respBody), "OK") {
		t.Errorf("expected response to contain 'OK', got: %s", string(respBody))
	}

	// 5. Verify storage contains log entries
	entries, err := p.storage.ReadLogEntries()
	if err != nil {
		t.Fatalf("ReadLogEntries: %v", err)
	}

	if len(entries) < 2 {
		t.Fatalf("expected at least 2 log entries (request + response), got %d", len(entries))
	}

	// Parse and verify request entry
	var reqEntry RequestLogEntry
	if err := json.Unmarshal(entries[0], &reqEntry); err != nil {
		t.Fatalf("unmarshal request entry: %v", err)
	}

	if reqEntry.Dialect != DialectAnthropic {
		t.Errorf("expected dialect %q, got %q", DialectAnthropic, reqEntry.Dialect)
	}
	if reqEntry.SessionID != "integration-test-anthropic" {
		t.Errorf("expected session ID %q, got %q", "integration-test-anthropic", reqEntry.SessionID)
	}
	if reqEntry.DLP == nil {
		t.Error("expected DLP info to be present")
	} else if len(reqEntry.DLP.Redactions) == 0 {
		t.Error("expected redactions to be recorded")
	} else {
		found := false
		for _, r := range reqEntry.DLP.Redactions {
			if r.Type == "email" {
				found = true
				if r.Count != 1 {
					t.Errorf("expected 1 email redaction, got %d", r.Count)
				}
			}
		}
		if !found {
			t.Error("expected email redaction to be recorded")
		}
	}

	// Parse and verify response entry
	var respEntry ResponseLogEntry
	if err := json.Unmarshal(entries[1], &respEntry); err != nil {
		t.Fatalf("unmarshal response entry: %v", err)
	}

	if respEntry.RequestID != reqEntry.ID {
		t.Errorf("response request_id %q does not match request id %q", respEntry.RequestID, reqEntry.ID)
	}
	if respEntry.Response.Status != http.StatusOK {
		t.Errorf("expected status 200, got %d", respEntry.Response.Status)
	}
	if respEntry.Usage.InputTokens != 50 {
		t.Errorf("expected input_tokens 50, got %d", respEntry.Usage.InputTokens)
	}
	if respEntry.Usage.OutputTokens != 100 {
		t.Errorf("expected output_tokens 100, got %d", respEntry.Usage.OutputTokens)
	}
}

// TestIntegration_FullFlowOpenAI verifies the complete proxy flow for OpenAI:
// 1. Request with PII is redacted before reaching upstream
// 2. Upstream response with usage (OpenAI format) is extracted and logged
func TestIntegration_FullFlowOpenAI(t *testing.T) {
	// 1. Start mock OpenAI upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream: failed to read body: %v", err)
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}

		// Verify DLP was applied - phone should be redacted
		bodyStr := string(body)
		if strings.Contains(bodyStr, "555-123-4567") {
			t.Error("phone should have been redacted before reaching upstream")
		}

		// Return an OpenAI-style response with usage
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"choices": [{"message": {"content": "Response"}}],
			"usage": {"prompt_tokens": 75, "completion_tokens": 150, "total_tokens": 225}
		}`))
	}))
	defer upstream.Close()

	// 2. Configure and start proxy
	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "integration-test-openai",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.Proxy.Port = 0
	cfg.Proxy.Providers.OpenAI = upstream.URL

	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	// 3. Send request with PII to proxy (OpenAI dialect)
	reqBody := `{"messages":[{"role":"user","content":"Call me at 555-123-4567"}]}`
	req, err := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/chat/completions",
		strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk-test-key") // OpenAI auth header
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	// 4. Verify storage entries
	entries, err := p.storage.ReadLogEntries()
	if err != nil {
		t.Fatalf("ReadLogEntries: %v", err)
	}

	if len(entries) < 2 {
		t.Fatalf("expected at least 2 log entries, got %d", len(entries))
	}

	// Verify request entry
	var reqEntry RequestLogEntry
	if err := json.Unmarshal(entries[0], &reqEntry); err != nil {
		t.Fatalf("unmarshal request entry: %v", err)
	}
	if reqEntry.Dialect != DialectOpenAI {
		t.Errorf("expected dialect %q, got %q", DialectOpenAI, reqEntry.Dialect)
	}

	// Verify response entry with OpenAI usage
	var respEntry ResponseLogEntry
	if err := json.Unmarshal(entries[1], &respEntry); err != nil {
		t.Fatalf("unmarshal response entry: %v", err)
	}
	if respEntry.Usage.InputTokens != 75 {
		t.Errorf("expected input_tokens 75, got %d", respEntry.Usage.InputTokens)
	}
	if respEntry.Usage.OutputTokens != 150 {
		t.Errorf("expected output_tokens 150, got %d", respEntry.Usage.OutputTokens)
	}
}

// TestIntegration_MultiplePIITypes verifies that multiple PII types are redacted correctly.
func TestIntegration_MultiplePIITypes(t *testing.T) {
	var (
		upstreamReceivedBody string
		upstreamMu           sync.Mutex
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamMu.Lock()
		upstreamReceivedBody = string(body)
		upstreamMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":[{"text":"OK"}],"usage":{"input_tokens":10,"output_tokens":20}}`))
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "integration-test-multi-pii",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.Proxy.Port = 0
	cfg.Proxy.Providers.Anthropic = upstream.URL

	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	// Request with multiple PII types: email, phone, SSN
	reqBody := `{"content":"Contact: user@test.org, 555-987-6543, SSN: 123-45-6789"}`
	req, _ := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(reqBody))
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Verify all PII was redacted
	upstreamMu.Lock()
	receivedBody := upstreamReceivedBody
	upstreamMu.Unlock()

	if strings.Contains(receivedBody, "user@test.org") {
		t.Error("email should have been redacted")
	}
	if strings.Contains(receivedBody, "555-987-6543") {
		t.Error("phone should have been redacted")
	}
	if strings.Contains(receivedBody, "123-45-6789") {
		t.Error("SSN should have been redacted")
	}

	// Verify redaction placeholders are present
	if !strings.Contains(receivedBody, "[REDACTED:email]") {
		t.Error("expected [REDACTED:email] placeholder")
	}
	if !strings.Contains(receivedBody, "[REDACTED:phone]") {
		t.Error("expected [REDACTED:phone] placeholder")
	}
	if !strings.Contains(receivedBody, "[REDACTED:ssn]") {
		t.Error("expected [REDACTED:ssn] placeholder")
	}

	// Verify storage records all redactions
	entries, _ := p.storage.ReadLogEntries()
	if len(entries) < 1 {
		t.Fatal("expected at least 1 log entry")
	}

	var reqEntry RequestLogEntry
	json.Unmarshal(entries[0], &reqEntry)

	if reqEntry.DLP == nil || len(reqEntry.DLP.Redactions) == 0 {
		t.Fatal("expected DLP redactions to be recorded")
	}

	// Count expected redaction types
	typeCount := make(map[string]int)
	for _, r := range reqEntry.DLP.Redactions {
		typeCount[r.Type] = r.Count
	}

	if typeCount["email"] != 1 {
		t.Errorf("expected 1 email redaction, got %d", typeCount["email"])
	}
	if typeCount["phone"] != 1 {
		t.Errorf("expected 1 phone redaction, got %d", typeCount["phone"])
	}
	if typeCount["ssn"] != 1 {
		t.Errorf("expected 1 SSN redaction, got %d", typeCount["ssn"])
	}
}

// TestIntegration_DLPDisabled verifies that PII passes through when DLP is disabled.
func TestIntegration_DLPDisabled(t *testing.T) {
	var (
		upstreamReceivedBody string
		upstreamMu           sync.Mutex
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamMu.Lock()
		upstreamReceivedBody = string(body)
		upstreamMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":[{"text":"OK"}],"usage":{"input_tokens":5,"output_tokens":10}}`))
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "integration-test-dlp-disabled",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.DLP.Mode = "disabled" // Disable DLP
	cfg.Proxy.Port = 0
	cfg.Proxy.Providers.Anthropic = upstream.URL

	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	email := "plaintext@example.com"
	reqBody := `{"content":"My email is ` + email + `"}`
	req, _ := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(reqBody))
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Verify email was NOT redacted (DLP disabled)
	upstreamMu.Lock()
	receivedBody := upstreamReceivedBody
	upstreamMu.Unlock()

	if !strings.Contains(receivedBody, email) {
		t.Error("email should NOT have been redacted when DLP is disabled")
	}
	if strings.Contains(receivedBody, "[REDACTED") {
		t.Error("no redaction should occur when DLP is disabled")
	}
}

// TestIntegration_HeaderRedaction verifies that sensitive headers are redacted in logs.
func TestIntegration_HeaderRedaction(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":[{"text":"OK"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "integration-test-header-redaction",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.Proxy.Port = 0
	cfg.Proxy.Providers.Anthropic = upstream.URL

	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	secretAPIKey := "secret-api-key-12345"
	req, _ := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(`{"content":"test"}`))
	req.Header.Set("x-api-key", secretAPIKey) // This should be redacted in logs
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	entries, _ := p.storage.ReadLogEntries()
	if len(entries) < 1 {
		t.Fatal("expected at least 1 log entry")
	}

	var reqEntry RequestLogEntry
	json.Unmarshal(entries[0], &reqEntry)

	// Check that the API key header is redacted in logs
	if apiKeyVals, ok := reqEntry.Request.Headers["X-Api-Key"]; ok {
		for _, v := range apiKeyVals {
			if v == secretAPIKey {
				t.Error("API key should be redacted in log headers")
			}
			if v != "[REDACTED]" {
				t.Errorf("expected header value to be '[REDACTED]', got %q", v)
			}
		}
	}
}

// TestIntegration_UnknownDialect verifies that unknown dialect requests are rejected.
func TestIntegration_UnknownDialect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for unknown dialect")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "integration-test-unknown-dialect",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.Proxy.Port = 0
	cfg.Proxy.Providers.Anthropic = upstream.URL

	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	// Request without auth headers - should be rejected as unknown dialect
	req, _ := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(`{"content":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	// No x-api-key or Authorization header

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown dialect, got %d", resp.StatusCode)
	}
}

// TestIntegration_UpstreamError verifies that upstream errors are properly proxied.
func TestIntegration_UpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "integration-test-upstream-error",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.Proxy.Port = 0
	cfg.Proxy.Providers.Anthropic = upstream.URL

	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	req, _ := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(`{"content":"test"}`))
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// Proxy should pass through the upstream error
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}

	// Verify error response is logged
	entries, _ := p.storage.ReadLogEntries()
	if len(entries) < 2 {
		t.Fatal("expected at least 2 log entries")
	}

	var respEntry ResponseLogEntry
	json.Unmarshal(entries[1], &respEntry)

	if respEntry.Response.Status != http.StatusInternalServerError {
		t.Errorf("expected logged status 500, got %d", respEntry.Response.Status)
	}
}

// TestIntegration_EnvVars verifies that EnvVars returns correct environment variables.
func TestIntegration_EnvVars(t *testing.T) {
	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "integration-test-envvars",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.Proxy.Port = 0

	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	envVars := p.EnvVars()

	// Verify required env vars are set
	if envVars["ANTHROPIC_BASE_URL"] == "" {
		t.Error("ANTHROPIC_BASE_URL should be set")
	}
	if envVars["OPENAI_BASE_URL"] == "" {
		t.Error("OPENAI_BASE_URL should be set")
	}
	if envVars["AGENTSH_SESSION_ID"] != "integration-test-envvars" {
		t.Errorf("expected session ID %q, got %q", "integration-test-envvars", envVars["AGENTSH_SESSION_ID"])
	}

	// Verify URLs point to proxy address
	addr := p.Addr().String()
	if !strings.Contains(envVars["ANTHROPIC_BASE_URL"], addr) {
		t.Errorf("ANTHROPIC_BASE_URL should contain proxy address %s, got %s", addr, envVars["ANTHROPIC_BASE_URL"])
	}
}

// TestIntegration_SessionIDHeader verifies X-Session-ID header override works.
func TestIntegration_SessionIDHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":[{"text":"OK"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "default-session",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.Proxy.Port = 0
	cfg.Proxy.Providers.Anthropic = upstream.URL

	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	req, _ := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(`{"content":"test"}`))
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-ID", "custom-session-id") // Override session ID

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	entries, _ := p.storage.ReadLogEntries()
	if len(entries) < 1 {
		t.Fatal("expected at least 1 log entry")
	}

	var reqEntry RequestLogEntry
	json.Unmarshal(entries[0], &reqEntry)

	// Session ID should use the header value, not the default
	if reqEntry.SessionID != "custom-session-id" {
		t.Errorf("expected session ID %q, got %q", "custom-session-id", reqEntry.SessionID)
	}
}
