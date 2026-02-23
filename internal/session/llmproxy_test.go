package session

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

func TestStartLLMProxy(t *testing.T) {
	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"id":   "msg_test",
			"type": "message",
			"usage": map[string]int{
				"input_tokens":  10,
				"output_tokens": 20,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	// Create a session manager and session
	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("test-proxy-session", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Configure proxy to use mock upstream
	proxyCfg := config.ProxyConfig{
		Mode: "embedded",
		Port: 0, // Auto-select port
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
			OpenAI:    upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{
		Mode: "disabled",
	}
	storageCfg := config.DefaultLLMStorageConfig()
	storagePath := t.TempDir()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Start the proxy
	mcpCfg := config.SandboxMCPConfig{}
	proxyURL, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, mcpCfg, storagePath, logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}
	defer closeFn()

	// Verify proxy URL is set
	if proxyURL == "" {
		t.Error("expected non-empty proxy URL")
	}
	if !strings.HasPrefix(proxyURL, "http://127.0.0.1:") {
		t.Errorf("expected proxy URL to start with http://127.0.0.1:, got %s", proxyURL)
	}

	// Verify session has the proxy URL
	if sess.LLMProxyURL() != proxyURL {
		t.Errorf("session proxy URL mismatch: expected %s, got %s", proxyURL, sess.LLMProxyURL())
	}

	// Verify we can make requests through the proxy
	time.Sleep(10 * time.Millisecond) // Wait for server to be ready

	reqBody := `{"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": "Hello"}]}`
	req, err := http.NewRequest(http.MethodPost, proxyURL+"/v1/messages", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
}

func TestStartLLMProxy_NilSession(t *testing.T) {
	proxyCfg := config.DefaultProxyConfig()
	dlpCfg := config.DefaultDLPConfig()
	storageCfg := config.DefaultLLMStorageConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, _, err := StartLLMProxy(nil, proxyCfg, dlpCfg, storageCfg, config.SandboxMCPConfig{}, t.TempDir(), logger)
	if err == nil {
		t.Error("expected error for nil session")
	}
	if !strings.Contains(err.Error(), "session is nil") {
		t.Errorf("expected 'session is nil' error, got: %v", err)
	}
}

func TestSession_LLMProxyEnvVars(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
		wantNil  bool
		wantVars map[string]string
	}{
		{
			name:     "no proxy configured",
			proxyURL: "",
			wantNil:  true,
		},
		{
			name:     "proxy configured",
			proxyURL: "http://127.0.0.1:52341",
			wantVars: map[string]string{
				"ANTHROPIC_BASE_URL": "http://127.0.0.1:52341",
				"OPENAI_BASE_URL":    "http://127.0.0.1:52341",
				"AGENTSH_SESSION_ID": "env-test-session",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(10)
			sess, err := mgr.CreateWithID("env-test-session", t.TempDir(), "default")
			if err != nil {
				t.Fatalf("failed to create session: %v", err)
			}

			if tt.proxyURL != "" {
				sess.SetLLMProxy(tt.proxyURL, func() error { return nil })
			}

			envVars := sess.LLMProxyEnvVars()

			if tt.wantNil {
				if envVars != nil {
					t.Errorf("expected nil env vars, got %v", envVars)
				}
				return
			}

			if envVars == nil {
				t.Fatal("expected non-nil env vars")
			}

			for key, want := range tt.wantVars {
				if got := envVars[key]; got != want {
					t.Errorf("env var %s: expected %s, got %s", key, want, got)
				}
			}
		})
	}
}

func TestSession_LLMProxyEnvVars_Integration(t *testing.T) {
	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// Create a session
	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("integration-test-session", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Before starting proxy, env vars should be nil
	if envVars := sess.LLMProxyEnvVars(); envVars != nil {
		t.Errorf("expected nil env vars before proxy start, got %v", envVars)
	}

	// Start the proxy
	proxyCfg := config.ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{Mode: "disabled"}
	storageCfg := config.DefaultLLMStorageConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	proxyURL, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, config.SandboxMCPConfig{}, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}
	defer closeFn()

	// After starting proxy, env vars should be set
	envVars := sess.LLMProxyEnvVars()
	if envVars == nil {
		t.Fatal("expected non-nil env vars after proxy start")
	}

	// Verify all expected vars are present
	if envVars["ANTHROPIC_BASE_URL"] != proxyURL {
		t.Errorf("ANTHROPIC_BASE_URL: expected %s, got %s", proxyURL, envVars["ANTHROPIC_BASE_URL"])
	}
	if envVars["OPENAI_BASE_URL"] != proxyURL {
		t.Errorf("OPENAI_BASE_URL: expected %s, got %s", proxyURL, envVars["OPENAI_BASE_URL"])
	}
	if envVars["AGENTSH_SESSION_ID"] != "integration-test-session" {
		t.Errorf("AGENTSH_SESSION_ID: expected integration-test-session, got %s", envVars["AGENTSH_SESSION_ID"])
	}

	// Verify we can use the env vars to make a request
	time.Sleep(10 * time.Millisecond)

	reqBody := `{"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": "Test"}]}`
	req, _ := http.NewRequest(http.MethodPost, envVars["ANTHROPIC_BASE_URL"]+"/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

func TestSession_CloseProxy(t *testing.T) {
	// Create a mock upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Create session and start proxy
	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("close-test-session", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	proxyCfg := config.ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{Mode: "disabled"}
	storageCfg := config.DefaultLLMStorageConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	proxyURL, _, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, config.SandboxMCPConfig{}, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}

	// Verify proxy is running
	if sess.LLMProxyURL() == "" {
		t.Error("expected proxy URL to be set")
	}

	// Close the proxy via session
	if err := sess.CloseLLMProxy(); err != nil {
		t.Errorf("CloseLLMProxy failed: %v", err)
	}

	// Verify proxy URL is cleared
	if sess.LLMProxyURL() != "" {
		t.Error("expected proxy URL to be cleared after close")
	}

	// Verify env vars are nil after close
	if envVars := sess.LLMProxyEnvVars(); envVars != nil {
		t.Errorf("expected nil env vars after close, got %v", envVars)
	}

	// Verify proxy is no longer accepting connections (with a short timeout)
	time.Sleep(50 * time.Millisecond)
	client := &http.Client{Timeout: 100 * time.Millisecond}
	_, err = client.Get(proxyURL + "/v1/messages")
	if err == nil {
		t.Error("expected connection to fail after proxy close")
	}
}

func TestStartLLMProxy_WithDLP(t *testing.T) {
	var receivedBody []byte

	// Create a mock upstream that captures the request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
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

	// Create session
	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("dlp-test-session", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Configure with DLP enabled
	proxyCfg := config.ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			Email: true,
			SSN:   true,
		},
	}
	storageCfg := config.DefaultLLMStorageConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	proxyURL, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, config.SandboxMCPConfig{}, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}
	defer closeFn()

	time.Sleep(10 * time.Millisecond)

	// Send a request with PII
	reqBody := `{"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": "Email test@example.com SSN 123-45-6789"}]}`
	req, _ := http.NewRequest(http.MethodPost, proxyURL+"/v1/messages", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// Verify PII was redacted
	receivedStr := string(receivedBody)
	if strings.Contains(receivedStr, "test@example.com") {
		t.Error("email was not redacted")
	}
	if strings.Contains(receivedStr, "123-45-6789") {
		t.Error("SSN was not redacted")
	}
	if !strings.Contains(receivedStr, "[REDACTED:email]") {
		t.Error("email redaction marker not found")
	}
	if !strings.Contains(receivedStr, "[REDACTED:ssn]") {
		t.Error("SSN redaction marker not found")
	}
}

func TestStartLLMProxy_SessionIDInEnvVars(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id": "msg_test", "type": "message"}`))
	}))
	defer upstream.Close()

	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("my-unique-session-id", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	proxyCfg := config.ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{Mode: "disabled"}
	storageCfg := config.DefaultLLMStorageConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, config.SandboxMCPConfig{}, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}
	defer closeFn()

	envVars := sess.LLMProxyEnvVars()
	if envVars["AGENTSH_SESSION_ID"] != "my-unique-session-id" {
		t.Errorf("expected session ID 'my-unique-session-id', got '%s'", envVars["AGENTSH_SESSION_ID"])
	}
}

func TestSession_LLMProxyEnvVars_ThreadSafety(t *testing.T) {
	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("concurrent-test-session", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	sess.SetLLMProxy("http://127.0.0.1:12345", func() error { return nil })

	// Run concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				envVars := sess.LLMProxyEnvVars()
				if envVars == nil {
					t.Error("unexpected nil env vars")
				}
				_ = sess.LLMProxyURL()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("test timed out")
		}
	}
}

func TestStartLLMProxy_MCPOnlyMode(t *testing.T) {
	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"id":   "msg_test",
			"type": "message",
			"usage": map[string]int{
				"input_tokens":  10,
				"output_tokens": 20,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("mcp-only-test-session", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Configure proxy in mcp-only mode
	proxyCfg := config.ProxyConfig{
		Mode: "mcp-only",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
			OpenAI:    upstream.URL,
		},
	}
	// Pass DLP as "redact" — mcp-only mode should force it to "disabled"
	dlpCfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			Email: true,
		},
	}
	// Pass StoreBodies as false — mcp-only mode should force it to true
	storageCfg := config.LLMStorageConfig{
		StoreBodies: false,
	}
	mcpCfg := config.SandboxMCPConfig{}
	storagePath := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	proxyURL, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, mcpCfg, storagePath, logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}
	defer closeFn()

	// Verify proxy URL is non-empty and well-formed
	if proxyURL == "" {
		t.Error("expected non-empty proxy URL")
	}
	if !strings.HasPrefix(proxyURL, "http://127.0.0.1:") {
		t.Errorf("expected proxy URL to start with http://127.0.0.1:, got %s", proxyURL)
	}

	// Verify session has the proxy URL
	if sess.LLMProxyURL() != proxyURL {
		t.Errorf("session proxy URL mismatch: expected %s, got %s", proxyURL, sess.LLMProxyURL())
	}

	// Verify we can make requests through the proxy
	time.Sleep(10 * time.Millisecond)

	reqBody := `{"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": "Hello"}]}`
	req, err := http.NewRequest(http.MethodPost, proxyURL+"/v1/messages", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
}

func TestStartLLMProxy_MCPConfigPassedThrough(t *testing.T) {
	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("mcp-passthrough-test", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	proxyCfg := config.ProxyConfig{
		Mode: "mcp-only",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
			OpenAI:    upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{Mode: "disabled"}
	storageCfg := config.DefaultLLMStorageConfig()
	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		FailClosed:    true,
		ToolPolicy:    "allowlist",
		AllowedTools: []config.MCPToolRule{
			{Server: "*", Tool: "safe_tool"},
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	proxyURL, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, mcpCfg, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}
	defer closeFn()

	// Verify the proxy started successfully with MCP config
	if proxyURL == "" {
		t.Error("expected non-empty proxy URL")
	}

	// Verify session has the proxy URL set
	if sess.LLMProxyURL() != proxyURL {
		t.Errorf("session proxy URL mismatch: expected %s, got %s", proxyURL, sess.LLMProxyURL())
	}

	// Verify the proxy instance is stored in the session
	proxyInst := sess.ProxyInstance()
	if proxyInst == nil {
		t.Error("expected non-nil proxy instance in session")
	}
}

func TestStartLLMProxy_CreatesRegistry(t *testing.T) {
	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("registry-enabled-test", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	proxyCfg := config.ProxyConfig{
		Mode: "mcp-only",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
			OpenAI:    upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{Mode: "disabled"}
	storageCfg := config.DefaultLLMStorageConfig()
	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		FailClosed:    true,
		ToolPolicy:    "allowlist",
		AllowedTools: []config.MCPToolRule{
			{Server: "*", Tool: "safe_tool"},
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	proxyURL, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, mcpCfg, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}
	defer closeFn()

	// Verify proxy started
	if proxyURL == "" {
		t.Error("expected non-empty proxy URL")
	}

	// Verify registry was created and stored in the session
	reg := sess.MCPRegistry()
	if reg == nil {
		t.Fatal("expected non-nil MCP registry when EnforcePolicy is true")
	}

	// Verify it's actually a *mcpregistry.Registry
	registry, ok := reg.(*mcpregistry.Registry)
	if !ok {
		t.Fatalf("expected *mcpregistry.Registry, got %T", reg)
	}

	// Verify the registry is functional (can register and look up tools)
	registry.Register("test-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "test_tool", Hash: "abc123"},
	})
	entry := registry.Lookup("test_tool")
	if entry == nil {
		t.Error("expected to find registered tool in registry")
	}
	if entry != nil && entry.ServerID != "test-server" {
		t.Errorf("expected server ID 'test-server', got %s", entry.ServerID)
	}
}

func TestStartLLMProxy_MCPOnlyWithoutPolicy(t *testing.T) {
	// Verify that registry is created in mcp-only mode even when EnforcePolicy is false,
	// as long as another MCP feature (rate limits) is enabled.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("mcp-only-no-policy-test", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	proxyCfg := config.ProxyConfig{
		Mode: "mcp-only",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
			OpenAI:    upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{Mode: "disabled"}
	storageCfg := config.DefaultLLMStorageConfig()
	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: false,
		RateLimits: config.MCPRateLimitsConfig{
			Enabled:    true,
			DefaultRPM: 60,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	proxyURL, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, mcpCfg, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}
	defer closeFn()

	// Verify proxy started
	if proxyURL == "" {
		t.Error("expected non-empty proxy URL")
	}

	// Verify registry WAS created even though EnforcePolicy is false.
	// The mcp-only mode + rate limits should trigger registry creation.
	reg := sess.MCPRegistry()
	if reg == nil {
		t.Fatal("expected non-nil MCP registry in mcp-only mode with rate limits enabled")
	}

	// Verify the registry is functional
	registry, ok := reg.(*mcpregistry.Registry)
	if !ok {
		t.Fatalf("expected *mcpregistry.Registry, got %T", reg)
	}

	registry.Register("test-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "rate_limited_tool", Hash: "def456"},
	})
	entry := registry.Lookup("rate_limited_tool")
	if entry == nil {
		t.Error("expected to find registered tool in registry")
	}
	if entry != nil && entry.ServerID != "test-server" {
		t.Errorf("expected server ID 'test-server', got %s", entry.ServerID)
	}
}

func TestStartLLMProxy_NoRegistryWhenPolicyDisabled(t *testing.T) {
	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("registry-disabled-test", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	proxyCfg := config.ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
			OpenAI:    upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{Mode: "disabled"}
	storageCfg := config.DefaultLLMStorageConfig()
	// EnforcePolicy defaults to false
	mcpCfg := config.SandboxMCPConfig{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	proxyURL, closeFn, err := StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, mcpCfg, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}
	defer closeFn()

	// Verify proxy started
	if proxyURL == "" {
		t.Error("expected non-empty proxy URL")
	}

	// Verify registry was NOT created
	reg := sess.MCPRegistry()
	if reg != nil {
		t.Errorf("expected nil MCP registry when EnforcePolicy is false, got %v", reg)
	}
}

func TestSession_MCPRegistryClearedOnClose(t *testing.T) {
	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"id":   "msg_test",
			"type": "message",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	mgr := NewManager(10)
	sess, err := mgr.CreateWithID("registry-close-test", t.TempDir(), "default")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	proxyCfg := config.ProxyConfig{
		Mode: "mcp-only",
		Port: 0,
		Providers: config.ProxyProvidersConfig{
			Anthropic: upstream.URL,
			OpenAI:    upstream.URL,
		},
	}
	dlpCfg := config.DLPConfig{Mode: "disabled"}
	storageCfg := config.DefaultLLMStorageConfig()
	mcpCfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, _, err = StartLLMProxy(sess, proxyCfg, dlpCfg, storageCfg, mcpCfg, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("StartLLMProxy failed: %v", err)
	}

	// Verify registry is set
	if sess.MCPRegistry() == nil {
		t.Fatal("expected non-nil registry before close")
	}

	// Close the LLM proxy
	if err := sess.CloseLLMProxy(); err != nil {
		t.Fatalf("CloseLLMProxy failed: %v", err)
	}

	// Verify registry is cleared
	if sess.MCPRegistry() != nil {
		t.Error("expected nil registry after CloseLLMProxy")
	}
}
